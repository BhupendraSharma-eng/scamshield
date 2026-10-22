"""Combine Tier 0 (rules + local models) and Tier 1 (Jev) into one calibrated risk and verdict.

Both p_local and p_jev are (roughly) calibrated probabilities, so we average them in log-odds space,
then apply hard floors from Evidence. See BACKEND_ARCHITECTURE.md §6.
"""

import math
from typing import Literal

from pydantic import BaseModel

from app.config import settings
from app.schemas import Evidence

Verdict = Literal["SCAM", "SUSPICIOUS", "SAFE"]
EPS = 0.01
# Positive URL rules that are enough, with a model, to reach SCAM. Weaker hints such as
# url.sensitive_words are not: the local URL model treats every "/login" path as phishing.
_URL_STRONG_RULES = frozenset({
    "url.lookalike", "url.brand_in_sub", "url.ip_host", "url.punycode", "url.at_symbol",
    "url.risky_tld", "url.free_host", "url.apk", "url.shortener", "url.entropy",
    "url.brand_tld_swap",
})


def clip(p: float, lo: float = EPS, hi: float = 1 - EPS) -> float:
    return min(max(p, lo), hi)


def logit(p: float) -> float:
    p = clip(p)
    return math.log(p / (1 - p))


def sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x))


def rules_score(evidence: list[Evidence]) -> float:
    """Noisy-OR over positive rule weights, minus half the negative (reassuring) weights."""
    rules = [e for e in evidence if e.source == "rule"]
    keep = 1.0
    for e in rules:
        if e.weight > 0:
            keep *= 1 - min(e.weight, 0.99)
    neg = sum(-e.weight for e in rules if e.weight < 0)
    return min(max(1 - keep - 0.5 * neg, 0.0), 1.0)


class FusionResult(BaseModel):
    risk: float
    verdict: Verdict
    confidence: float           # distance from the nearest decision threshold, 0..1
    decided_by: str             # rule_floor | tier1 | local | rules | url | allowlist | brand_tld_cap | model_cap | llm
    needs_llm: bool
    scores: dict[str, float | None]


def fuse(
    evidence: list[Evidence],
    p_local: float | None,
    p_jev: float | None,
    url_risk: float | None = None,
    channel: str | None = None,
) -> FusionResult:
    """p_jev is the Tier 1 decision probability (OpenAI Decisions or Jev); None = offline."""
    r_rules = rules_score(evidence)
    cw = settings.channel_weights.get(channel or "")
    w_jev, w_local, w_rules = cw["online"] if cw else (settings.w_jev, settings.w_local, settings.w_rules)
    w_local_off, w_rules_off = cw["offline"] if cw else (settings.w_local_offline, settings.w_rules_offline)

    parts: list[tuple[str, float, float]] = []   # (name, weight, prob)
    if p_jev is not None:
        parts.append(("tier1", w_jev, p_jev))
        if p_local is not None:
            parts.append(("local", w_local, p_local))
        parts.append(("rules", w_rules, r_rules))
    else:
        if p_local is not None:
            parts.append(("local", w_local_off, p_local))
        parts.append(("rules", w_rules_off if p_local is not None else 1.0, r_rules))

    total_w = sum(w for _, w, _ in parts)
    base = sigmoid(sum(w * logit(p) for _, w, p in parts) / total_w)

    # Which input pushed hardest in the direction of the final answer
    contrib = {name: w * logit(p) for name, w, p in parts}
    decided_by = max(contrib, key=lambda k: contrib[k] if base >= 0.5 else -contrib[k])

    risk = base
    floors = [e.floor for e in evidence if e.floor is not None]
    # A standalone check of an exactly allowlisted official domain with no red flags stays low
    if channel == "url" and not floors and any(e.id == "url.allowlisted" for e in evidence):
        if risk > settings.allowlisted_url_cap:
            risk, decided_by = settings.allowlisted_url_cap, "allowlist"
    # Exact brand name on another ending (amazon.net) with no other red flag: at most SUSPICIOUS
    ids = {e.id for e in evidence if e.weight > 0}
    if channel == "url" and not floors and "url.brand_tld_swap" in ids and "url.risky_tld" not in ids:
        cap = settings.thresh_scam - 0.05
        if risk > cap:
            risk, decided_by = cap, "brand_tld_cap"
    if floors and max(floors) > risk:
        risk, decided_by = max(floors), "rule_floor"
    if url_risk is not None and url_risk > risk:
        risk, decided_by = url_risk, "url"
    # A URL model score, without a hard rule or a confident tier-1 call, stays at most SUSPICIOUS.
    strong_url_rule = any(
        e.source == "rule" and e.weight > 0 and e.id in _URL_STRONG_RULES for e in evidence
    )
    if (
        channel == "url"
        and not floors
        and not strong_url_rule
        and (p_jev is None or p_jev < settings.thresh_scam)
    ):
        cap = settings.thresh_scam - 0.05
        if risk > cap:
            risk, decided_by = cap, "model_cap"

    if risk >= settings.thresh_scam:
        verdict: Verdict = "SCAM"
        confidence = (risk - settings.thresh_scam) / (1 - settings.thresh_scam)
    elif risk >= settings.thresh_suspicious:
        verdict = "SUSPICIOUS"
        mid = (settings.thresh_scam + settings.thresh_suspicious) / 2
        confidence = 1 - abs(risk - mid) / ((settings.thresh_scam - settings.thresh_suspicious) / 2)
    else:
        verdict = "SAFE"
        confidence = (settings.thresh_suspicious - risk) / settings.thresh_suspicious

    disagree = p_jev is not None and p_local is not None and abs(p_jev - p_local) > settings.disagree_llm
    needs_llm = verdict == "SUSPICIOUS" or (disagree and decided_by != "rule_floor")

    return FusionResult(
        risk=round(risk, 4),
        verdict=verdict,
        confidence=round(min(max(confidence, 0.0), 1.0), 3),
        decided_by=decided_by,
        needs_llm=needs_llm,
        scores={"p_jev": p_jev, "p_local": p_local, "rules": round(r_rules, 4), "url": url_risk},
    )
