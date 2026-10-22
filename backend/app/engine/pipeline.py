"""Request pipeline: Envelope → Tier 0a → (Tier 0b ∥ Jev) → fusion → explanation → persist → optional LLM.

See BACKEND_ARCHITECTURE.md §2 for the lifecycle diagram.
"""

import asyncio
import hashlib
import logging
import time
import uuid
from typing import Any

from app import db
from app.config import settings
from app.engine.explain import explain
from app.engine.fusion import fuse, logit, rules_score, sigmoid
from app.schemas import Envelope, Evidence
from app.tier0.header_analyzer import analyze_email
from app.tier0.local_model import LocalScores, local_models
from app.tier0.text_rules import analyze_text
from app.tier0.url_analyzer import analyze_url
from app.tier1.decision_client import DecisionResult, decision_client

log = logging.getLogger(__name__)

MAX_URLS = 10
# Invalidate persisted URL verdicts when URL rules or fusion behavior changes.
URL_CACHE_VERSION = "url-v4"

# Fallback category when Jev is unavailable: first matching rule wins
RULE_CATEGORY = [
    ("txt.otp_plus_link", "otp_theft"), ("txt.asks_otp", "otp_theft"), ("txt.upi_collect", "upi_trap"),
    ("txt.kyc", "kyc_freeze"), ("txt.account_block", "kyc_freeze"), ("txt.digital_arrest", "impersonation"),
    ("txt.job_task", "fake_job"), ("txt.lottery", "lottery_prize"), ("txt.courier", "delivery"),
    ("txt.electricity", "impersonation"), ("hdr.brand_spoof", "credential_phish"),
    ("hdr.brand_spoof_auth", "credential_phish"), ("link.text_mismatch", "credential_phish"),
    ("url.", "credential_phish"),
]


def input_hash(env: Envelope) -> str:
    key = "|".join([env.channel, env.sender or "", env.subject or "", env.text.strip(), ",".join(env.urls),
                    ",".join(f"{k}:{v}" for k, v in sorted(env.headers.items()))])
    if env.channel == "url":
        key = f"{URL_CACHE_VERSION}|{key}"
    return hashlib.sha256(key.encode()).hexdigest()


def _url_risk(rules_ev: list[Evidence], p_model: float | None) -> float:
    """Per-URL risk: 0.7 urlbert + 0.3 rules in log-odds space, raised to any rule floor."""
    r = rules_score(rules_ev)
    risk = sigmoid(0.7 * logit(p_model) + 0.3 * logit(r)) if p_model is not None else r
    floors = [e.floor for e in rules_ev if e.floor is not None]
    if not floors and any(e.id in {"url.allowlisted", "url.verified_portal"} for e in rules_ev):
        risk = min(risk, settings.allowlisted_url_cap)
    return max([risk, *floors])


def _category(jev: DecisionResult | None, evidence: list[Evidence], verdict: str) -> str | None:
    if verdict == "SAFE":
        return None
    if jev is not None and jev.category != "none":
        return jev.category
    ids = [e.id for e in evidence if e.weight > 0]
    for prefix, cat in RULE_CATEGORY:
        if any(i.startswith(prefix) for i in ids):
            return cat
    return "other_scam"


async def analyze(env: Envelope, deep: bool = False, use_cache: bool = True,
                  decision_timeout_s: float | None = None) -> dict[str, Any]:
    t_start = time.perf_counter()
    timings: dict[str, float] = {}
    env.urls = list(dict.fromkeys(env.urls))[:MAX_URLS]

    h = input_hash(env)
    if use_cache and not deep:
        cached = await db.find_by_hash(h)
        if cached:
            cached["cached"] = True
            return cached

    # ── Tier 0a: deterministic analyzers ────────────────────────────────────
    t0 = time.perf_counter()
    evidence: list[Evidence] = []
    url_rule_ev: dict[str, list[Evidence]] = {}
    url_meta: dict[str, Any] = {}
    for u in env.urls:
        a = analyze_url(u)
        for e in a.evidence:
            e.detail.setdefault("url", u)
        url_rule_ev[u] = a.evidence
        url_meta[u] = a
        evidence.extend(a.evidence)
    if env.channel != "url" and env.text:
        evidence.extend(analyze_text(env.text))
    if env.channel == "email":
        evidence.extend(analyze_email(env))
    timings["tier0a"] = (time.perf_counter() - t0) * 1000

    async def classify():
        if decision_timeout_s is None:
            return await decision_client.classify(env, evidence)
        try:
            return await asyncio.wait_for(decision_client.classify(env, evidence), decision_timeout_s)
        except asyncio.TimeoutError:
            log.info("Live-call decision budget exceeded; using local rules and models")
            return None

    # ── Tier 0b (thread) ∥ Tier 1 Jev ───────────────────────────────────────
    t0 = time.perf_counter()
    jev: DecisionResult | None = None
    if env.channel == "url":
        local: LocalScores = await asyncio.to_thread(local_models.score, env)
        timings["tier0b"] = local.latency_ms
        pre = _url_risk(evidence, local.p_local)
        if pre >= settings.url_skip_jev_below:
            jev = await classify()
    else:
        local_task = asyncio.to_thread(local_models.score, env)
        local, jev = await asyncio.gather(local_task, classify())
        timings["tier0b"] = local.latency_ms
    if jev is not None:
        timings["tier1"] = jev.latency_ms
        evidence.extend(jev.evidence)
    timings["parallel"] = (time.perf_counter() - t0) * 1000

    # ── Per-URL risk table ──────────────────────────────────────────────────
    urls_out = []
    for u in env.urls:
        r = _url_risk(url_rule_ev[u], local.url_scores.get(u))
        if env.channel == "url":
            # Show the same corroboration policy in the URL details as in the
            # overall verdict. Embedded URLs retain the email/SMS risk policy.
            r = fuse(url_rule_ev[u], local.url_scores.get(u),
                     jev.p_scam if jev else None, channel="url").risk
        urls_out.append({
            "url": u,
            "domain": getattr(url_meta[u], "registered_domain", None),
            "risk": round(r, 4),
            "model": local.url_scores.get(u),
            "flags": [e.id.removeprefix("url.") for e in url_rule_ev[u] if e.weight > 0],
        })
    max_url = max((x["risk"] for x in urls_out), default=None)

    # ── Fusion ──────────────────────────────────────────────────────────────
    t0 = time.perf_counter()
    url_risk = None
    if env.channel != "url" and max_url is not None:
        url_risk = 0.8 * max_url
    fused = fuse(evidence, local.p_local, jev.p_scam if jev else None, url_risk, channel=env.channel)
    category = _category(jev, evidence, fused.verdict)
    if env.channel == "url" and fused.decided_by == "model_cap":
        evidence.append(Evidence(
            id="url.model_unconfirmed", source="model", weight=-0.01,
            reason="The URL model's alert was not corroborated by technical phishing indicators. Page content was not inspected.",
            detail={"p_local": local.p_local, "p_tier1": jev.p_scam if jev else None},
        ))
    reasons, action = explain(evidence, fused.verdict, category)
    timings["fusion"] = (time.perf_counter() - t0) * 1000

    from app.tier2.auditor import auditor  # local import: tier2 is optional

    llm_wanted = deep or fused.needs_llm
    llm_status = "pending" if (llm_wanted and auditor.available) else ("unavailable" if llm_wanted else "skipped")

    timings["total"] = (time.perf_counter() - t_start) * 1000
    result: dict[str, Any] = {
        "scan_id": str(uuid.uuid4()),
        "channel": env.channel,
        "verdict": fused.verdict,
        "risk": fused.risk,
        "confidence": fused.confidence,
        "category": category,
        "trigger": jev.trigger if jev and jev.trigger != "none" and fused.verdict != "SAFE" else None,
        "severity": round(jev.severity, 2) if jev else None,
        "decided_by": fused.decided_by,
        "reasons": reasons,
        "action": action,
        "urls": urls_out,
        "evidence": [e.model_dump() for e in evidence],
        "scores": {**fused.scores, "models": local.per_model},
        "tier1": jev.model_dump(exclude={"evidence"}) if jev else None,
        "llm": {"status": llm_status, "audit": None},
        "mode": "online" if jev else "offline",
        "latency_ms": {k: round(v, 1) for k, v in timings.items()},
        "input": {"sender": env.sender, "subject": env.subject, "text": env.text[:2000], "urls": env.urls},
        "cached": False,
    }
    await db.save_scan(result, h, env.subject or env.text or (env.urls[0] if env.urls else ""))

    if llm_status == "pending":
        if deep:
            await auditor.audit_and_update(result, env, evidence)
        else:
            auditor.schedule(result, env, evidence)
    return result
