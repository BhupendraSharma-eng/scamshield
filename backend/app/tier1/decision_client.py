"""Tier 1: one typed-decision call per message. Never raises — returns None when unavailable.

Providers (settings.decision_provider):
- "openai": OpenAI Decisions API, POST /v1/decisions, model gpt-6-luna (default)
- "jev":    TypeSafe Jev via OpenRouter's System One API (TypeSafe SDK)
Both answer the same provider-neutral question set (questions.py) and map to DecisionResult.
"""

import logging
import time
from typing import Any

import httpx
from pydantic import BaseModel

from app.config import settings
from app.schemas import Envelope, Evidence
from app.tier1.questions import (
    CATEGORIES, TRIGGERS, build_questions, build_state, openai_input, to_openai, to_typesafe,
)

log = logging.getLogger(__name__)


class DecisionResult(BaseModel):
    provider: str
    model: str
    p_scam: float
    category: str
    category_conf: float
    category_probs: dict[str, float]
    trigger: str
    trigger_conf: float
    severity: float                 # 0..3, probability-weighted level
    severity_conf: float
    asks_secret: float
    impersonation: float
    payment_change: float | None = None
    refused: list[str] = []
    latency_ms: float
    evidence: list[Evidence] = []


CATEGORY_REASONS = {
    "kyc_freeze": "It follows the pattern of a fake KYC / account-block scam.",
    "upi_trap": "It looks like a UPI trick — you never need to enter your UPI PIN to receive money.",
    "otp_theft": "It is trying to get your OTP or PIN, which gives full access to your account.",
    "fake_job": "It matches the fake job / paid-task scam pattern (easy money, then fees).",
    "lottery_prize": "It uses a prize, lottery or cashback lure — classic bait for scams.",
    "impersonation": "It impersonates an official organisation to pressure you.",
    "invoice_fraud": "It asks you to pay to a new or changed bank account — a common invoice fraud.",
    "delivery": "It matches the fake parcel / courier re-delivery scam.",
    "credential_phish": "It looks like a fake security or account alert designed to steal your login.",
    "other_scam": "Its content matches known scam patterns.",
}

TRIGGER_REASONS = {
    "urgency": "It rushes you with a deadline so you act before thinking.",
    "fear": "It uses fear (blocked account, penalty, disconnection or arrest) to pressure you.",
    "authority": "It claims official authority to make you comply.",
    "greed": "It tempts you with money or a reward.",
    "curiosity": "It baits your curiosity to make you click.",
}


class DecisionClient:
    def __init__(self) -> None:
        self.provider = settings.decision_provider
        self.status = "disabled"
        self._http: httpx.AsyncClient | None = None
        self._ts: Any = None

    @property
    def model(self) -> str:
        return settings.decision_model if self.provider == "openai" else settings.jev_model

    @property
    def available(self) -> bool:
        return self._http is not None or self._ts is not None

    async def start(self) -> None:
        if not settings.decision_enabled:
            self.status = "disabled"
            return
        if self.provider == "openai":
            if not settings.openai_api_key:
                self.status = "no_api_key (OPENAI_API_KEY)"
                return
            self._http = httpx.AsyncClient(
                base_url=settings.openai_base_url,
                headers={"Authorization": f"Bearer {settings.openai_api_key}"},
                timeout=settings.decision_timeout_s,
            )
            self.status = "ready"
            await self._warm_up()
        elif self.provider == "jev":
            if not settings.openrouter_api_key:
                self.status = "no_api_key (OPENROUTER_API_KEY)"
                return
            try:
                from typesafe_sdk import AsyncTypeSafeClient, RetryPolicy

                self._ts = AsyncTypeSafeClient(
                    api_key=settings.openrouter_api_key, base_url=settings.openrouter_base_url,
                    model=settings.jev_model,
                    retry=RetryPolicy(max_retries=0, timeout=settings.decision_timeout_s),
                )
                self.status = "ready"
            except Exception as exc:
                log.warning("Jev client init failed: %r", exc)
                self.status = f"error: {exc.__class__.__name__}"
        else:
            self.status = f"unknown provider {self.provider!r}"

    async def _warm_up(self) -> None:
        """First Decisions call is slow (~4 s); pay that at startup, not on the first user request."""
        t0 = time.perf_counter()
        r = await self.classify(Envelope(channel="sms", text="Your OTP is 123456. Do not share it."), [])
        log.info("Tier 1 warm-up: %s in %.0f ms", "ok" if r else "failed", (time.perf_counter() - t0) * 1000)
        if r is None:
            self.status = "ready (warm-up failed)"

    async def close(self) -> None:
        if self._http:
            await self._http.aclose()
        if self._ts:
            await self._ts.close()

    async def classify(self, env: Envelope, tier0_evidence: list[Evidence]) -> DecisionResult | None:
        if not self.available:
            return None
        state = build_state(env, tier0_evidence)
        questions = build_questions(env.channel)
        t0 = time.perf_counter()
        try:
            if self._http is not None:
                answers, model = await self._call_openai(state, questions)
            else:
                answers, model = await self._call_jev(state, questions)
        except Exception as exc:
            log.warning("Tier 1 (%s) call failed: %r", self.provider, exc)
            return None
        latency = (time.perf_counter() - t0) * 1000
        return _to_result(answers, self.provider, model, latency, env.channel)

    async def _call_openai(self, state: dict, questions: list) -> tuple[dict[str, dict], str]:
        assert self._http is not None
        resp = await self._http.post("/decisions", json={
            "model": settings.decision_model,
            "input": openai_input(state),
            "questions": to_openai(questions),
            "prompt_cache_key": f"scamshield-{state['channel']}",
        })
        if resp.status_code >= 400:
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        answers: dict[str, dict] = {}
        for a in data["answers"]:
            t = a["type"]
            if t == "refusal":
                answers[a["name"]] = {"refused": True}
            elif t == "predicate":
                answers[a["name"]] = {"p": a["probability"]}
            elif t == "choice":
                answers[a["name"]] = {"choice": a["choice"], "confidence": a["confidence"],
                                      "probs": {str(p["value"]): p["probability"] for p in a["probabilities"]}}
            elif t == "score":
                answers[a["name"]] = {"score": a["score"], "confidence": a["confidence"]}
        return answers, data.get("model", settings.decision_model)

    async def _call_jev(self, state: dict, questions: list) -> tuple[dict[str, dict], str]:
        r = await self._ts.system_one(state=state, questions=to_typesafe(questions))
        answers: dict[str, dict] = {}
        for name, a in r.nouls.items():
            answers[name] = {"p": a.noul}
        for name, a in r.choices.items():
            answers[name] = {"choice": a.choice, "confidence": a.confidence,
                             "probs": {str(k): float(v) for k, v in a.probabilities.items()}}
        for name, a in r.scores.items():
            answers[name] = {"score": a.score, "confidence": a.confidence}
        return answers, getattr(r, "model", settings.jev_model)


def _to_result(ans: dict[str, dict], provider: str, model: str, latency_ms: float, channel: str) -> DecisionResult | None:
    refused = [k for k, v in ans.items() if v.get("refused")]
    if "p" not in ans.get("is_scam", {}):
        log.warning("Tier 1 gave no is_scam answer (refused=%s)", refused)
        return None
    cat = ans.get("category", {})
    trig = ans.get("trigger", {})
    sev = ans.get("severity", {})
    res = DecisionResult(
        provider=provider,
        model=model,
        p_scam=ans["is_scam"]["p"],
        category=str(cat.get("choice", "none")),
        category_conf=cat.get("confidence", 0.0),
        category_probs=cat.get("probs", {}),
        trigger=str(trig.get("choice", "none")),
        trigger_conf=trig.get("confidence", 0.0),
        severity=sev.get("score", 0.0),
        severity_conf=sev.get("confidence", 0.0),
        asks_secret=ans.get("asks_secret", {}).get("p", 0.0),
        impersonation=ans.get("impersonation", {}).get("p", 0.0),
        payment_change=ans.get("payment_change", {}).get("p") if channel == "email" else None,
        refused=refused,
        latency_ms=latency_ms,
    )
    res.evidence = decision_evidence(res)
    return res


def decision_evidence(d: DecisionResult) -> list[Evidence]:
    """Turn typed answers into explainable Evidence. Weights come from the model's own probabilities."""
    ev: list[Evidence] = []
    scammy = d.p_scam >= 0.35
    if scammy and d.category in CATEGORY_REASONS and d.category_conf >= 0.3:
        ev.append(Evidence(
            id=f"t1.category.{d.category}", source="tier1", weight=d.p_scam * d.category_conf,
            reason=CATEGORY_REASONS[d.category],
            detail={"category": d.category, "label": CATEGORIES.get(d.category), "confidence": d.category_conf},
        ))
    if scammy and d.trigger in TRIGGER_REASONS and d.trigger_conf >= 0.3:
        ev.append(Evidence(
            id=f"t1.trigger.{d.trigger}", source="tier1", weight=0.5 * d.p_scam * d.trigger_conf,
            reason=TRIGGER_REASONS[d.trigger],
            detail={"trigger": d.trigger, "label": TRIGGERS.get(d.trigger), "confidence": d.trigger_conf},
        ))
    if d.asks_secret >= 0.6:
        ev.append(Evidence(
            id="t1.asks_secret", source="tier1", weight=d.asks_secret,
            reason="It asks for a secret (OTP, PIN or password) — no genuine bank or company ever asks for this.",
            detail={"p": d.asks_secret},
        ))
    if scammy and d.impersonation >= 0.6:
        ev.append(Evidence(
            id="t1.impersonation", source="tier1", weight=0.5 * d.impersonation,
            reason="It claims to be from an official organisation, but other signs say it isn't genuine.",
            detail={"p": d.impersonation},
        ))
    if d.payment_change is not None and d.payment_change >= 0.6:
        ev.append(Evidence(
            id="t1.payment_change", source="tier1", weight=d.payment_change,
            reason="It asks you to send money to a new or changed bank account — verify by phone first.",
            detail={"p": d.payment_change},
        ))
    return ev


decision_client = DecisionClient()
