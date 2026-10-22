"""OpenAI Decisions client: request shape and response mapping, with a mocked transport (no network)."""

import asyncio
import json

import httpx

from app.schemas import Envelope, Evidence
from app.tier1.decision_client import DecisionClient


def _client(handler) -> DecisionClient:
    c = DecisionClient()
    c.provider = "openai"
    c._http = httpx.AsyncClient(base_url="https://api.openai.com/v1", transport=httpx.MockTransport(handler))
    return c


SCAM_RESPONSE = {
    "model": "gpt-6-luna",
    "answers": [
        {"type": "predicate", "name": "is_scam", "probability": 0.97},
        {"type": "choice", "name": "category", "choice": "kyc_freeze", "confidence": 0.9,
         "probabilities": [{"value": "none", "probability": 0.02}, {"value": "kyc_freeze", "probability": 0.92}]},
        {"type": "choice", "name": "trigger", "choice": "fear", "confidence": 0.8,
         "probabilities": [{"value": "fear", "probability": 0.85}]},
        {"type": "score", "name": "severity", "score": 2.6, "confidence": 0.6,
         "probabilities": [{"value": 3, "label": "money_loss", "probability": 0.7}]},
        {"type": "predicate", "name": "asks_secret", "probability": 0.2},
        {"type": "predicate", "name": "impersonation", "probability": 0.95},
    ],
    "usage": {"input_tokens": 512, "output_tokens": 30, "total_tokens": 542},
}


def test_openai_request_shape_and_mapping() -> None:
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["path"] = req.url.path
        seen["body"] = json.loads(req.content)
        return httpx.Response(200, json=SCAM_RESPONSE)

    env = Envelope(channel="sms", text="Your SBI account will be blocked today. Update KYC: http://sbi-kyc.xyz",
                   urls=["http://sbi-kyc.xyz"])
    ev = [Evidence(id="url.lookalike", source="rule", weight=0.85, floor=0.8, reason="`sbi-kyc.xyz` imitates SBI")]
    r = asyncio.run(_client(handler).classify(env, ev))

    assert seen["path"] == "/v1/decisions"
    body = seen["body"]
    assert body["model"] == "gpt-6-luna"
    types = {q["name"]: q["type"] for q in body["questions"]}
    assert types == {"is_scam": "predicate", "category": "choice", "trigger": "choice", "severity": "score",
                     "asks_secret": "predicate", "impersonation": "predicate"}
    cat = next(q for q in body["questions"] if q["name"] == "category")
    assert cat["choices"][0]["value"] == "none"          # fallback first (first-option bias)
    assert "untrusted_message" in body["input"] and "imitates SBI" in body["input"]

    assert r is not None
    assert r.provider == "openai" and r.p_scam == 0.97
    assert r.category == "kyc_freeze" and r.trigger == "fear" and r.severity == 2.6
    assert {e.id for e in r.evidence} >= {"t1.category.kyc_freeze", "t1.trigger.fear", "t1.impersonation"}
    assert all(e.source == "tier1" for e in r.evidence)


def test_email_adds_payment_question() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        names = [q["name"] for q in json.loads(req.content)["questions"]]
        assert "payment_change" in names
        return httpx.Response(200, json=SCAM_RESPONSE)

    r = asyncio.run(_client(handler).classify(Envelope(channel="email", text="pay new account"), []))
    assert r is not None and r.payment_change is None   # not answered → stays None


def test_refused_main_question_returns_none() -> None:
    resp = {**SCAM_RESPONSE, "answers": [{"type": "refusal", "name": "is_scam"}, *SCAM_RESPONSE["answers"][1:]]}
    r = asyncio.run(_client(lambda req: httpx.Response(200, json=resp)).classify(Envelope(channel="sms", text="x"), []))
    assert r is None


def test_http_error_returns_none() -> None:
    r = asyncio.run(_client(lambda req: httpx.Response(429, json={"error": "rate"})).classify(
        Envelope(channel="sms", text="x"), []))
    assert r is None


def test_unconfigured_client_is_unavailable() -> None:
    c = DecisionClient()
    assert not c.available
    assert asyncio.run(c.classify(Envelope(channel="sms", text="x"), [])) is None
