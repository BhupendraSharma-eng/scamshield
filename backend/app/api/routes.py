"""HTTP API. Thin layer: build an Envelope, hand it to the pipeline."""

import asyncio
from typing import Any, Literal

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

from app import db
from app.config import settings
from app.engine.fusion import rules_score
from app.engine.pipeline import analyze
from app.parsers.email import parse_raw_email, parse_simple_email
from app.schemas import Envelope, Evidence
from app.tier0.local_model import local_models
from app.tier0.phone_rules import analyze_number, normalize
from app.tier0.url_analyzer import extract_urls
from app.tier1.decision_client import decision_client
from app.tier2.auditor import auditor

router = APIRouter(prefix="/api")

MAX_INPUT = 1_000_000


class SmsRequest(BaseModel):
    content: str = Field(min_length=1, max_length=20_000)
    sender: str | None = None


class EmailRequest(BaseModel):
    raw: str | None = Field(default=None, max_length=MAX_INPUT)   # full .eml source
    sender: str | None = None
    subject: str | None = None
    body: str | None = Field(default=None, max_length=MAX_INPUT)


class UrlRequest(BaseModel):
    url: str = Field(min_length=3, max_length=4000)


@router.post("/analyze/sms")
async def analyze_sms(req: SmsRequest, deep: bool = False) -> dict[str, Any]:
    env = Envelope(channel="sms", sender=req.sender, text=req.content.strip(), urls=extract_urls(req.content))
    return await analyze(env, deep=deep)


@router.post("/analyze/email")
async def analyze_email_json(req: EmailRequest, deep: bool = False) -> dict[str, Any]:
    if req.raw:
        env = parse_raw_email(req.raw)
    elif req.body:
        env = parse_simple_email(req.sender, req.subject, req.body)
    else:
        raise HTTPException(422, "Provide either `raw` (.eml source) or `body`.")
    return await analyze(env, deep=deep)


@router.post("/analyze/email/upload")
async def analyze_email_upload(file: UploadFile = File(...), deep: bool = False) -> dict[str, Any]:
    data = await file.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise HTTPException(413, "Email too large (max 1 MB).")
    return await analyze(parse_raw_email(data), deep=deep)


@router.post("/analyze/url")
async def analyze_url_endpoint(req: UrlRequest, deep: bool = False) -> dict[str, Any]:
    env = Envelope(channel="url", urls=[req.url.strip()])
    return await analyze(env, deep=deep)


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str) -> dict[str, Any]:
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.post("/scans/{scan_id}/deep-audit")
async def deep_audit(scan_id: str) -> dict[str, Any]:
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if not auditor.available:
        raise HTTPException(503, "LLM not configured (set OPENAI_API_KEY).")
    inp = scan["input"]
    env = Envelope(channel=scan["channel"], sender=inp.get("sender"), subject=inp.get("subject"),
                   text=inp.get("text") or "", urls=inp.get("urls") or [])
    from app.schemas import Evidence
    evidence = [Evidence(**e) for e in scan["evidence"]]
    scan["llm"] = {"status": "pending", "audit": None}
    await auditor.audit_and_update(scan, env, evidence)
    return scan


@router.get("/scans")
async def list_scans(
    limit: int = Query(50, ge=1, le=500),
    channel: Literal["sms", "email", "url"] | None = None,
    verdict: Literal["SCAM", "SUSPICIOUS", "SAFE"] | None = None,
) -> list[dict[str, Any]]:
    return await db.list_scans(limit, channel, verdict)


@router.get("/stats")
async def stats() -> dict[str, Any]:
    return await db.stats()


@router.get("/health")
async def health() -> dict[str, Any]:
    models_ok = bool(local_models.models)
    return {
        "status": "ok" if models_ok and decision_client.available else "degraded",
        "models": local_models.status,
        "tier1": {"provider": decision_client.provider, "status": decision_client.status, "model": decision_client.model},
        "llm": {"available": auditor.available, "provider": settings.llm_provider, "model": settings.llm_model},
        "thresholds": {"scam": settings.thresh_scam, "suspicious": settings.thresh_suspicious},
    }


class CallRequest(BaseModel):
    number: str = Field(default="", max_length=64)
    transcript: str | None = Field(default=None, max_length=20_000)
    name: str | None = Field(default=None, max_length=200)


class NumberReportRequest(BaseModel):
    number: str = Field(min_length=1, max_length=64)
    note: str | None = Field(default=None, max_length=500)


_CALL_ACTIONS = {
    "SCAM": "Don't share OTP, PIN or card details. Hang up and call the bank/agency on its official number. Report on 1930.",
    "SUSPICIOUS": "Be careful: never share OTP/UPI PIN on a call. Verify the caller independently.",
    "SAFE": "No scam signs for this number. Still, never share OTP or PIN on calls.",
}
_SMS_SAFE_REASON = "No links, sender tricks or scam language were found."


def _verdict_for(risk: float) -> str:
    if risk >= settings.thresh_scam:
        return "SCAM"
    if risk >= settings.thresh_suspicious:
        return "SUSPICIOUS"
    return "SAFE"


def _number_risk(evidence: list[Evidence]) -> float:
    score = rules_score(evidence)
    floors = [item.floor for item in evidence if item.floor is not None]
    return max(score, max(floors)) if floors else score


def _phone_reasons(evidence: list[Evidence], verdict: str) -> list[str]:
    if verdict == "SAFE":
        chosen = [item for item in evidence if item.reason and item.weight < 0]
        chosen.sort(key=lambda item: item.weight)
    else:
        chosen = [item for item in evidence if item.reason and item.weight >= 0.3]
        chosen.sort(
            key=lambda item: (item.floor is not None, item.floor or 0, item.weight),
            reverse=True,
        )
    reasons: list[str] = []
    for item in chosen:
        if item.reason not in reasons:
            reasons.append(item.reason)
    return reasons


@router.post("/analyze/call")
async def analyze_call(req: CallRequest) -> dict[str, Any]:
    e164 = normalize(req.number)
    reports = await db.get_report_count(e164) if e164 else 0
    evidence, info = analyze_number(req.number, reports)
    risk = _number_risk(evidence)

    transcript = (req.transcript or "").strip()
    scan_id: str | None = None
    category: str | None = None
    text_reasons: list[str] = []
    text_evidence: list[dict[str, Any]] = []
    if len(transcript) >= 15:
        scanned = await analyze(Envelope(
            channel="sms",
            sender=req.number,
            text=transcript,
            urls=extract_urls(transcript),
        ))
        risk = max(risk, float(scanned["risk"]))
        scan_id = scanned.get("scan_id")
        category = scanned.get("category")
        text_reasons = [reason for reason in scanned.get("reasons") or [] if reason and reason != _SMS_SAFE_REASON]
        text_evidence = list(scanned.get("evidence") or [])

    risk = round(risk, 4)
    verdict = _verdict_for(risk)
    if verdict == "SAFE":
        category = None
    elif not category:
        category = "other_scam"

    reasons: list[str] = []
    if verdict != "SAFE":
        reasons.extend(text_reasons)
    for reason in _phone_reasons(evidence, verdict):
        if reason not in reasons:
            reasons.append(reason)

    return {
        "verdict": verdict,
        "risk": risk,
        "number": info["e164"],
        "country": info["country"],
        "number_type": info["type"],
        "reports": reports,
        "reasons": reasons[:5],
        "action": _CALL_ACTIONS[verdict],
        "category": category,
        "scan_id": scan_id,
        "evidence": [item.model_dump() for item in evidence] + text_evidence,
    }


@router.post("/report/number")
async def report_number_endpoint(req: NumberReportRequest) -> dict[str, Any]:
    e164 = normalize(req.number)
    if not e164:
        raise HTTPException(422, "Enter a visible phone number.")
    count = await db.report_number(e164, req.note)
    return {"number": e164, "reports": count}
