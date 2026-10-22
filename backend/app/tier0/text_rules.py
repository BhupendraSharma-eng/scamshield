"""Fast, deterministic scam-language rules for SMS and email text."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable

from app.schemas import Evidence

try:
    from app.tier0.url_analyzer import extract_urls
except ImportError:  # pragma: no cover - useful when this file is run alone
    _FALLBACK_URL_RE = re.compile(
        r"(?i)(?:https?://|www\.|bit\.ly/|wa\.me/)[^\s]+|"
        r"(?<![@\w.-])(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s]*)?"
    )

    def extract_urls(text: str) -> list[str]:
        return [match.group(0) for match in _FALLBACK_URL_RE.finditer(text)]


_FLAGS = re.IGNORECASE

# Patterns are deliberately bounded: these are useful hints, not a general NLP
# model.  Alternate word orders cover common Indian scam-message phrasing.
_ASKS_OTP_RE = re.compile(
    r"\b(?:share|send|tell|batao|bataye(?:in)?|bataiye|bhejo|forward|provide)\b"
    r".{0,20}?\b(?:otp|upi\s*pin|pin|cvv|password|m\s*pin)\b"
    r"|\b(?:otp|upi\s*pin|pin|cvv|password|m\s*pin)\b"
    r".{0,20}?\b(?:batao|bataye(?:in)?|bataiye|bhejo|share|send|tell)\b",
    _FLAGS,
)
_KYC_RE = re.compile(
    r"\bkyc\b.{0,20}?\b(?:update|updated|expired?|pending|suspend(?:ed)?)\b"
    r"|\b(?:update|complete|renew)\b.{0,20}?\bkyc\b"
    r"|\b(?:pan|aadhaar|aadhar)\b.{0,20}?\b(?:link|update|verify)\b",
    _FLAGS,
)
_ACCOUNT_BLOCK_RE = re.compile(
    r"\b(?:account|bank\s+account)\b.{0,25}?\b(?:will\s+be\s+|ho\s+)?"
    r"(?:block(?:ed)?|suspend(?:ed)?|freez(?:e|ed)|clos(?:e|ed)|band\s+ho\s+jayega)\b"
    r"|\b(?:khata|account)\b.{0,15}?\bband(?:\s+ho\s+jayega)?\b",
    _FLAGS,
)
_UPI_COLLECT_RE = re.compile(
    r"\b(?:receive|collect|refund|cashback|paisa)\b.{0,25}?"
    r"\b(?:enter|scan|upi\s*pin|qr)\b"
    r"|\b(?:enter\s+(?:your\s+)?upi\s*pin|scan\s+(?:the\s+)?qr(?:\s+code)?)\b"
    r".{0,25}?\b(?:to\s+)?(?:receive|collect|get|refund|cashback|paisa)\b",
    _FLAGS,
)
_LOTTERY_RE = re.compile(
    r"\b(?:won|winner|lottery|lucky\s*draw|prize|inaam)\b"
    r"|\bcashback\s+(?:of\s+)?(?:rs\.?|inr|₹)?\s*\d+",
    _FLAGS,
)
_JOB_TASK_RE = re.compile(
    r"\b(?:part[\s-]?time(?:\s+job)?|work\s+from\s+home|ghar\s+baithe\s+kamao|"
    r"daily\s+(?:earn|income)|(?:like|liking)\s+(?:videos?|youtube)|task|naukri)\b"
    r".{0,45}?(?:rs\.?|inr|₹|\b\d{3,}\b)",
    _FLAGS,
)
_ELECTRICITY_RE = re.compile(
    r"\b(?:electricity|bijli|power)\b.{0,35}?\b(?:disconnect(?:ed|ion)?|cut|band)\b"
    r".{0,35}?\b(?:tonight|today|aaj|raat|9\s*[:.]\s*30)\b"
    r"|\b(?:tonight|today|aaj)\b.{0,35}?\b(?:electricity|bijli|power)\b"
    r".{0,35}?\b(?:disconnect(?:ed|ion)?|cut|band)\b",
    _FLAGS,
)
_COURIER_RE = re.compile(
    r"\b(?:parcel|courier|package)\b.{0,35}?"
    r"\b(?:held|customs|address\s+incomplete|re[\s-]?delivery\s+fee|delivery\s+fee)\b",
    _FLAGS,
)
_DIGITAL_ARREST_RE = re.compile(
    r"\b(?:cbi|police|customs|narcotics|ed|trai|cyber\s+police)\b.{0,50}?"
    r"\b(?:arrest|case|warrant|video\s*call)\b",
    _FLAGS,
)
_URGENCY_RE = re.compile(
    r"\b(?:within|in)\s+\d+\s*(?:hours?|hrs?|minutes?|mins?)\b"
    r"|\b(?:immediately|last\s+chance|urgent(?:ly)?|turant|abhi)\b",
    _FLAGS,
)
_MONEY_RE = re.compile(r"(?:\brs\.?|\binr\b|₹)\s*\d[\d,]*(?:\.\d{1,2})?", _FLAGS)
_PHONE_CTA_RE = re.compile(
    r"\bcall\s+(?:now|immediately|on)\s*(?:\+?\d[\d\s-]{8,}\d)", _FLAGS
)
_APK_RE = re.compile(
    r"\bdownload\b.{0,20}?\b(?:apk|app)\b.{0,35}?\b(?:link|https?://|www\.)"
    r"|\bdownload\b.{0,55}?https?://\S+?\.(?:apk|exe|scr)\b",
    _FLAGS,
)
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?\d{10}(?!\d)")
_NEGATED_SHARE_RE = re.compile(
    r"(?:\bdo\s+not|\bdon['’]?t|\bnever|\bna|\bmat)\s+$", _FLAGS
)
_NEGATED_ACTION_RE = re.compile(
    r"\b(?:do\s+not|don['’]?t|never|na|mat)\b.{0,12}?"
    r"\b(?:share|send|tell|batao|bataye(?:in)?|bataiye|bhejo|forward|provide)\b",
    _FLAGS,
)


def _matches(pattern: re.Pattern[str], text: str) -> list[str]:
    """Return non-empty matched spans, normalized only at their edges."""

    return [match.group(0).strip() for match in pattern.finditer(text) if match.group(0).strip()]


def _otp_matches(text: str) -> list[str]:
    results: list[str] = []
    for match in _ASKS_OTP_RE.finditer(text):
        # A legitimate alert commonly says "Do not share OTP".  Since the
        # regex starts at "share", inspect its immediate left context.
        left = text[max(0, match.start() - 16) : match.start()]
        if _NEGATED_SHARE_RE.search(left) or _NEGATED_ACTION_RE.search(match.group(0)):
            continue
        results.append(match.group(0).strip())
    return results


def _evidence(
    evidence_id: str,
    weight: float,
    reason: str,
    matches: Iterable[str],
    *,
    floor: float | None = None,
) -> Evidence:
    spans = list(matches)
    return Evidence(
        id=evidence_id,
        source="rule",
        weight=weight,
        floor=floor,
        reason=reason,
        detail={"matches": spans},
    )


def _quoted_reason(prefix: str, matches: list[str], suffix: str = "") -> str:
    phrase = matches[0].replace('"', "'")
    return f'{prefix} ("{phrase}"){suffix}'


def analyze_text(text: str) -> list[Evidence]:
    """Return all deterministic text-rule evidence found in *text*."""

    if not text:
        return []

    evidence: list[Evidence] = []
    otp_matches = _otp_matches(text)
    destinations = extract_urls(text)
    if not destinations:
        destinations = [match.group(0) for match in _PHONE_RE.finditer(text)]
    has_destination = bool(destinations)

    if otp_matches:
        reason = _quoted_reason(
            "It asks you to share a private security code",
            otp_matches,
            " — banks never ask for this.",
        )
        evidence.append(_evidence("txt.asks_otp", 0.6, reason, otp_matches))
        if has_destination:
            evidence[-1].reason = ""
            evidence.append(_evidence(
                "txt.otp_plus_link",
                0.9,
                _quoted_reason(
                    "It asks for a private security code and gives you a link or phone number",
                    otp_matches,
                    " — a strong sign of credential theft.",
                ),
                [*otp_matches, *destinations],
                floor=0.90,
            ))

    rules: tuple[tuple[str, re.Pattern[str], float, float | None, str], ...] = (
        ("txt.kyc", _KYC_RE, 0.45, None, "It pressures you to update or verify identity details"),
        ("txt.account_block", _ACCOUNT_BLOCK_RE, 0.45, None, "It threatens to block or close your account"),
        ("txt.upi_collect", _UPI_COLLECT_RE, 0.7, 0.75, "It tells you to enter a UPI PIN or scan a QR code to receive money"),
        ("txt.lottery", _LOTTERY_RE, 0.45, None, "It promises an unexpected prize, lottery win, or cashback"),
        ("txt.job_task", _JOB_TASK_RE, 0.5, None, "It offers easy money for a part-time job or simple online tasks"),
        ("txt.electricity", _ELECTRICITY_RE, 0.65, 0.70, "It threatens an urgent electricity disconnection"),
        ("txt.courier", _COURIER_RE, 0.45, None, "It claims a parcel is held or needs an extra delivery action"),
        ("txt.digital_arrest", _DIGITAL_ARREST_RE, 0.7, 0.75, "It uses an authority and arrest or video-call threat to frighten you"),
        ("txt.urgency", _URGENCY_RE, 0.25, None, "It creates artificial urgency"),
        ("txt.money_amount", _MONEY_RE, 0.1, None, "It emphasizes a money amount"),
        ("txt.phone_call_to_action", _PHONE_CTA_RE, 0.3, None, "It tells you to call a phone number immediately"),
        ("txt.apk", _APK_RE, 0.6, 0.70, "It asks you to download an app or APK from a link"),
    )
    for evidence_id, pattern, weight, floor, prefix in rules:
        spans = _matches(pattern, text)
        if spans:
            evidence.append(_evidence(
                evidence_id,
                weight,
                _quoted_reason(prefix, spans, "."),
                spans,
                floor=floor,
            ))

    return evidence


def rules_score(evidence: list[Evidence]) -> float:
    """Combine rule weights using the documented noisy-OR formula."""

    positive = 1.0 - math.prod(1.0 - item.weight for item in evidence if item.weight > 0)
    negative = 0.5 * sum(abs(item.weight) for item in evidence if item.weight < 0)
    return max(0.0, min(1.0, positive - negative))
