"""Deterministic caller-ID checks for Indian call-scam detection.

`normalize` turns the forms people actually see ("98…", "098…", "+91 98…", "0091…")
into an E.164-ish string. `analyze_number` emits rule Evidence only — the route
supplies how many times that number has already been reported.
"""

from __future__ import annotations

import re
from typing import Any

from app.schemas import Evidence

# Hidden caller-ID labels from Android, iOS, and carrier networks.
_HIDDEN_RE = re.compile(
    r"(?i)^(?:hidden|private|unknown|withheld|anonymous|restricted|unavailable|"
    r"no\s*caller\s*id|blocked|private\s*number|null|none|n/?a|withheld\s*number)$"
)

# Government / bank short codes. 1800 and 1860 are matched by prefix, not listed here.
_SHORT_CODES = frozenset({
    "1930",    # national cyber-crime helpline
    "155260",
    "100", "101", "102", "108", "112",
    "1091", "1098", "139", "182", "1075", "1912", "14567",
})

# Country calling codes we can name. Longest prefix wins.
_CALLING_CODES: dict[str, str] = {
    "1": "United States",
    "7": "Russia",
    "20": "Egypt",
    "27": "South Africa",
    "30": "Greece",
    "31": "Netherlands",
    "32": "Belgium",
    "33": "France",
    "34": "Spain",
    "39": "Italy",
    "41": "Switzerland",
    "43": "Austria",
    "44": "United Kingdom",
    "45": "Denmark",
    "46": "Sweden",
    "47": "Norway",
    "48": "Poland",
    "49": "Germany",
    "51": "Peru",
    "52": "Mexico",
    "53": "Cuba",
    "54": "Argentina",
    "55": "Brazil",
    "56": "Chile",
    "57": "Colombia",
    "58": "Venezuela",
    "60": "Malaysia",
    "61": "Australia",
    "62": "Indonesia",
    "63": "Philippines",
    "64": "New Zealand",
    "65": "Singapore",
    "66": "Thailand",
    "81": "Japan",
    "82": "South Korea",
    "84": "Vietnam",
    "86": "China",
    "90": "Turkey",
    "91": "India",
    "92": "Pakistan",
    "93": "Afghanistan",
    "94": "Sri Lanka",
    "95": "Myanmar",
    "98": "Iran",
    "212": "Morocco",
    "213": "Algeria",
    "216": "Tunisia",
    "220": "Gambia",
    "221": "Senegal",
    "222": "Mauritania",
    "223": "Mali",
    "224": "Guinea",
    "225": "Ivory Coast",
    "226": "Burkina Faso",
    "227": "Niger",
    "228": "Togo",
    "229": "Benin",
    "230": "Mauritius",
    "231": "Liberia",
    "232": "Sierra Leone",
    "233": "Ghana",
    "234": "Nigeria",
    "235": "Chad",
    "237": "Cameroon",
    "249": "Sudan",
    "250": "Rwanda",
    "251": "Ethiopia",
    "252": "Somalia",
    "254": "Kenya",
    "255": "Tanzania",
    "256": "Uganda",
    "260": "Zambia",
    "263": "Zimbabwe",
    "264": "Namibia",
    "265": "Malawi",
    "266": "Lesotho",
    "267": "Botswana",
    "880": "Bangladesh",
    "852": "Hong Kong",
    "853": "Macau",
    "855": "Cambodia",
    "856": "Laos",
    "886": "Taiwan",
    "960": "Maldives",
    "961": "Lebanon",
    "962": "Jordan",
    "964": "Iraq",
    "965": "Kuwait",
    "966": "Saudi Arabia",
    "968": "Oman",
    "971": "United Arab Emirates",
    "972": "Israel",
    "973": "Bahrain",
    "974": "Qatar",
    "975": "Bhutan",
    "977": "Nepal",
    "992": "Tajikistan",
    "993": "Turkmenistan",
    "994": "Azerbaijan",
    "995": "Georgia",
    "996": "Kyrgyzstan",
    "998": "Uzbekistan",
}

# Prefixes commonly used for wangiri / impersonation calls into India.
# +977 (Nepal) is deliberately absent. +44 is only the mobile range (+447).
# +1 is only flagged when it does not look like a real NANP number.
_RISKY_CODES: dict[str, str] = {
    "880": "Bangladesh",
    "234": "Nigeria",
    "225": "Ivory Coast",
    "222": "Mauritania",
    "252": "Somalia",
    "855": "Cambodia",
    "856": "Laos",
    "92": "Pakistan",
    "95": "Myanmar",
    "62": "Indonesia",
    "63": "Philippines",
    "84": "Vietnam",
    "60": "Malaysia",
    "66": "Thailand",
}

_INTL_REASON = (
    "Call from {country} (+{code}) — international calls pretending to be Indian banks, "
    "police or courier companies are a common scam."
)


def _is_hidden(number: str) -> bool:
    raw = (number or "").strip()
    if not raw:
        return True
    compact = re.sub(r"[\s.\-_/]+", " ", raw).strip()
    return _HIDDEN_RE.match(compact) is not None


def _match_code(digits: str) -> tuple[str, str] | None:
    """Longest calling-code prefix with at least a few subscriber digits left."""
    for length in (3, 2, 1):
        code = digits[:length]
        country = _CALLING_CODES.get(code)
        if country and len(digits) - length >= 4:
            return code, country
    return None


def _nanp(national: str) -> bool:
    """True when `national` looks like NPA-NXX-XXXX (the +1 numbering plan)."""
    if len(national) != 10 or not national.isdigit():
        return False
    area, exchange = national[:3], national[3:6]
    if area[0] in "01" or exchange[0] in "01":
        return False
    if area.endswith("11") or exchange.endswith("11"):
        return False
    return True


def _risky(digits: str) -> tuple[str, str] | None:
    """Return (calling code, country) when this non-Indian number is a known scam source."""
    if digits.startswith("447"):
        return "44", "United Kingdom"
    if digits.startswith("1"):
        if _nanp(digits[1:]):
            return None
        return "1", "United States"
    for length in (3, 2):
        code = digits[:length]
        country = _RISKY_CODES.get(code)
        if country:
            return code, country
    return None


def _india_type(national: str) -> str:
    if national in _SHORT_CODES:
        return "shortcode"
    if national.startswith(("1800", "1860")) and len(national) >= 10:
        return "tollfree"
    if national.startswith("140") and len(national) == 10:
        return "telemarketer"
    if len(national) != 10:
        return "invalid"
    if national[0] in "6789":
        return "mobile"
    return "landline"


def _evidence(
    evidence_id: str,
    weight: float,
    reason: str,
    *,
    floor: float | None = None,
    **detail: Any,
) -> Evidence:
    return Evidence(
        id=evidence_id,
        source="rule",
        weight=weight,
        floor=floor,
        reason=reason,
        detail=detail,
    )


def normalize(number: str) -> str:
    """E.164-ish form (`+` and digits), or `""` when the caller ID is hidden or empty."""
    if _is_hidden(number):
        return ""
    raw = number.strip()
    digits = re.sub(r"\D", "", raw)
    if not digits:
        return ""

    if digits.startswith("00"):
        rest = digits[2:]
        return f"+{rest}" if rest else ""
    if raw.startswith("+"):
        return f"+{digits}"

    # Domestic trunk prefix: 098… and 011… are 0 + a 10-digit national number.
    if digits.startswith("0"):
        national = digits[1:]
        if national.startswith("91") and len(national) >= 12:
            return f"+{national}"
        return f"+91{national}"

    if digits.startswith("91") and len(digits) == 12:
        return f"+{digits}"
    if len(digits) == 10:
        return f"+91{digits}"
    if digits.startswith(("1800", "1860")) and len(digits) in {10, 11}:
        return f"+91{digits}"
    if digits in _SHORT_CODES:
        return f"+91{digits}"

    # A long digit string with a real calling code and no + (92300…, 447700…).
    # Bare +1 is too easy to confuse with Indian 1xx numbers, so it still needs a +.
    if len(digits) >= 11:
        matched = _match_code(digits)
        if matched and matched[0] not in {"1", "91"}:
            return f"+{digits}"

    return f"+91{digits}"


def _reported(count: int) -> Evidence:
    noun = "user" if count == 1 else "users"
    return _evidence(
        "call.reported",
        min(0.5 + 0.1 * count, 0.95),
        f"Reported as a scam by {count} ScamShield {noun}.",
        floor=0.75 if count >= 3 else None,
        count=count,
    )


def analyze_number(number: str, reports: int = 0) -> tuple[list[Evidence], dict[str, Any]]:
    """Rule evidence for one caller ID, plus ``{"e164", "country", "type"}``.

    `reports` is the existing row count from `number_reports` (0 when unseen).
    The function does not touch the database.
    """
    count = reports if reports > 0 else 0
    if _is_hidden(number) or not normalize(number):
        if _is_hidden(number):
            evidence = [_evidence("call.hidden", 0.35, "The caller's number is hidden.", input=number or "")]
            if count:
                evidence.append(_reported(count))
            return evidence, {"e164": "", "country": None, "type": "hidden"}
        evidence = [_evidence(
            "call.spoof_format",
            0.4,
            "This number's length doesn't match a real phone number.",
            input=number or "",
        )]
        return evidence, {"e164": "", "country": None, "type": "unknown"}

    e164 = normalize(number)
    digits = e164[1:]
    evidence: list[Evidence] = []

    if digits.startswith("91"):
        national = digits[2:]
        kind = _india_type(national)
        info: dict[str, Any] = {"e164": e164, "country": "India", "type": kind}
        if kind in {"tollfree", "shortcode"}:
            evidence.append(_evidence(
                "call.safe_bank",
                -0.4,
                "This is an official toll-free helpline number.",
                e164=e164,
            ))
        elif kind == "telemarketer":
            evidence.append(_evidence(
                "call.telemarketer",
                0.2,
                "This is a registered telemarketing number (140 series).",
                e164=e164,
            ))
        elif kind == "invalid":
            evidence.append(_evidence(
                "call.spoof_format",
                0.4,
                "This number's length doesn't match a real phone number.",
                e164=e164,
            ))
    else:
        code_match = _match_code(digits)
        risky = _risky(digits) if len(digits) >= 7 else None
        if risky:
            code, country = risky
            kind = "mobile" if code == "44" else "international"
            info = {"e164": e164, "country": country, "type": kind}
            evidence.append(_evidence(
                "call.intl_risky",
                0.6,
                _INTL_REASON.format(country=country, code=code),
                floor=0.70,
                e164=e164,
                country=country,
                calling_code=code,
            ))
        elif len(digits) < 7:
            country = code_match[1] if code_match else None
            info = {"e164": e164, "country": country, "type": "invalid"}
            evidence.append(_evidence(
                "call.spoof_format",
                0.4,
                "This number's length doesn't match a real phone number.",
                e164=e164,
            ))
        else:
            code, country = code_match if code_match else ("", None)
            national = digits[len(code):] if code else digits
            if code == "44" and national.startswith("7"):
                kind = "mobile"
            elif code == "44":
                kind = "landline"
            elif code == "1" and _nanp(national):
                kind = "mobile"
            else:
                kind = "international"
            info = {"e164": e164, "country": country, "type": kind}
            evidence.append(_evidence(
                "call.intl",
                0.25,
                "This is an international call, not an Indian number.",
                e164=e164,
                country=country,
                calling_code=code,
            ))

    if count:
        evidence.append(_reported(count))
    return evidence, info
