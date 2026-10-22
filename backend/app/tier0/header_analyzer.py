"""Deterministic email header, link, and attachment checks."""

from __future__ import annotations

import re
from email.utils import parseaddr
from pathlib import PurePath
from urllib.parse import urlsplit

import tldextract

from app.schemas import Envelope, Evidence


_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
_FREE_MAIL = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me",
    "protonmail.com", "rediffmail.com", "yandex.com", "aol.com", "icloud.com",
}
_RISKY_EXTENSIONS = {
    "exe", "scr", "js", "vbs", "bat", "iso", "img", "html", "htm", "lnk",
    "apk", "docm", "xlsm",
}
_URLISH_TEXT_RE = re.compile(
    r"(?i)(?:https?://|www\.)[^\s<>]+|(?<![@\w.-])(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>]*)?"
)
_AUTH_RE = re.compile(r"(?i)\b(spf|dkim|dmarc)\s*=\s*([a-z_-]+)")


def _brand_helpers() -> tuple[dict[str, dict], object, object]:
    """Load the full registry when available, retaining standalone usability."""

    try:
        from app.tier0.brands import BRANDS, brand_for_domain, brands_mentioned

        return BRANDS, brand_for_domain, brands_mentioned
    except ImportError:  # pragma: no cover - only for standalone copying/runs
        brands = {
            "sbi": {"name": "SBI", "domains": ["onlinesbi.sbi", "sbi.co.in"], "aliases": ["sbi", "state bank"]},
            "hdfc": {"name": "HDFC Bank", "domains": ["hdfcbank.com"], "aliases": ["hdfc", "hdfc bank"]},
            "icici": {"name": "ICICI Bank", "domains": ["icicibank.com"], "aliases": ["icici", "icici bank"]},
            "axis": {"name": "Axis Bank", "domains": ["axisbank.com"], "aliases": ["axis", "axis bank"]},
            "paytm": {"name": "Paytm", "domains": ["paytm.com"], "aliases": ["paytm"]},
            "phonepe": {"name": "PhonePe", "domains": ["phonepe.com"], "aliases": ["phonepe", "phone pe"]},
            "amazon": {"name": "Amazon", "domains": ["amazon.in", "amazon.com"], "aliases": ["amazon"]},
            "flipkart": {"name": "Flipkart", "domains": ["flipkart.com"], "aliases": ["flipkart"]},
        }

        def fallback_brand_for_domain(domain: str) -> str | None:
            return next((key for key, value in brands.items() if domain in value["domains"]), None)

        def fallback_brands_mentioned(text: str) -> list[str]:
            lowered = text.lower()
            return [
                key for key, value in brands.items()
                if any(re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", lowered) for alias in value["aliases"])
            ]

        return brands, fallback_brand_for_domain, fallback_brands_mentioned


def _header(headers: dict[str, str], name: str) -> str:
    return next((value for key, value in headers.items() if key.lower() == name.lower()), "")


def _registered_domain(value: str) -> str:
    host = value.strip().lower().rstrip(".")
    if not host:
        return ""
    extracted = _EXTRACT(host)
    return (
        getattr(extracted, "top_domain_under_public_suffix", "")
        or getattr(extracted, "registered_domain", "")
        or host
    ).lower()


def _address_parts(raw_address: str) -> tuple[str, str, str]:
    display, address = parseaddr(raw_address or "")
    domain = address.rsplit("@", 1)[1].lower().rstrip(".") if "@" in address else ""
    return display, address, _registered_domain(domain)


def _url_domain(value: str) -> str:
    candidate = value.strip().strip("<>()[]{}.,;:'\"")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", candidate, re.I):
        candidate = "http://" + candidate
    return _registered_domain(urlsplit(candidate).hostname or "")


def _evidence(
    evidence_id: str,
    weight: float,
    reason: str,
    *,
    floor: float | None = None,
    **detail: object,
) -> Evidence:
    return Evidence(
        id=evidence_id,
        source="rule",
        weight=weight,
        floor=floor,
        reason=reason,
        detail=detail,
    )


def analyze_email(env: Envelope) -> list[Evidence]:
    """Analyze an email envelope without DNS or network access."""

    evidence: list[Evidence] = []
    brands, brand_for_domain, brands_mentioned = _brand_helpers()

    if env.headers_available:
        from_raw = _header(env.headers, "From") or env.sender or ""
        display, _from_address, from_domain = _address_parts(from_raw)
        _reply_display, _reply_address, reply_domain = _address_parts(_header(env.headers, "Reply-To"))
        _return_display, _return_address, return_domain = _address_parts(_header(env.headers, "Return-Path"))
        auth_raw = _header(env.headers, "Authentication-Results")
        auth: dict[str, list[str]] = {"spf": [], "dkim": [], "dmarc": []}
        for mechanism, result in _AUTH_RE.findall(auth_raw):
            auth[mechanism.lower()].append(result.lower())

        spf_failed = any(result in {"fail", "softfail"} for result in auth["spf"])
        dkim_failed = any(result in {"fail", "none"} for result in auth["dkim"])
        dmarc_failed = any(result == "fail" for result in auth["dmarc"])
        if spf_failed:
            evidence.append(_evidence(
                "hdr.spf_fail", 0.5,
                f"The sending server isn't authorized to send for `{from_domain}` (SPF failed).",
                domain=from_domain, results=auth["spf"],
            ))
        if dkim_failed:
            evidence.append(_evidence(
                "hdr.dkim_fail", 0.4,
                "The email's digital signature is missing or invalid (DKIM).",
                results=auth["dkim"],
            ))
        if dmarc_failed:
            evidence.append(_evidence(
                "hdr.dmarc_fail", 0.6,
                "The email failed the sender domain's anti-spoofing policy (DMARC).",
                results=auth["dmarc"],
            ))

        display_brands = brands_mentioned(display)
        spoofed_brand = next((key for key in display_brands if brand_for_domain(from_domain) != key), None)
        if spoofed_brand:
            brand_name = brands[spoofed_brand]["name"]
            if spf_failed or dkim_failed:
                evidence.append(_evidence(
                    "hdr.brand_spoof_auth", 0.9,
                    f"It's signed '{brand_name}' but comes from `{from_domain}`, and its authentication failed.",
                    floor=0.85, brand=spoofed_brand, domain=from_domain,
                ))
            else:
                evidence.append(_evidence(
                    "hdr.brand_spoof", 0.8,
                    f"It's signed '{brand_name}' but comes from `{from_domain}`.",
                    floor=0.80, brand=spoofed_brand, domain=from_domain,
                ))

            if from_domain in _FREE_MAIL:
                evidence.append(_evidence(
                    "hdr.freemail_brand", 0.75,
                    f"A '{brand_name}' email was sent from a free `{from_domain}` account.",
                    floor=0.75, brand=spoofed_brand, provider=from_domain,
                ))

        if reply_domain and from_domain and reply_domain != from_domain:
            evidence.append(_evidence(
                "hdr.replyto_mismatch", 0.5,
                f"Your reply would go to `{reply_domain}`, not the sender's company.",
                from_domain=from_domain, replyto=reply_domain,
            ))
        if return_domain and from_domain and return_domain != from_domain:
            evidence.append(_evidence(
                "hdr.returnpath_mismatch", 0.25, "",
                from_domain=from_domain, return_path=return_domain,
            ))

        all_auth_pass = all("pass" in auth[mechanism] for mechanism in ("spf", "dkim", "dmarc"))
        if all_auth_pass and brand_for_domain(from_domain) is not None:
            evidence.append(_evidence(
                "hdr.auth_pass", -0.4,
                f"Sender `{from_domain}` passed all authenticity checks.",
                domain=from_domain,
            ))

    for link in env.links:
        shown_match = _URLISH_TEXT_RE.search(link.text.strip())
        if not shown_match:
            continue
        shown_domain = _url_domain(shown_match.group(0))
        real_domain = _url_domain(link.href)
        if shown_domain and real_domain and shown_domain != real_domain:
            evidence.append(_evidence(
                "link.text_mismatch", 0.8,
                f"The link says `{shown_domain}` but actually opens `{real_domain}`.",
                floor=0.75, shown=shown_domain, real=real_domain, href=link.href,
            ))

    for name in env.attachments:
        filename = PurePath(name).name
        parts = [part.lower() for part in filename.split(".")]
        extension = parts[-1] if len(parts) > 1 else ""
        double_extension = len(parts) >= 3 and extension in _RISKY_EXTENSIONS
        if double_extension:
            evidence.append(_evidence(
                "att.double_ext", 0.85,
                f"The attachment hides its real type (`{filename}`).",
                floor=0.85, name=filename,
            ))
        if extension in _RISKY_EXTENSIONS:
            evidence.append(_evidence(
                "att.risky", 0.7,
                f"It has a risky attachment (`{filename}`) that can run code or show a fake login page.",
                floor=0.75, name=filename, extension=extension,
            ))

    return evidence
