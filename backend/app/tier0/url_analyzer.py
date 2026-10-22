"""Fast, deterministic URL checks for the Tier-0 scam detector."""

from __future__ import annotations

import ipaddress
import math
import re
from urllib.parse import unquote, urlsplit

import idna
import tldextract
from pydantic import BaseModel, Field
from rapidfuzz.distance import Levenshtein

from app.schemas import Evidence
from app.tier0.brands import BRANDS, SAFE_DOMAINS


# ernet.in is an education-network suffix missing from the bundled public-suffix snapshot.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), extra_suffixes=["ernet.in"])
_RISKY_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "buzz", "rest", "club", "cc", "info",
    "cam", "icu", "sbs", "cfd", "live", "shop", "online", "site",
}
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy",
    "shorturl.at", "goo.gl", "ow.ly", "tiny.cc",
}
_SENSITIVE_WORDS = (
    "login", "verify", "update", "kyc", "secure", "account", "wallet",
    "refund", "otp", "bank", "pay", "reward", "claim",
)
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"})
_COMMON_TLDS = (
    "com|org|net|in|co\\.in|gov\\.in|bank\\.in|sbi|io|ai|app|dev|me|ly|co|uk|"
    "info|biz|xyz|top|online|site|shop|live|cfd|icu|click|buzz|rest|cam|sbs"
)
_URL_RE = re.compile(
    rf"(?ix)"
    rf"(?:https?://[^\s<>\"']+|www\.[^\s<>\"']+|"
    rf"(?<![@a-z0-9_.-])(?:[a-z0-9](?:[a-z0-9-]{{0,62}}[a-z0-9])?\.)+(?:{_COMMON_TLDS})"
    rf"(?::\d{{1,5}})?(?:/[^\s<>\"']*)?)"
)
_TRAILING_PUNCTUATION = ".,;:!?)]}>'\""
_INSTITUTIONAL_SUFFIXES = frozenset({
    "ac.in", "edu", "edu.in", "gov.in", "nic.in", "res.in", "ernet.in", "mil", "gov",
})


class UrlAnalysis(BaseModel):
    """Normalized URL and the evidence emitted by its rule checks."""

    url: str
    normalized: str
    host: str
    registered_domain: str
    evidence: list[Evidence] = Field(default_factory=list)
    rules_score: float


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


def _ascii_host(host: str) -> str:
    """Convert a Unicode hostname to the ASCII form expected by DNS tools."""

    try:
        return idna.encode(host, uts46=True).decode("ascii").lower()
    except idna.IDNAError:
        # Invalid IDNs are still analyzable by the remaining lexical rules.
        try:
            return host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return host.lower()


def _display_host(host: str) -> str:
    try:
        return idna.decode(host, uts46=True)
    except idna.IDNAError:
        labels: list[str] = []
        for label in host.split("."):
            try:
                labels.append(label.encode("ascii").decode("idna"))
            except (UnicodeError, ValueError):
                labels.append(label)
        return ".".join(labels)


def _homoglyph_normalize(value: str) -> str:
    value = value.lower().translate(_HOMOGLYPHS)
    # These multi-character lookalikes must be replaced after digit swaps.
    return value.replace("rn", "m").replace("vv", "w")


def _compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", _homoglyph_normalize(value))


def _registered_domain(host: str) -> tuple[str, str, str]:
    """Return registrable domain, subdomain and public suffix."""

    try:
        ipaddress.ip_address(host)
        return host, "", ""
    except ValueError:
        pass

    extracted = _EXTRACT(host)
    registered = getattr(extracted, "top_domain_under_public_suffix", "")
    if not registered:
        registered = getattr(extracted, "registered_domain", "")
    if not registered:
        registered = host
    return registered.lower(), extracted.subdomain.lower(), extracted.suffix.lower()


def _is_free_host(host: str, path: str) -> bool:
    if host in {"sites.google.com", "forms.gle"}:
        return True
    if host == "docs.google.com" and path.lower().startswith("/forms"):
        return True
    fixed_suffixes = (
        ".web.app", ".firebaseapp.com", ".netlify.app", ".vercel.app",
        ".github.io", ".blogspot.com", ".weebly.com", ".wixsite.com",
        ".trycloudflare.com",
    )
    if host.endswith(fixed_suffixes):
        return True
    return bool(re.search(r"(?:^|\.)ngrok[^.]*\.app$", host))


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum(
        (count / len(value)) * math.log2(count / len(value))
        for count in (value.count(char) for char in set(value))
    )


def _brand_targets(brand: dict) -> set[str]:
    targets = {_compact(alias) for alias in brand["aliases"]}
    for domain in brand["domains"]:
        extracted = _EXTRACT(domain)
        if extracted.domain:
            targets.add(_compact(extracted.domain))
        targets.add(_compact(domain.split(".", 1)[0]))
    return {target for target in targets if target}


def _lookalike_limit(target_len: int) -> int:
    """Edit distance allowed after homoglyph normalization, by target length."""

    if target_len <= 4:
        return 0
    if target_len <= 7:
        return 1
    return 2


def _find_lookalike(first_label: str) -> tuple[str, str] | None:
    candidate = _compact(first_label)
    if not candidate:
        return None
    normalized_candidate = _homoglyph_normalize(first_label.lower())
    for key, brand in BRANDS.items():
        for target in _brand_targets(brand):
            distance = Levenshtein.distance(candidate, target)
            # Short targets only match exactly: rn→m turned "rntu" into "mtu" ≈ "meta".
            close = len(target) >= 3 and distance <= _lookalike_limit(len(target))
            if distance > 0:
                close = (
                    close
                    and abs(len(candidate) - len(target)) <= 2
                    and candidate[:1] == target[:1]
                )
            swapped = candidate == target and first_label.lower() != target
            if close or swapped or normalized_candidate == target:
                return key, brand["domains"][0]
    return None


def _exact_brand_key(first_label: str) -> str | None:
    """Brand whose normalized name is exactly this registered label, if any."""

    candidate = _compact(first_label)
    raw = first_label.lower()
    if not candidate and not raw:
        return None
    for key, brand in BRANDS.items():
        targets = _brand_targets(brand)
        if raw in targets or candidate in targets:
            return key
    return None


def _find_brand_in_untrusted_location(
    subdomain: str, first_label: str, path: str, *, include_registered_label: bool = True,
) -> str | None:
    label_part = first_label if include_registered_label and "-" in first_label else ""
    searchable_parts = [part for part in (subdomain, label_part, unquote(path)) if part]
    normalized_parts = [_homoglyph_normalize(part.lower()) for part in searchable_parts]
    compact_parts = [_compact(part) for part in searchable_parts]
    for key, brand in BRANDS.items():
        for alias in brand["aliases"]:
            normalized_alias = _homoglyph_normalize(alias.lower())
            compact_alias = _compact(alias)
            if any(
                re.search(rf"(?<![a-z0-9]){re.escape(normalized_alias)}(?![a-z0-9])", part)
                for part in normalized_parts
            ) or (len(compact_alias) >= 3 and any(compact_alias in part for part in compact_parts)):
                return key
    return None


def analyze_url(url: str) -> UrlAnalysis:
    """Analyze one URL without making any network requests."""

    original = url.strip()
    normalized = original if re.match(r"^[a-z][a-z0-9+.-]*://", original, re.I) else f"http://{original}"
    parsed = urlsplit(normalized)
    raw_host = (parsed.hostname or "").rstrip(".")
    ascii_host = _ascii_host(raw_host)
    registered_domain, subdomain, suffix = _registered_domain(ascii_host)
    first_label = registered_domain.split(".", 1)[0]
    path_and_query = unquote(f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path)
    evidence: list[Evidence] = []
    allowlisted = registered_domain in SAFE_DOMAINS
    institutional = suffix in _INSTITUTIONAL_SUFFIXES
    institution_brand = _exact_brand_key(first_label) if institutional else None

    if "xn--" in ascii_host or any(ord(char) > 127 for char in raw_host):
        decoded = _display_host(ascii_host)
        evidence.append(_evidence(
            "url.punycode", 0.8,
            f"The address uses look-alike foreign characters (`{decoded}`) to imitate a real site.",
            floor=0.80, decoded=decoded,
        ))

    try:
        ipaddress.ip_address(raw_host.strip("[]"))
    except ValueError:
        pass
    else:
        evidence.append(_evidence(
            "url.ip_host", 0.7,
            "The link points to a raw IP address instead of a company website.",
            floor=0.80, host=raw_host,
        ))

    if not allowlisted:
        lookalike = _find_lookalike(first_label)
        # Hyphen tokens are still the registered label. Colleges keep that label;
        # misspellings such as amzon-support are checked only off institutional suffixes.
        if not lookalike and "-" in first_label and not institutional:
            for token in first_label.split("-"):
                if len(token) >= 4:
                    hit = _find_lookalike(token)
                    if hit and token.lower() not in _brand_targets(BRANDS[hit[0]]):
                        lookalike = hit
                        break
        if lookalike:
            brand_key, legit = lookalike
            brand_name = BRANDS[brand_key]["name"]
            exact_label = first_label.lower() in _brand_targets(BRANDS[brand_key])
            if exact_label:
                # Exact brand name on another ending (amazon.net, onlinesbi.edu): brands often own these
                # defensively, so this is only a weak hint — risky TLDs and models add the rest.
                evidence.append(_evidence(
                    "url.brand_tld_swap", 0.3,
                    f"`{registered_domain}` uses the {brand_name} name, but {brand_name}'s main site is {legit} — check it's official.",
                    domain=registered_domain, brand=brand_key, legit=legit,
                ))
            elif not institutional:
                evidence.append(_evidence(
                    "url.lookalike", 0.85,
                    f"`{registered_domain}` imitates **{brand_name}** but is not {brand_name}'s real domain ({legit}).",
                    floor=0.80, domain=registered_domain, brand=brand_key, legit=legit,
                ))

        mentioned_brand = _find_brand_in_untrusted_location(
            subdomain, first_label, parsed.path, include_registered_label=not institutional,
        )
        # A college's own name in a subdomain is the institution, not a spoof of it.
        if mentioned_brand and mentioned_brand == institution_brand:
            mentioned_brand = None
        if mentioned_brand:
            brand_name = BRANDS[mentioned_brand]["name"]
            evidence.append(_evidence(
                "url.brand_in_sub", 0.75,
                f"The link puts '{brand_name}' in front of an unrelated site (`{registered_domain}`).",
                floor=0.75, domain=registered_domain, brand=mentioned_brand,
            ))

    if "@" in parsed.netloc:
        evidence.append(_evidence(
            "url.at_symbol", 0.6,
            "The link hides its real destination after an '@' sign.",
            floor=0.70, authority=parsed.netloc,
        ))

    if suffix in _INSTITUTIONAL_SUFFIXES:
        evidence.append(_evidence(
            "url.institutional", -0.3,
            f"This is a registered educational/government domain (.{suffix}).",
            suffix=suffix,
        ))

    if suffix in _RISKY_TLDS:
        evidence.append(_evidence(
            "url.risky_tld", 0.35,
            f"The site uses a `.{suffix}` domain, common in scams.", tld=suffix,
        ))

    if registered_domain in _SHORTENERS:
        evidence.append(_evidence(
            "url.shortener", 0.3,
            "The link is shortened, hiding where it really goes.", domain=registered_domain,
        ))

    if _is_free_host(ascii_host, parsed.path):
        evidence.append(_evidence(
            "url.free_host", 0.35,
            "The page is hosted on a free website builder, often used for fake login pages.",
            host=ascii_host,
        ))

    if parsed.scheme.lower() == "http":
        evidence.append(_evidence(
            "url.no_tls", 0.2, "The link is not secure (no HTTPS).", scheme="http",
        ))

    subdomain_labels = [label for label in subdomain.split(".") if label]
    if len(subdomain_labels) >= 4:
        evidence.append(_evidence(
            "url.many_subdomains", 0.3,
            "The address has an unusually long chain of sub-domains.",
            count=len(subdomain_labels),
        ))

    if len(original) > 100:
        evidence.append(_evidence("url.long", 0.15, "", length=len(original)))

    entropy = _shannon_entropy(ascii_host)
    digits_ratio = sum(char.isdigit() for char in ascii_host) / max(len(ascii_host), 1)
    if entropy > 4.0 or digits_ratio > 0.3:
        evidence.append(_evidence(
            "url.entropy", 0.3, "The address looks randomly generated.",
            entropy=round(entropy, 3), digits_ratio=round(digits_ratio, 3),
        ))

    sensitive_haystack = f"{ascii_host} {path_and_query}".lower()
    sensitive_word = next((word for word in _SENSITIVE_WORDS if word in sensitive_haystack), None)
    if sensitive_word:
        evidence.append(_evidence(
            "url.sensitive_words", 0.25,
            f"The link uses words like '{sensitive_word}' to look official.", word=sensitive_word,
        ))

    if re.search(r"\.(?:apk|exe|scr)$", parsed.path, re.I):
        evidence.append(_evidence(
            "url.apk", 0.8,
            "The link downloads an app/program file — a common way to install malware.",
            floor=0.85, path=parsed.path,
        ))

    if allowlisted:
        evidence.append(_evidence(
            "url.allowlisted", -0.5,
            f"The link goes to the official `{registered_domain}` site.",
            domain=registered_domain,
        ))

    positive_weights = [item.weight for item in evidence if item.weight > 0]
    negative_weights = [item.weight for item in evidence if item.weight < 0]
    positive_score = 1.0 - math.prod(1.0 - weight for weight in positive_weights)
    rules_score = max(0.0, min(1.0, positive_score - 0.5 * sum(abs(weight) for weight in negative_weights)))

    return UrlAnalysis(
        url=original,
        normalized=normalized,
        host=ascii_host,
        registered_domain=registered_domain,
        evidence=evidence,
        rules_score=rules_score,
    )


def extract_urls(text: str) -> list[str]:
    """Extract supported web URL forms, de-duplicating in encounter order."""

    found: list[str] = []
    seen: set[str] = set()
    for match in _URL_RE.finditer(text):
        candidate = match.group(0).rstrip(_TRAILING_PUNCTUATION)
        if candidate and candidate not in seen:
            seen.add(candidate)
            found.append(candidate)
    return found
