"""Regression tests for the Tier-0 URL analyzer."""

import pytest

from app.tier0.url_analyzer import analyze_url, extract_urls


PHISHING_URLS = [
    "http://sbi-kyc-update.xyz/login",
    "https://hdfc-secure-verify.top/netbanking",
    "https://xn--phonpe-0ra.com/login",
    "http://192.168.43.12/icici/login.php",
    "https://www.amaz0n-in.com/gift-card/claim",
    "https://sbi.co.in.verify-account.online/yono",
    "http://axis-rewards.in.net/AxisReward.apk",
    "http://paytm-kyc.web.app/verify",
    "https://uidai-aadhaar-update.cfd/verify",
]

LEGIT_URLS = [
    "https://www.onlinesbi.sbi/",
    "https://www.hdfcbank.com/personal/pay/cards",
    "https://www.amazon.in/gp/your-account/order-history",
    "https://www.flipkart.com/account/orders",
    "https://www.incometax.gov.in/iec/foportal/",
    "https://uidai.gov.in/en/my-aadhaar.html",
    "https://github.com/huggingface/transformers",
    "https://docs.python.org/3/library/asyncio.html",
    "https://mail.google.com/mail/u/0/#inbox",
]


@pytest.mark.parametrize("url", PHISHING_URLS)
def test_phishing_urls_are_high_risk(url: str) -> None:
    result = analyze_url(url)
    floors = [item.floor for item in result.evidence if item.floor is not None]
    assert result.rules_score >= 0.5 or any(floor >= 0.7 for floor in floors), (
        url,
        result.model_dump(),
    )


@pytest.mark.parametrize("url", LEGIT_URLS)
def test_legitimate_urls_are_low_risk(url: str) -> None:
    result = analyze_url(url)
    assert result.rules_score < 0.35, (url, result.model_dump())
    assert not any(item.floor is not None for item in result.evidence), (
        url,
        result.model_dump(),
    )
    assert "url.allowlisted" in {item.id for item in result.evidence}


def test_url_without_scheme_is_normalized() -> None:
    result = analyze_url("bit.ly/abc")
    assert result.normalized == "http://bit.ly/abc"
    assert result.registered_domain == "bit.ly"
    assert "url.shortener" in {item.id for item in result.evidence}


def test_extract_urls_supported_forms_and_deduplication() -> None:
    text = (
        "Open https://example.com/login, then www.flipkart.com/account/orders. "
        "Backup: bit.ly/abc. Duplicate https://example.com/login! "
        "Message us at wa.me/919999999999)."
    )
    assert extract_urls(text) == [
        "https://example.com/login",
        "www.flipkart.com/account/orders",
        "bit.ly/abc",
        "wa.me/919999999999",
    ]


def test_extract_urls_ignores_email_domain_and_plain_words() -> None:
    text = "Email help@example.com; this sentence has no link, but docs.python.org/3/ does."
    assert extract_urls(text) == ["docs.python.org/3/"]
