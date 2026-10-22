"""Offline checks for URL false positives: college domains and model-only SCAM calls."""

import pytest

from app.engine.fusion import fuse
from app.schemas import Evidence
from app.tier0.url_analyzer import analyze_url


@pytest.fixture(autouse=True)
def documented_fusion_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep verdict boundaries independent of a developer's backend/.env."""
    from app.engine import fusion

    monkeypatch.setattr(fusion.settings, "thresh_scam", 0.70)
    monkeypatch.setattr(fusion.settings, "thresh_suspicious", 0.35)


def test_rntu_is_an_institutional_domain_not_a_lookalike() -> None:
    result = analyze_url("https://rntu.ac.in/")
    ids = {item.id for item in result.evidence}

    assert "url.lookalike" not in ids
    assert "url.institutional" in ids


def test_login_portal_with_a_weak_tier1_score_is_not_scam() -> None:
    evidence = analyze_url("https://bssserp.com/login/mis").evidence

    result = fuse(evidence, p_local=0.94, p_jev=0.56, channel="url")

    assert result.verdict != "SCAM"


@pytest.mark.parametrize(
    "url",
    [
        "https://www.iitb.ac.in/",
        "https://lms.bssserp.com/login",
        "https://erp.example.edu/login/student",
    ],
)
def test_benign_login_pages_are_not_scam_offline(url: str) -> None:
    evidence = analyze_url(url).evidence

    result = fuse(evidence, p_local=0.9, p_jev=None, channel="url")

    assert result.verdict != "SCAM"


@pytest.mark.parametrize(
    "url",
    [
        "http://sbi-kyc-update.xyz/login",
        "https://www.amaz0n-in.com/gift-card/claim",
        "http://192.168.43.12/icici/login.php",
    ],
)
def test_known_phishing_urls_stay_scam(url: str) -> None:
    evidence = analyze_url(url).evidence

    result = fuse(evidence, p_local=0.95, p_jev=None, channel="url")

    assert result.verdict == "SCAM"


def test_url_model_alone_cannot_reach_scam() -> None:
    evidence = [
        Evidence(id="url.sensitive_words", source="rule", weight=0.25, reason="The link says login."),
    ]

    result = fuse(evidence, p_local=0.99, p_jev=None, channel="url")

    assert result.verdict == "SUSPICIOUS"
    assert result.decided_by == "model_cap"
    assert result.risk == pytest.approx(0.65, abs=1e-4)
