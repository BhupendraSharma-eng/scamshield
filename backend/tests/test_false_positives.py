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

    assert result.verdict == "SAFE"
    assert result.decided_by == "model_cap"
    assert result.risk == pytest.approx(0.34, abs=1e-4)


@pytest.mark.parametrize('p_local', [.9, .99])
@pytest.mark.parametrize('p_tier1', [None, .1, .56])
def test_unfamiliar_login_portal_needs_corroboration_before_warning(p_local, p_tier1):
    evidence = analyze_url('https://student.example.com/login/mis').evidence
    result = fuse(evidence, p_local=p_local, p_jev=p_tier1, channel='url')
    assert result.verdict == 'SAFE'


def test_confident_decision_can_still_flag_a_clean_looking_url():
    evidence = analyze_url('https://student.example.com/login/mis').evidence
    result = fuse(evidence, p_local=.99, p_jev=.99, channel='url')
    assert result.verdict == 'SCAM'


def test_strong_phishing_indicators_still_warn_without_decision_provider():
    evidence = analyze_url('https://sbi-kyc-update.xyz/login').evidence
    assert fuse(evidence, p_local=.99, p_jev=None, channel='url').verdict == 'SCAM'


def test_full_pipeline_preserves_raw_model_score_but_explains_unconfirmed_alert(tmp_path, monkeypatch):
    import asyncio
    from app import db
    from app.config import settings
    from app.engine import pipeline
    from app.schemas import Envelope
    from app.tier0.local_model import LocalScores
    url = 'https://student.example.com/login/mis'
    monkeypatch.setattr(settings, 'db_path', tmp_path / 'unconfirmed.db')
    monkeypatch.setattr(settings, 'openai_api_key', None)
    monkeypatch.setattr(settings, 'openrouter_api_key', None)
    monkeypatch.setattr(pipeline.local_models, 'score', lambda env: LocalScores(
        p_local=.99, per_model={'urlbert': .99}, url_scores={url: .99}, latency_ms=0))
    async def unavailable(*args):
        return None
    monkeypatch.setattr(pipeline.decision_client, 'classify', unavailable)
    async def check():
        await db.init_db()
        result = await pipeline.analyze(Envelope(channel='url', urls=[url]), use_cache=False)
        assert result['verdict'] == 'SAFE'
        assert result['scores']['models']['urlbert'] == .99
        assert result['urls'][0]['risk'] < .35
        assert any('not corroborated' in reason for reason in result['reasons'])
    asyncio.run(check())
