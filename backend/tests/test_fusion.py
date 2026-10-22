import math

import pytest

from app.engine.fusion import fuse, logit, rules_score, sigmoid
from app.schemas import Evidence


def evidence(
    evidence_id: str,
    weight: float,
    *,
    source: str = "rule",
    floor: float | None = None,
) -> Evidence:
    return Evidence(
        id=evidence_id,
        source=source,
        weight=weight,
        floor=floor,
        reason=evidence_id,
    )


@pytest.fixture(autouse=True)
def documented_fusion_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep these unit tests independent of values in a developer's backend/.env."""
    from app.engine import fusion

    values = {
        "w_jev": 0.50,
        "w_local": 0.30,
        "w_rules": 0.20,
        "w_local_offline": 0.65,
        "w_rules_offline": 0.35,
        "thresh_scam": 0.70,
        "thresh_suspicious": 0.35,
        "disagree_llm": 0.50,
    }
    for name, value in values.items():
        monkeypatch.setattr(fusion.settings, name, value)


def test_rules_score_uses_noisy_or_and_subtracts_half_negative_weights() -> None:
    items = [
        evidence("rule.one", 0.50),
        evidence("rule.two", 0.40),
        evidence("rule.reassuring", -0.20),
        evidence("model.ignored", 1.0, source="model"),
    ]

    # Positive noisy-OR: 1 - (1 - .5) * (1 - .4) = .7; reassurance: .2 / 2 = .1.
    assert rules_score(items) == pytest.approx(0.60)


def test_rules_score_is_clamped_after_strong_negative_evidence() -> None:
    assert rules_score([evidence("rule.reassuring", -1.0)]) == 0.0


def test_fuse_online_uses_jev_local_and_rule_weights() -> None:
    items = [evidence("rule.signal", 0.40)]

    result = fuse(items, p_local=0.60, p_jev=0.80)

    expected = sigmoid(0.50 * logit(0.80) + 0.30 * logit(0.60) + 0.20 * logit(0.40))
    assert result.risk == pytest.approx(expected, abs=5e-5)
    assert result.scores == {
        "p_jev": 0.80,
        "p_local": 0.60,
        "rules": 0.40,
        "url": None,
    }


def test_fuse_offline_uses_local_and_rule_weights() -> None:
    items = [evidence("rule.signal", 0.40)]

    result = fuse(items, p_local=0.60, p_jev=None)

    expected = sigmoid(0.65 * logit(0.60) + 0.35 * logit(0.40))
    assert result.risk == pytest.approx(expected, abs=5e-5)
    assert result.scores["p_jev"] is None


def test_fuse_rules_only_uses_the_rule_probability() -> None:
    result = fuse([evidence("rule.signal", 0.40)], p_local=None, p_jev=None)

    assert result.risk == pytest.approx(0.40)
    assert result.decided_by == "rules"


@pytest.mark.parametrize(
    ("risk", "expected_verdict"),
    [
        (0.70, "SCAM"),
        (0.699, "SUSPICIOUS"),
        (0.35, "SUSPICIOUS"),
        (0.349, "SAFE"),
    ],
)
def test_verdict_thresholds(risk: float, expected_verdict: str) -> None:
    result = fuse([evidence("rule.signal", risk)], p_local=None, p_jev=None)

    assert result.verdict == expected_verdict


def test_rule_floor_raises_risk_and_records_the_decider() -> None:
    items = [evidence("rule.hard", 0.10, floor=0.80)]

    result = fuse(items, p_local=0.10, p_jev=0.10)

    assert result.risk == 0.80
    assert result.verdict == "SCAM"
    assert result.decided_by == "rule_floor"


def test_url_risk_raises_risk_and_records_the_decider() -> None:
    result = fuse([], p_local=0.10, p_jev=None, url_risk=0.82)

    assert result.risk == 0.82
    assert result.verdict == "SCAM"
    assert result.decided_by == "url"
    assert result.scores["url"] == 0.82


def test_suspicious_verdict_needs_llm() -> None:
    result = fuse([evidence("rule.signal", 0.50)], p_local=None, p_jev=None)

    assert result.verdict == "SUSPICIOUS"
    assert result.needs_llm is True


def test_strong_jev_local_disagreement_needs_llm_even_for_scam() -> None:
    items = [evidence("rule.strong", 0.99)]

    result = fuse(items, p_local=0.40, p_jev=1.0)

    assert result.verdict == "SCAM"
    assert abs(1.0 - 0.40) > 0.50
    assert result.needs_llm is True


def test_rule_floor_suppresses_llm_despite_strong_disagreement() -> None:
    items = [evidence("rule.hard", 0.10, floor=0.99)]

    result = fuse(items, p_local=0.10, p_jev=0.90)

    assert result.decided_by == "rule_floor"
    assert result.needs_llm is False


@pytest.mark.parametrize(
    ("items", "p_local", "p_jev", "url_risk"),
    [
        ([], 0.0, 1.0, None),
        ([evidence("rule.certain", 1.0)], 1.0, None, None),
        ([], 0.0, None, 0.0),
        ([evidence("rule.mid", 0.52)], None, None, None),
    ],
)
def test_confidence_is_always_bounded(
    items: list[Evidence],
    p_local: float | None,
    p_jev: float | None,
    url_risk: float | None,
) -> None:
    result = fuse(items, p_local=p_local, p_jev=p_jev, url_risk=url_risk)

    assert 0.0 <= result.confidence <= 1.0


@pytest.mark.parametrize(
    ("p_local", "p_jev"),
    [(0.0, 0.0), (1.0, 1.0), (0.0, 1.0), (1.0, 0.0)],
)
def test_extreme_probabilities_are_clipped_and_do_not_crash(
    p_local: float,
    p_jev: float,
) -> None:
    result = fuse([], p_local=p_local, p_jev=p_jev)

    assert math.isfinite(result.risk)
    assert 0.0 <= result.risk <= 1.0

