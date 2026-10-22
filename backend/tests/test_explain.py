import pytest

from app.engine.explain import ACTIONS, explain
from app.schemas import Evidence


def evidence(
    evidence_id: str,
    weight: float,
    reason: str,
    *,
    source: str = "rule",
    floor: float | None = None,
    detail: dict | None = None,
) -> Evidence:
    return Evidence(
        id=evidence_id,
        source=source,
        weight=weight,
        floor=floor,
        reason=reason,
        detail=detail or {},
    )


def test_safe_uses_negative_weight_evidence_ordered_most_reassuring_first() -> None:
    items = [
        evidence("hdr.auth", -0.40, "Authentication passed."),
        evidence("txt.neutral", 0.60, "This positive-risk reason is not shown."),
        evidence("sender.known", -0.80, "The sender is known."),
    ]

    reasons, action = explain(items, "SAFE", category=None)

    assert reasons == ["The sender is known.", "Authentication passed."]
    assert action == ACTIONS["SAFE"]["_default"]


def test_safe_falls_back_when_there_is_no_negative_reason() -> None:
    items = [
        evidence("rule.positive", 0.90, "A scam signal."),
        evidence("rule.empty", -0.80, ""),
    ]

    reasons, _ = explain(items, "SAFE", category=None)

    assert reasons == ["No links, sender tricks or scam language were found."]


def test_scam_ranks_floor_evidence_before_higher_weight_non_floor_evidence() -> None:
    items = [
        evidence("txt.urgent", 0.99, "Urgent wording was found."),
        evidence("txt.otp", 0.30, "An OTP was requested.", floor=0.90),
    ]

    reasons, _ = explain(items, "SCAM", category=None)

    assert reasons == ["An OTP was requested.", "Urgent wording was found."]


def test_deduplicates_multiple_evidence_items_for_the_same_url() -> None:
    url = "https://paypa1.example/login"
    items = [
        evidence(
            "url.lookalike",
            0.90,
            "The domain imitates a known brand.",
            detail={"url": url},
        ),
        evidence(
            "url.ip_address",
            0.80,
            "The link uses a raw IP address.",
            detail={"url": url},
        ),
        evidence(
            "url.lookalike",
            0.70,
            "A different URL is also suspicious.",
            detail={"url": "https://another.example"},
        ),
    ]

    reasons, _ = explain(items, "SCAM", category=None)

    assert reasons == [
        "The domain imitates a known brand.",
        "A different URL is also suspicious.",
    ]


def test_non_safe_skips_empty_reasons_and_weights_below_point_three() -> None:
    items = [
        evidence("txt.strong", 0.30, "Included at the boundary."),
        evidence("txt.weak", 0.299, "Too weak."),
        evidence("txt.empty", 0.90, ""),
    ]

    reasons, _ = explain(items, "SUSPICIOUS", category=None)

    assert reasons == ["Included at the boundary."]


def test_reasons_are_capped_at_five() -> None:
    items = [
        evidence(f"rule.{index}", 0.90 - index / 100, f"Reason {index}")
        for index in range(7)
    ]

    reasons, _ = explain(items, "SCAM", category=None)

    assert reasons == [f"Reason {index}" for index in range(5)]


@pytest.mark.parametrize("category", ["otp_theft", "upi_trap"])
def test_scam_uses_category_specific_action(category: str) -> None:
    _, action = explain([], "SCAM", category=category)

    assert action == ACTIONS["SCAM"][category]
    assert action != ACTIONS["SCAM"]["_default"]


@pytest.mark.parametrize("category", [None, "unknown_category"])
def test_scam_uses_default_action_for_missing_or_unknown_category(category: str | None) -> None:
    _, action = explain([], "SCAM", category=category)

    assert action == ACTIONS["SCAM"]["_default"]
