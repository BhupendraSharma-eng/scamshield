"""Regression tests for India-focused Tier-0 text rules."""

import pytest

from app.tier0.text_rules import analyze_text, rules_score


SCAM_MESSAGES = [
    "SBI customer: your KYC has expired and account will be blocked. Update at http://sbi-kyc.top/login",
    "Electricity connection will disconnect tonight. Call now on 9876543210.",
    "PhonePe cashback of Rs 500: enter UPI PIN to receive your cashback.",
    "HDFC Bank: share the OTP 829104 at https://hdfc-verify.top now.",
    "Part-time job: earn Rs 3000 daily liking YouTube videos. Complete each task.",
    "India Post: your parcel is held because address incomplete. Pay Rs 25 re-delivery fee.",
    "Mumbai Cyber Police has an arrest warrant in your name. Join our video call immediately.",
    "Aapka bank account aaj band ho jayega. Turant OTP batayein.",
    "Download Axis rewards app APK from link http://axis-rewards.top/AxisReward.apk",
]

LEGIT_MESSAGES = [
    "123456 is your HDFC OTP for card payment. Do not share OTP with anyone.",
    "SBI UPI debit alert: Rs. 725 paid to ANITA. If not you, use the YONO app.",
    "Your Flipkart order has shipped and will arrive on Tuesday.",
    "Jio recharge of Rs 299 was successful. Validity: 28 days.",
    "Can you call me after dinner? We can plan the weekend.",
    "Kal college kab aaoge? Notes bhejo yaar, exam ke liye padhna hai.",
]


@pytest.mark.parametrize("message", SCAM_MESSAGES)
def test_indian_scam_messages_score_high(message: str) -> None:
    evidence = analyze_text(message)
    assert rules_score(evidence) >= 0.5, (message, [item.model_dump() for item in evidence])


@pytest.mark.parametrize("message", LEGIT_MESSAGES)
def test_legitimate_messages_score_low(message: str) -> None:
    evidence = analyze_text(message)
    assert rules_score(evidence) < 0.35, (message, [item.model_dump() for item in evidence])


def test_legitimate_otp_warning_is_not_an_otp_request() -> None:
    evidence = analyze_text("482019 is your OTP. Never share this OTP or PIN with anyone.")
    assert "txt.asks_otp" not in {item.id for item in evidence}


def test_otp_plus_link_keeps_base_evidence_but_suppresses_duplicate_reason() -> None:
    evidence = analyze_text("Please share the OTP at https://verify.example/login")
    by_id = {item.id: item for item in evidence}
    assert by_id["txt.asks_otp"].reason == ""
    assert by_id["txt.otp_plus_link"].floor == 0.90
    assert by_id["txt.otp_plus_link"].detail["matches"] == [
        "share the OTP",
        "https://verify.example/login",
    ]


def test_otp_plus_phone_number_fires() -> None:
    evidence = analyze_text("Tell your OTP by calling 9876543210")
    assert {item.id for item in evidence} >= {"txt.asks_otp", "txt.otp_plus_link"}


def test_all_evidence_contains_quoted_matches() -> None:
    evidence = analyze_text("KYC expired. Act immediately and pay Rs 500.")
    assert evidence
    for item in evidence:
        assert item.source == "rule"
        assert item.detail["matches"]
        assert item.reason == "" or '"' in item.reason


def test_rules_score_uses_noisy_or_and_negative_subtraction() -> None:
    evidence = analyze_text("KYC expired immediately")
    assert rules_score(evidence) == pytest.approx(1 - (1 - 0.45) * (1 - 0.25))
