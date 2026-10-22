"""Caller-ID rules and the call-analysis API."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.engine.fusion import rules_score
from app.tier0.phone_rules import analyze_number, normalize


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("9876543210", "+919876543210"),
        ("09876543210", "+919876543210"),
        ("+91 98765 43210", "+919876543210"),
        ("+91-98765-43210", "+919876543210"),
        ("0091 98765 43210", "+919876543210"),
        ("00919876543210", "+919876543210"),
        ("", ""),
        ("   ", ""),
        ("Unknown", ""),
        ("unknown", ""),
        ("private", ""),
        ("Hidden", ""),
        ("No Caller ID", ""),
        ("+92 300 1234567", "+923001234567"),
        ("00923001234567", "+923001234567"),
    ],
)
def test_normalize_indian_and_hidden_forms(raw: str, expected: str) -> None:
    assert normalize(raw) == expected


def test_pakistan_call_has_scam_floor() -> None:
    evidence, info = analyze_number("+92 300 1234567")
    risky = next(item for item in evidence if item.id == "call.intl_risky")
    assert info == {"e164": "+923001234567", "country": "Pakistan", "type": "international"}
    assert risky.weight == pytest.approx(0.6)
    assert risky.floor == pytest.approx(0.70)
    assert risky.reason == (
        "Call from Pakistan (+92) — international calls pretending to be Indian banks, "
        "police or courier companies are a common scam."
    )
    assert max(rules_score(evidence), risky.floor or 0) >= 0.70


def test_uk_mobile_is_risky_and_uk_landline_is_not() -> None:
    mobile, _ = analyze_number("+44 7700 900123")
    landline, info = analyze_number("+44 20 7946 0958")
    assert any(item.id == "call.intl_risky" and item.floor == pytest.approx(0.70) for item in mobile)
    assert all(item.id != "call.intl_risky" for item in landline)
    assert any(item.id == "call.intl" and item.weight == pytest.approx(0.25) for item in landline)
    assert info["country"] == "United Kingdom"


def test_nepal_is_not_a_risky_prefix() -> None:
    evidence, info = analyze_number("+977 9801234567")
    assert info["country"] == "Nepal"
    assert [item.id for item in evidence] == ["call.intl"]
    assert evidence[0].weight == pytest.approx(0.25)
    assert evidence[0].floor is None


def test_non_nanp_plus_one_is_risky() -> None:
    spoof, _ = analyze_number("+1 123 555 0100")
    real, _ = analyze_number("+1 202 555 0147")
    assert any(item.id == "call.intl_risky" for item in spoof)
    assert all(item.id != "call.intl_risky" for item in real)
    assert any(item.id == "call.intl" for item in real)


def test_hidden_caller_is_suspicious_weight() -> None:
    evidence, info = analyze_number("Unknown")
    assert info == {"e164": "", "country": None, "type": "hidden"}
    assert len(evidence) == 1
    assert evidence[0].id == "call.hidden"
    assert evidence[0].weight == pytest.approx(0.35)
    assert evidence[0].reason == "The caller's number is hidden."
    assert rules_score(evidence) == pytest.approx(0.35)
    assert evidence[0].source == "rule"


def test_indian_mobile_has_no_positive_evidence() -> None:
    evidence, info = analyze_number("9876543210")
    assert info == {"e164": "+919876543210", "country": "India", "type": "mobile"}
    assert evidence == []
    assert rules_score(evidence) == 0


def test_tollfree_helpline_is_negative() -> None:
    evidence, info = analyze_number("1800 180 1234")
    assert info["country"] == "India"
    assert info["type"] == "tollfree"
    assert info["e164"] == "+9118001801234"
    assert len(evidence) == 1
    assert evidence[0].id == "call.safe_bank"
    assert evidence[0].weight == pytest.approx(-0.4)
    assert evidence[0].reason == "This is an official toll-free helpline number."
    assert rules_score(evidence) == 0


@pytest.mark.parametrize("number", ["1860 123 4567", "1930", "155260"])
def test_other_official_numbers_are_helplines(number: str) -> None:
    evidence, info = analyze_number(number)
    assert info["country"] == "India"
    assert any(item.id == "call.safe_bank" and item.weight < 0 for item in evidence)


def test_telemarketer_140_is_low_weight() -> None:
    evidence, info = analyze_number("1401234567")
    assert info == {"e164": "+911401234567", "country": "India", "type": "telemarketer"}
    assert len(evidence) == 1
    assert evidence[0].id == "call.telemarketer"
    assert evidence[0].weight == pytest.approx(0.2)
    assert evidence[0].floor is None
    assert evidence[0].reason == "This is a registered telemarketing number (140 series)."
    assert rules_score(evidence) == pytest.approx(0.2)
    assert rules_score(evidence) < 0.35


def test_bad_length_is_spoof_format() -> None:
    short, _ = analyze_number("+91 98765")
    tiny, _ = analyze_number("12345")
    assert short[0].id == "call.spoof_format"
    assert short[0].weight == pytest.approx(0.4)
    assert tiny[0].id == "call.spoof_format"
    assert tiny[0].weight == pytest.approx(0.4)


def test_reported_weight_and_floor() -> None:
    once, _ = analyze_number("+919876543210", reports=1)
    thrice, _ = analyze_number("9876543210", 3)
    many, _ = analyze_number("9876543210", reports=8)
    assert once[0].id == "call.reported"
    assert once[0].weight == pytest.approx(0.6)
    assert once[0].floor is None
    assert once[0].reason == "Reported as a scam by 1 ScamShield user."
    assert thrice[0].weight == pytest.approx(0.8)
    assert thrice[0].floor == pytest.approx(0.75)
    assert thrice[0].reason == "Reported as a scam by 3 ScamShield users."
    assert many[0].weight == pytest.approx(0.95)


def test_report_then_analyze_increases_risk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECISION_ENABLED", "false")
    monkeypatch.setenv("OPENAI_API_KEY", "")
    monkeypatch.setattr(settings, "db_path", tmp_path / "calls.db")
    monkeypatch.setattr(settings, "decision_enabled", False)
    monkeypatch.setattr(settings, "openai_api_key", None)
    monkeypatch.setattr(settings, "thresh_scam", 0.70)
    monkeypatch.setattr(settings, "thresh_suspicious", 0.35)

    from app.tier0.local_model import LocalScores, local_models

    monkeypatch.setattr(local_models, "load", lambda: None)

    def fake_score(env: object) -> LocalScores:
        return LocalScores(p_local=0.01, per_model={}, url_scores={}, latency_ms=0.0)

    monkeypatch.setattr(local_models, "score", fake_score)

    from app.main import app

    keys = {
        "verdict", "risk", "number", "country", "number_type", "reports",
        "reasons", "action", "category", "scan_id", "evidence",
    }
    with TestClient(app) as client:
        before = client.post("/api/analyze/call", json={"number": "9876543210", "transcript": None, "name": None})
        assert before.status_code == 200
        clean = before.json()
        assert set(clean) == keys
        assert clean["verdict"] == "SAFE"
        assert clean["risk"] == 0
        assert clean["reports"] == 0
        assert clean["number"] == "+919876543210"
        assert clean["scan_id"] is None
        assert clean["action"] == "No scam signs for this number. Still, never share OTP or PIN on calls."

        hidden = client.post("/api/analyze/call", json={"number": "Unknown"}).json()
        assert hidden["verdict"] == "SUSPICIOUS"
        assert hidden["risk"] == pytest.approx(0.35)
        assert hidden["number_type"] == "hidden"
        assert hidden["reasons"] == ["The caller's number is hidden."]

        pakistan = client.post("/api/analyze/call", json={"number": "+92 300 1234567"}).json()
        assert pakistan["verdict"] == "SCAM"
        assert pakistan["risk"] >= 0.70
        assert pakistan["country"] == "Pakistan"
        assert pakistan["category"] == "other_scam"
        assert pakistan["action"].startswith("Don't share OTP")
        assert pakistan["scan_id"] is None

        for expected in (1, 2, 3):
            reported = client.post("/api/report/number", json={"number": "09876543210", "note": "asked for an OTP"})
            assert reported.status_code == 200
            assert reported.json() == {"number": "+919876543210", "reports": expected}

        after = client.post("/api/analyze/call", json={"number": "+91 98765 43210"}).json()
        assert set(after) == keys
        assert after["reports"] == 3
        assert after["risk"] > clean["risk"]
        assert after["risk"] >= 0.75
        assert after["verdict"] == "SCAM"
        assert any(item["id"] == "call.reported" for item in after["evidence"])
        assert any("3 ScamShield users" in reason for reason in after["reasons"])

        transcript = "HDFC Bank: share the OTP 829104 at https://hdfc-verify.top now."
        spoken = client.post(
            "/api/analyze/call",
            json={"number": "9123456789", "transcript": transcript, "name": "HDFC"},
        ).json()
        assert spoken["verdict"] == "SCAM"
        assert spoken["risk"] >= 0.70
        assert spoken["scan_id"]
        assert spoken["category"] == "otp_theft"
        assert spoken["action"] == (
            "Don't share OTP, PIN or card details. Hang up and call the bank/agency on its official number. Report on 1930."
        )

        refused = client.post("/api/report/number", json={"number": "Unknown"})
        assert refused.status_code == 422
