"""Regression tests for raw-email parsing and Tier-0 email checks."""

from app.parsers.email import parse_raw_email, parse_simple_email
from app.tier0.header_analyzer import analyze_email


PHISHING_EMAIL = """From: HDFC Bank <alerts@hdfc-secure.top>
Reply-To: support.hdfc@gmail.com
Return-Path: <bounce@hdfc-secure.top>
Subject: Verify your account
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8
Authentication-Results: mx.example; spf=fail smtp.mailfrom=hdfc-secure.top;
 dkim=none header.d=hdfc-secure.top; dmarc=fail header.from=hdfc-secure.top

<html><body><p>Verify now.</p>
<a href="https://hdfc-secure.top/login">www.hdfcbank.com</a>
</body></html>
"""

LEGIT_EMAIL = """From: ICICI Bank <alerts@icicibank.com>
Reply-To: alerts@icicibank.com
Return-Path: <bounce@icicibank.com>
Subject: Monthly account statement
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.example; spf=pass smtp.mailfrom=icicibank.com;
 dkim=pass header.d=icicibank.com; dmarc=pass header.from=icicibank.com

Your monthly statement is ready in the ICICI Bank app.
"""


def test_spoofed_brand_auth_and_visible_link_mismatch() -> None:
    env = parse_raw_email(PHISHING_EMAIL)
    evidence = analyze_email(env)
    by_id = {item.id: item for item in evidence}

    assert env.headers_available is True
    assert env.text == "Verify now. www.hdfcbank.com"
    assert by_id["hdr.brand_spoof_auth"].floor == 0.85
    assert "hdr.brand_spoof" not in by_id
    assert "hdr.spf_fail" in by_id
    assert "hdr.dkim_fail" in by_id
    assert "hdr.replyto_mismatch" in by_id
    assert "link.text_mismatch" in by_id


def test_legitimate_authenticated_brand_has_no_positive_header_signal() -> None:
    env = parse_raw_email(LEGIT_EMAIL)
    evidence = analyze_email(env)
    positive_header_ids = {
        item.id for item in evidence if item.id.startswith("hdr.") and item.weight > 0
    }
    assert not positive_header_ids
    assert "hdr.auth_pass" in {item.id for item in evidence}


def test_header_checks_are_skipped_for_simple_email_but_links_are_checked() -> None:
    env = parse_simple_email(
        "HDFC Bank <alerts@example.com>",
        "Account notice",
        '<p>Open <a href="https://evil.top/login">www.hdfcbank.com</a></p>',
    )
    evidence = analyze_email(env)
    assert env.headers_available is False
    assert not any(item.id.startswith("hdr.") for item in evidence)
    assert "link.text_mismatch" in {item.id for item in evidence}


def test_raw_email_prefers_plain_text_but_keeps_html_links_and_attachments() -> None:
    raw = """From: sender@example.com
Subject: Multipart
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=outer

--outer
Content-Type: multipart/alternative; boundary=inner

--inner
Content-Type: text/plain; charset=utf-8

Plain version https://example.com/help
--inner
Content-Type: text/html; charset=utf-8

<p>HTML version <a href="https://example.net/help">example.net</a></p>
--inner--
--outer
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.pdf.exe"

payload
--outer--
"""
    env = parse_raw_email(raw)
    assert env.text == "Plain version https://example.com/help"
    assert env.urls == ["https://example.net/help", "https://example.com/help"]
    assert env.attachments == ["invoice.pdf.exe"]
    ids = {item.id for item in analyze_email(env)}
    assert {"att.double_ext", "att.risky"} <= ids
