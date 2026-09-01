"""Unit tests for the email_parser module."""

from __future__ import annotations

from pathlib import Path
from app.parsing.email_parser import parse_email

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_parse_benign_email():
    eml_bytes = (FIXTURES_DIR / "sample_benign.eml").read_bytes()
    result = parse_email(eml_bytes)

    assert result["subject"] == "Your Monthly Acme Statement"
    assert "support@acme-corp.com" in result["sender"]
    assert result["sender_domain"] == "acme-corp.com"
    assert result["reply_to_domain"] == "acme-corp.com"
    assert result["return_path_domain"] == "acme-corp.com"
    assert "user@example.com" in result["to"]
    assert "Valued Customer" in result["to"]
    assert result["message_id"] == "<20260831041520.12345.support@acme-corp.com>"

    # Check alignment
    assert result["domain_mismatches"]["reply_to_mismatch"] is False
    assert result["domain_mismatches"]["return_path_mismatch"] is False

    # Check body & URLs
    assert "Hello Customer" in result["body_text"]
    assert "https://portal.acme-corp.com/statements/2026-08" in result["urls"]
    assert "https://help.acme-corp.com/faq" in result["urls"]
    assert "portal.acme-corp.com" in result["domains"]
    assert "help.acme-corp.com" in result["domains"]

    # Check attachments
    assert "statement_aug2026.pdf" in result["attachments"]
    assert len(result["suspicious_attachments"]) == 0

    # Check authentication
    assert result["authentication"]["spf"] == "pass"
    assert result["authentication"]["dkim"] == "pass"
    assert result["authentication"]["dmarc"] == "pass"

    # Check email hash
    assert len(result["email_hash"]) == 64


def test_parse_phishing_email():
    eml_bytes = (FIXTURES_DIR / "sample_phish.eml").read_bytes()
    result = parse_email(eml_bytes)

    assert "Unauthorized login" in result["subject"]
    assert result["sender_domain"] == "security-paypa1.com"
    assert result["reply_to_domain"] == "gmail.com"
    assert result["return_path_domain"] == "compromised-vps.net"

    # Check alignment mismatches detected
    assert result["domain_mismatches"]["reply_to_mismatch"] is True
    assert result["domain_mismatches"]["return_path_mismatch"] is True

    # Check HTML body tag stripping
    assert "Dear PayPal Customer" in result["body_text"]
    assert "<html>" not in result["body_text"]

    # Check URLs and domains
    assert any("paypa1-security-verify.com" in u for u in result["urls"])
    assert "paypa1-security-verify.com" in result["domains"]

    # Check suspicious attachments
    assert "paypal_security_fix.scr" in result["attachments"]
    assert "paypal_security_fix.scr" in result["suspicious_attachments"]

    # Check authentication failures
    assert result["authentication"]["spf"] == "softfail"
    assert result["authentication"]["dkim"] == "fail"
    assert result["authentication"]["dmarc"] == "fail"


def test_plain_text_truncated_at_8000_chars():
    long_text = "A" * 10000
    raw_email = f"From: a@test.com\nTo: b@test.com\nSubject: Long\n\n{long_text}".encode("utf-8")
    result = parse_email(raw_email)
    assert len(result["body_text"]) == 8000
