"""Unit tests for ReportLab forensic PDF report generation."""

from __future__ import annotations

from app.reports.pdf_report import generate_report


def test_generate_report_returns_valid_pdf():
    analysis = {
        "email_hash": "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
        "subject": "Urgent Wire Transfer Request",
        "sender": "CEO Impersonator <ceo@spoofed-domain.com>",
        "sender_domain": "spoofed-domain.com",
        "reply_to": "scammer@gmail.com",
        "return_path": "bounce@compromised-server.net",
        "date": "Tue, 01 Sep 2026 09:00:00 +0000",
        "message_id": "<wire.12345@spoofed-domain.com>",
        "verdict": "Phishing/Scam",
        "risk_score": 95,
        "ml_phishing_probability": 0.982,
        "authentication": {
            "spf": "softfail",
            "dkim": "fail",
            "dmarc": "fail",
        },
        "indicators": [
            "High ML phishing probability score (98.2%)",
            "SPF authentication failed",
            "DKIM authentication failed",
            "Reply-To domain does not match sender domain",
        ],
        "hops": [
            {
                "sequence": 1,
                "from_host": "mail.attacker.com",
                "from_ip": "185.220.101.5",
                "by_host": "relay.target.com",
                "timestamp": "2026-09-01T08:59:30Z",
                "is_public_ip": True,
            },
            {
                "sequence": 2,
                "from_host": "relay.target.com",
                "from_ip": "10.0.0.5",
                "by_host": "mx.target.com",
                "timestamp": "2026-09-01T09:00:00Z",
                "is_public_ip": False,
            },
        ],
        "originating_ip": "185.220.101.5",
        "origin_geo": {
            "ip": "185.220.101.5",
            "country": "Germany",
            "country_code": "DE",
            "city": "Berlin",
            "asn_org": "Stiftung Erneuerbare Freiheit",
            "latitude": 52.52,
            "longitude": 13.405,
        },
        "threat_intel": {
            "originating_ip_reputation": {
                "available": True,
                "reputation": "malicious",
                "malicious": 14,
            },
            "domain_reputations": {
                "spoofed-domain.com": {
                    "available": True,
                    "reputation": "suspicious",
                    "malicious": 2,
                }
            },
        },
        "campaign": {
            "campaign_size": 2,
            "related_emails": [
                {
                    "id": "rel1_hash_99999999",
                    "subject": "Previous Attack Email",
                    "verdict": "Phishing/Scam",
                    "shared_via": "ip",
                    "shared_value": "185.220.101.5",
                }
            ],
        },
    }

    pdf_bytes = generate_report(analysis)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    # PDF magic header
    assert pdf_bytes.startswith(b"%PDF")
    # PDF EOF marker
    assert b"%%EOF" in pdf_bytes


def test_generate_report_minimal_empty_fields():
    """Ensure generate_report doesn't crash on bare minimum dictionary."""
    minimal_analysis = {
        "email_hash": "mini_hash_12345",
        "subject": None,
        "sender": None,
        "verdict": "Safe",
        "risk_score": 5,
        "ml_phishing_probability": 0.04,
        "authentication": {},
        "indicators": [],
        "hops": [],
        "origin_geo": None,
        "threat_intel": {},
        "campaign": {"campaign_size": 0, "related_emails": []},
    }

    pdf_bytes = generate_report(minimal_analysis)
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 500
