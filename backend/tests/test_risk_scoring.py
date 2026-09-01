"""Unit tests for composite risk scoring engine."""

from __future__ import annotations

from app.ml.risk_scoring import compute_risk


def test_safe_email_risk_score():
    parsed = {
        "authentication": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "domain_mismatches": {"reply_to_mismatch": False, "return_path_mismatch": False},
        "suspicious_attachments": [],
        "reply_to_domain": "acme.com",
        "sender_domain": "acme.com",
        "return_path_domain": "acme.com",
    }
    ml_result = {"phishing_probability": 0.05, "ml_label": "legitimate"}

    result = compute_risk(parsed, ml_result)
    assert result["risk_score"] < 35
    assert result["verdict"] == "Safe"
    assert result["ml_phishing_probability"] == 0.05
    assert len(result["indicators"]) == 0


def test_suspicious_email_risk_score():
    # Moderate ML (0.6 * 50 = 30) + Reply-to mismatch (+10) = 40 (Suspicious)
    parsed = {
        "authentication": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "domain_mismatches": {"reply_to_mismatch": True, "return_path_mismatch": False},
        "suspicious_attachments": [],
        "reply_to_domain": "scam.com",
        "sender_domain": "acme.com",
        "return_path_domain": "acme.com",
    }
    ml_result = {"phishing_probability": 0.60, "ml_label": "phishing"}

    result = compute_risk(parsed, ml_result)
    assert 35 <= result["risk_score"] < 70
    assert result["verdict"] == "Suspicious"
    assert any("Reply-To domain" in ind for ind in result["indicators"])


def test_phishing_email_risk_score_and_capping():
    # High ML (1.0 * 50 = 50) + SPF softfail (+15) + DKIM fail (+15) + DMARC fail (+10) + Reply-To (+10) + Return-Path (+5) + Attachment (+15) = 120 -> capped at 100
    parsed = {
        "authentication": {"spf": "softfail", "dkim": "fail", "dmarc": "fail"},
        "domain_mismatches": {"reply_to_mismatch": True, "return_path_mismatch": True},
        "suspicious_attachments": ["malware.exe"],
        "reply_to_domain": "attacker.com",
        "sender_domain": "paypal.com",
        "return_path_domain": "vps.com",
    }
    ml_result = {"phishing_probability": 0.98, "ml_label": "phishing"}

    result = compute_risk(parsed, ml_result)
    assert result["risk_score"] == 100
    assert result["verdict"] == "Phishing/Scam"
    assert len(result["indicators"]) >= 6
    assert any("SPF authentication failed" in ind for ind in result["indicators"])
    assert any("DKIM authentication failed" in ind for ind in result["indicators"])
    assert any("DMARC authentication failed" in ind for ind in result["indicators"])
    assert any("malware.exe" in ind for ind in result["indicators"])


def test_threat_intel_malicious_ip_and_domain_penalty():
    parsed = {
        "authentication": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "domain_mismatches": {"reply_to_mismatch": False, "return_path_mismatch": False},
        "suspicious_attachments": [],
    }
    ml_result = {"phishing_probability": 0.10, "ml_label": "legitimate"}
    threat_intel = {
        "originating_ip_reputation": {"reputation": "malicious", "malicious": 12},
        "domain_reputations": {
            "phish-site.org": {"reputation": "malicious", "malicious": 8}
        },
    }

    # ML: 5 pts + Malicious IP: +20 pts + Malicious Domain: +20 pts = 45 pts (Suspicious)
    result = compute_risk(parsed, ml_result, threat_intel=threat_intel)
    assert result["risk_score"] == 45
    assert result["verdict"] == "Suspicious"
    assert any("Sending IP flagged malicious on VirusTotal (12" in ind for ind in result["indicators"])
    assert any("Domain 'phish-site.org' flagged malicious on VirusTotal (8" in ind for ind in result["indicators"])
