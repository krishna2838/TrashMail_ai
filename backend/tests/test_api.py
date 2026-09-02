"""API route tests using TestClient."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
from starlette.testclient import TestClient

from app.core.config import settings
from app.main import app

client = TestClient(app)
FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Default mocks for VT and Neo4j used across tests
_VT_CLEAN = {"available": True, "reputation": "clean", "malicious": 0}
_VT_MALICIOUS = {"available": True, "reputation": "malicious", "malicious": 10}
_CAMPAIGN_EMPTY = {"related_emails": [], "campaign_size": 0}


def _patch_vt_and_neo4j(vt_ip=_VT_CLEAN, vt_domain=_VT_CLEAN, campaign=_CAMPAIGN_EMPTY):
    """Return a list of context managers that mock VT + Neo4j for test isolation."""
    return [
        patch("app.api.routes_analyze.check_ip", return_value=vt_ip),
        patch("app.api.routes_analyze.check_domain", return_value=vt_domain),
        patch("app.api.routes_analyze.save_analysis"),
        patch("app.api.routes_analyze.find_related_emails", return_value=campaign),
    ]


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app"] == settings.APP_NAME


def test_model_info_endpoint():
    response = client.get("/api/model-info")
    assert response.status_code == 200
    data = response.json()
    assert "model" in data
    assert "metrics" in data
    assert "accuracy" in data["metrics"]
    assert "sources" in data
    assert data["metrics"]["accuracy"] > 0.95


def test_analyze_via_eml_file_upload():
    benign_path = FIXTURES_DIR / "sample_benign.eml"
    patches = _patch_vt_and_neo4j()
    with patches[0], patches[1], patches[2], patches[3]:
        with open(benign_path, "rb") as f:
            response = client.post(
                "/api/analyze",
                files={"file": ("sample_benign.eml", f, "message/rfc822")},
            )
    assert response.status_code == 200
    data = response.json()
    assert data["subject"] == "Your Monthly Acme Statement"
    assert data["sender_domain"] == "acme-corp.com"
    assert "hops" in data
    assert len(data["hops"]) == 2
    assert data["originating_ip"] == "209.85.216.41"

    # Phase 2 ML & risk fields
    assert "ml_phishing_probability" in data
    assert "risk_score" in data
    assert "verdict" in data
    assert "indicators" in data
    assert data["verdict"] == "Safe"
    assert data["risk_score"] < 35

    # Phase 3 GeoIP & Threat Intel
    assert "origin_geo" in data
    assert data["origin_geo"] is not None
    assert data["origin_geo"]["ip"] == "209.85.216.41"
    assert data["origin_geo"]["country"] == "United States"
    assert "threat_intel" in data

    # Phase 4 Campaign
    assert "campaign" in data
    assert data["campaign"]["campaign_size"] == 0


def test_analyze_via_json_payload():
    phish_path = FIXTURES_DIR / "sample_phish.eml"
    raw_text = phish_path.read_text(encoding="utf-8")
    patches = _patch_vt_and_neo4j(
        vt_ip=_VT_MALICIOUS,
        vt_domain=_VT_MALICIOUS,
    )
    with patches[0], patches[1], patches[2], patches[3]:
        response = client.post(
            "/api/analyze",
            json={"raw_email": raw_text},
        )
    assert response.status_code == 200
    data = response.json()
    assert "Unauthorized login" in data["subject"]
    assert data["sender_domain"] == "security-paypa1.com"
    assert data["domain_mismatches"]["reply_to_mismatch"] is True
    assert data["originating_ip"] == "185.220.101.5"
    assert "paypal_security_fix.scr" in data["suspicious_attachments"]

    # Phase 2 ML & risk fields
    assert data["verdict"] == "Phishing/Scam"
    assert data["risk_score"] >= 70
    assert len(data["indicators"]) > 0

    # Phase 3 GeoIP & Threat Intel
    assert data["origin_geo"]["ip"] == "185.220.101.5"
    assert data["threat_intel"]["originating_ip_reputation"]["reputation"] == "malicious"

    # Phase 4 Campaign (empty for this test — only one email analyzed)
    assert "campaign" in data
    assert data["campaign"]["campaign_size"] == 0


def test_analyze_with_campaign_match():
    """Verify campaign boost adds +15 risk and an indicator when related emails exist."""
    benign_path = FIXTURES_DIR / "sample_benign.eml"
    campaign_data = {
        "related_emails": [
            {"id": "other-hash", "subject": "Another scam", "verdict": "Phishing/Scam",
             "shared_via": "domain", "shared_value": "evil.com"}
        ],
        "campaign_size": 1,
    }
    patches = _patch_vt_and_neo4j(campaign=campaign_data)
    with patches[0], patches[1], patches[2], patches[3]:
        with open(benign_path, "rb") as f:
            response = client.post(
                "/api/analyze",
                files={"file": ("sample_benign.eml", f, "message/rfc822")},
            )
    assert response.status_code == 200
    data = response.json()
    assert data["campaign"]["campaign_size"] == 1
    assert any("part of a known campaign" in ind for ind in data["indicators"])


def test_analyze_empty_request_fails():
    response = client.post(
        "/api/analyze",
        json={"raw_email": ""},
    )
    assert response.status_code == 400


def test_analyze_exceeds_max_size(monkeypatch):
    # Temporarily set max size to small value to test 413
    monkeypatch.setattr(settings, "MAX_EMAIL_SIZE_BYTES", 50)
    response = client.post(
        "/api/analyze",
        json={"raw_email": "Subject: Test\n\n" + "x" * 100},
    )
    assert response.status_code == 413


def test_graph_related_endpoint():
    """Verify the /api/graph/{hash}/related endpoint is routable."""
    with patch("app.graph.neo4j_client.get_driver") as mock_driver:
        from neo4j.exceptions import ServiceUnavailable
        mock_driver.side_effect = ServiceUnavailable("test")
        response = client.get("/api/graph/test-hash/related")
    assert response.status_code == 200
    data = response.json()
    assert data["campaign_size"] == 0


def test_graph_visualization_endpoint():
    """Verify the /api/graph/{hash} endpoint is routable."""
    with patch("app.graph.neo4j_client.get_driver") as mock_driver:
        from neo4j.exceptions import ServiceUnavailable
        mock_driver.side_effect = ServiceUnavailable("test")
        response = client.get("/api/graph/test-hash")
    assert response.status_code == 200
    data = response.json()
    assert data["nodes"] == []
    assert data["edges"] == []


def test_history_and_reports_flow():
    """Test analyze -> history listing -> history detail -> PDF report generation."""
    benign_path = FIXTURES_DIR / "sample_benign.eml"
    patches = _patch_vt_and_neo4j()
    with patches[0], patches[1], patches[2], patches[3]:
        with open(benign_path, "rb") as f:
            analyze_resp = client.post(
                "/api/analyze",
                files={"file": ("sample_benign.eml", f, "message/rfc822")},
            )
    assert analyze_resp.status_code == 200
    email_hash = analyze_resp.json()["email_hash"]

    # 1. Check history list contains the analyzed email
    hist_resp = client.get("/api/history")
    assert hist_resp.status_code == 200
    hist_items = hist_resp.json()
    assert any(item["id"] == email_hash for item in hist_items)

    # 2. Check history detail returns full JSON
    detail_resp = client.get(f"/api/history/{email_hash}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["email_hash"] == email_hash
    assert detail_resp.json()["subject"] == "Your Monthly Acme Statement"

    # 3. Check PDF report endpoint
    pdf_resp = client.get(f"/api/reports/{email_hash}.pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert "attachment" in pdf_resp.headers["content-disposition"]
    assert pdf_resp.content.startswith(b"%PDF")


def test_history_not_found():
    response = client.get("/api/history/nonexistent_hash_123")
    assert response.status_code == 404


def test_report_not_found():
    response = client.get("/api/reports/nonexistent_hash_123.pdf")
    assert response.status_code == 404
