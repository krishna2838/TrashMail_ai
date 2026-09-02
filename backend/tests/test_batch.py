"""Unit and integration tests for batch email analysis."""

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.api.routes_batch import compute_cluster_count
from app.main import app

client = TestClient(app)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_compute_cluster_count_logic():
    # Scenario 1: No edges, emails unconnected
    graph1 = {
        "nodes": [{"id": "e1"}, {"id": "e2"}, {"id": "e3"}],
        "edges": [],
    }
    assert compute_cluster_count(graph1, {"e1", "e2", "e3"}) == 0

    # Scenario 2: e1 and e2 connected to shared domain d1; e3 isolated
    graph2 = {
        "nodes": [{"id": "e1"}, {"id": "e2"}, {"id": "e3"}, {"id": "d1"}],
        "edges": [
            {"source": "e1", "target": "d1"},
            {"source": "e2", "target": "d1"},
        ],
    }
    assert compute_cluster_count(graph2, {"e1", "e2", "e3"}) == 1

    # Scenario 3: Two separate clusters: (e1, e2) and (e3, e4)
    graph3 = {
        "nodes": [{"id": "e1"}, {"id": "e2"}, {"id": "e3"}, {"id": "e4"}, {"id": "d1"}, {"id": "d2"}],
        "edges": [
            {"source": "e1", "target": "d1"},
            {"source": "e2", "target": "d1"},
            {"source": "e3", "target": "d2"},
            {"source": "e4", "target": "d2"},
        ],
    }
    assert compute_cluster_count(graph3, {"e1", "e2", "e3", "e4"}) == 2


@patch("app.api.routes_analyze.check_domain", return_value={"available": False})
@patch("app.api.routes_analyze.check_ip", return_value={"available": False})
@patch("app.api.routes_analyze.geolocate_ip", return_value=None)
def test_batch_analyze_success(mock_geo, mock_ip, mock_domain):
    phish1 = (FIXTURES_DIR / "sample_phish.eml").read_bytes()
    phish2 = (FIXTURES_DIR / "sample_phish2.eml").read_bytes()
    benign = (FIXTURES_DIR / "sample_benign.eml").read_bytes()

    files = [
        ("files", ("sample_phish.eml", phish1, "message/rfc822")),
        ("files", ("sample_phish2.eml", phish2, "message/rfc822")),
        ("files", ("sample_benign.eml", benign, "message/rfc822")),
    ]

    response = client.post("/api/analyze/batch", files=files)
    assert response.status_code == 200
    data = response.json()

    assert "results" in data
    assert "errors" in data
    assert "combined_graph" in data
    assert "cluster_count" in data

    assert len(data["results"]) == 3
    assert len(data["errors"]) == 0

    filenames = [r["filename"] for r in data["results"]]
    assert "sample_phish.eml" in filenames
    assert "sample_phish2.eml" in filenames
    assert "sample_benign.eml" in filenames

    # Verify verdicts
    results_by_fname = {r["filename"]: r for r in data["results"]}
    assert results_by_fname["sample_phish.eml"]["verdict"] in ["Phishing/Scam", "Suspicious"]
    assert results_by_fname["sample_phish2.eml"]["verdict"] in ["Phishing/Scam", "Suspicious"]
    assert results_by_fname["sample_benign.eml"]["verdict"] == "Safe"


def test_batch_analyze_exceeds_max_files():
    # 21 files when MAX_BATCH_FILES is 20
    files = [
        ("files", (f"file_{i}.eml", b"From: test@example.com\nSubject: Test\n\nBody", "message/rfc822"))
        for i in range(21)
    ]
    response = client.post("/api/analyze/batch", files=files)
    assert response.status_code == 400
    assert "exceeds maximum limit" in response.json()["detail"]


@patch("app.api.routes_analyze.check_domain", return_value={"available": False})
@patch("app.api.routes_analyze.check_ip", return_value={"available": False})
@patch("app.api.routes_analyze.geolocate_ip", return_value=None)
def test_batch_analyze_partial_failure_continues(mock_geo, mock_ip, mock_domain):
    benign = (FIXTURES_DIR / "sample_benign.eml").read_bytes()
    files = [
        ("files", ("valid.eml", benign, "message/rfc822")),
        ("files", ("empty.eml", b"", "message/rfc822")),
    ]

    response = client.post("/api/analyze/batch", files=files)
    assert response.status_code == 200
    data = response.json()

    assert len(data["results"]) == 1
    assert data["results"][0]["filename"] == "valid.eml"

    assert len(data["errors"]) == 1
    assert data["errors"][0]["filename"] == "empty.eml"
    assert "empty" in data["errors"][0]["error"].lower()
