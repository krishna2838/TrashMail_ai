"""Unit tests for Neo4j graph client — all calls mocked at the driver level."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.graph.neo4j_client import (
    compute_clusters,
    find_related_emails,
    get_graph_for_visualization,
    save_analysis,
)


# ── compute_clusters tests ──────────────────────────────────────────────


def test_compute_clusters_no_shared_indicators():
    """Two emails with no connecting edges — no clusters returned."""
    nodes = [
        {"id": "e1", "type": "email", "risk_score": 80, "subject": "s1"},
        {"id": "e2", "type": "email", "risk_score": 40, "subject": "s2"},
    ]
    assert compute_clusters(nodes, []) == []


def test_compute_clusters_single_pair_via_shared_ip():
    nodes = [
        {"id": "e1", "type": "email", "risk_score": 88, "subject": "Bank"},
        {"id": "e2", "type": "email", "risk_score": 55, "subject": "KYC"},
        {"id": "1.2.3.4", "type": "ip"},
        {"id": "e3", "type": "email", "risk_score": 10, "subject": "Lonely"},
    ]
    edges = [
        {"source": "e1", "target": "1.2.3.4", "type": "ORIGINATED_FROM"},
        {"source": "e2", "target": "1.2.3.4", "type": "ORIGINATED_FROM"},
    ]
    clusters = compute_clusters(nodes, edges)
    assert len(clusters) == 1
    c = clusters[0]
    assert c["cluster_id"] == "CLU-01"
    assert c["email_count"] == 2
    assert c["highest_risk_score"] == 88
    assert c["representative_subject"] == "Bank"
    assert set(c["member_email_ids"]) == {"e1", "e2"}


def test_compute_clusters_three_emails_transitively_linked():
    """e1–D1, e2–D1, e2–D2, e3–D2 → all three emails in one component (transitive)."""
    nodes = [
        {"id": "e1", "type": "email", "risk_score": 60, "subject": "one"},
        {"id": "e2", "type": "email", "risk_score": 92, "subject": "TWO high"},
        {"id": "e3", "type": "email", "risk_score": 70, "subject": "three"},
        {"id": "d1", "type": "domain"},
        {"id": "d2", "type": "domain"},
    ]
    edges = [
        {"source": "e1", "target": "d1", "type": "LINKS_TO"},
        {"source": "e2", "target": "d1", "type": "LINKS_TO"},
        {"source": "e2", "target": "d2", "type": "LINKS_TO"},
        {"source": "e3", "target": "d2", "type": "LINKS_TO"},
    ]
    clusters = compute_clusters(nodes, edges)
    assert len(clusters) == 1
    c = clusters[0]
    assert c["email_count"] == 3
    assert c["highest_risk_score"] == 92
    assert c["representative_subject"] == "TWO high"
    assert set(c["member_email_ids"]) == {"e1", "e2", "e3"}


def test_compute_clusters_multiple_independent_clusters_ordered_by_risk():
    nodes = [
        # cluster A (max risk 70)
        {"id": "ea1", "type": "email", "risk_score": 70, "subject": "A1"},
        {"id": "ea2", "type": "email", "risk_score": 55, "subject": "A2"},
        {"id": "ipA", "type": "ip"},
        # cluster B (max risk 95)
        {"id": "eb1", "type": "email", "risk_score": 95, "subject": "B1"},
        {"id": "eb2", "type": "email", "risk_score": 60, "subject": "B2"},
        {"id": "ipB", "type": "ip"},
    ]
    edges = [
        {"source": "ea1", "target": "ipA", "type": "ORIGINATED_FROM"},
        {"source": "ea2", "target": "ipA", "type": "ORIGINATED_FROM"},
        {"source": "eb1", "target": "ipB", "type": "ORIGINATED_FROM"},
        {"source": "eb2", "target": "ipB", "type": "ORIGINATED_FROM"},
    ]
    clusters = compute_clusters(nodes, edges)
    assert [c["cluster_id"] for c in clusters] == ["CLU-01", "CLU-02"]
    # Highest-risk cluster first
    assert clusters[0]["highest_risk_score"] == 95
    assert clusters[1]["highest_risk_score"] == 70


def _make_mock_driver():
    """Create a mock Neo4j driver with session context manager."""
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
    return mock_driver, mock_session


# ── save_analysis tests ──────────────────────────────────────────────


@patch("app.graph.neo4j_client.get_driver")
def test_save_analysis_persists_email_with_geo_and_domains(mock_get_driver):
    mock_driver, mock_session = _make_mock_driver()
    mock_get_driver.return_value = mock_driver

    analysis = {
        "email_hash": "abc123",
        "subject": "Test Subject",
        "sender": "test@example.com",
        "verdict": "Safe",
        "risk_score": 10,
        "origin_geo": {
            "ip": "1.2.3.4",
            "country": "US",
            "city": "New York",
            "asn_org": "Example ISP",
        },
        "domains": ["example.com", "test.org"],
    }

    save_analysis(analysis)

    # Should have called session.run with a Cypher query
    mock_session.run.assert_called_once()
    call_args = mock_session.run.call_args
    cypher = call_args[0][0]
    assert "MERGE (e:Email {id: $email_hash})" in cypher
    assert "MERGE (ip:IP {address: $ip_address})" in cypher
    assert "MERGE (e)-[:ORIGINATED_FROM]->(ip)" in cypher
    assert "MERGE (d:Domain {name: domain_name})" in cypher
    assert "MERGE (e)-[:LINKS_TO]->(d)" in cypher


@patch("app.graph.neo4j_client.get_driver")
def test_save_analysis_without_geo(mock_get_driver):
    mock_driver, mock_session = _make_mock_driver()
    mock_get_driver.return_value = mock_driver

    analysis = {
        "email_hash": "xyz789",
        "subject": "No Geo",
        "sender": "sender@example.com",
        "verdict": "Safe",
        "risk_score": 5,
        "origin_geo": None,
        "domains": [],
    }

    save_analysis(analysis)

    mock_session.run.assert_called_once()
    cypher = mock_session.run.call_args[0][0]
    assert "MERGE (e:Email {id: $email_hash})" in cypher
    # No IP or domain nodes when geo is None and domains is empty
    assert "MERGE (ip:IP" not in cypher
    assert "UNWIND" not in cypher


@patch("app.graph.neo4j_client.get_driver")
def test_save_analysis_handles_neo4j_down(mock_get_driver):
    from neo4j.exceptions import ServiceUnavailable

    mock_get_driver.side_effect = ServiceUnavailable("Connection refused")

    # Should NOT raise — logs warning and returns silently
    save_analysis({"email_hash": "fail-test", "subject": "", "sender": "", "verdict": "", "risk_score": 0})


# ── find_related_emails tests ────────────────────────────────────────


@patch("app.graph.neo4j_client.get_driver")
def test_find_related_emails_returns_matches(mock_get_driver):
    mock_driver, mock_session = _make_mock_driver()
    mock_get_driver.return_value = mock_driver

    mock_record = {
        "id": "related-email-1",
        "subject": "Another Phish",
        "verdict": "Phishing/Scam",
        "shared_indicators": [{"type": "domain", "value": "evil.com"}],
    }
    mock_session.run.return_value = [mock_record]

    result = find_related_emails("test-email-hash")

    assert result["campaign_size"] == 1
    rel = result["related_emails"][0]
    assert rel["id"] == "related-email-1"
    # Backward compat fields derived from first indicator
    assert rel["shared_via"] == "domain"
    assert rel["shared_value"] == "evil.com"
    # New multi-indicator fields
    assert len(rel["shared_indicators"]) == 1
    assert rel["shared_indicators"][0] == {"type": "domain", "value": "evil.com"}
    assert rel["correlation_strength"] == "weak"


@patch("app.graph.neo4j_client.get_driver")
def test_find_related_emails_handles_neo4j_down(mock_get_driver):
    from neo4j.exceptions import ServiceUnavailable

    mock_get_driver.side_effect = ServiceUnavailable("Connection refused")

    result = find_related_emails("some-hash")
    assert result == {"related_emails": [], "campaign_size": 0}


# ── get_graph_for_visualization tests ────────────────────────────────


@patch("app.graph.neo4j_client.get_driver")
def test_get_graph_returns_empty_when_neo4j_down(mock_get_driver):
    from neo4j.exceptions import ServiceUnavailable

    mock_get_driver.side_effect = ServiceUnavailable("Connection refused")

    result = get_graph_for_visualization("some-hash")
    assert result == {"nodes": [], "edges": []}


@patch("app.graph.neo4j_client.get_driver")
def test_get_graph_returns_nodes_and_edges(mock_get_driver):
    mock_driver, mock_session = _make_mock_driver()
    mock_get_driver.return_value = mock_driver

    # Mock empty result — just verify it doesn't crash
    mock_session.run.return_value = []

    result = get_graph_for_visualization("test-hash", depth=2)
    assert "nodes" in result
    assert "edges" in result
    assert isinstance(result["nodes"], list)
    assert isinstance(result["edges"], list)


@patch("app.graph.neo4j_client.get_driver")
def test_save_analysis_persists_fingerprints(mock_get_driver):
    mock_driver, mock_session = _make_mock_driver()
    mock_get_driver.return_value = mock_driver

    analysis = {
        "email_hash": "hash-with-fingerprints",
        "subject": "Phish with UPI",
        "sender": "scam@fake.com",
        "verdict": "Phishing/Scam",
        "risk_score": 85,
        "origin_geo": None,
        "domains": [],
        "upi_ids": ["scam@okhdfcbank"],
        "wallet_addresses": ["0x1234567890abcdef1234567890abcdef12345678"],
        "attachment_hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        "template_structure_hash": "a1b2c3d4e5f6",
    }

    save_analysis(analysis)

    mock_session.run.assert_called_once()
    cypher = mock_session.run.call_args[0][0]
    call_kwargs = mock_session.run.call_args[1]

    assert "MERGE (u:UPI {id: upi_id})" in cypher
    assert "MERGE (w:Wallet {address: wallet})" in cypher
    assert "MERGE (a:AttachmentHash {hash: att_hash})" in cypher
    assert "MERGE (t:TemplateHash {hash: $template_hash})" in cypher
    assert call_kwargs["upi_ids"] == ["scam@okhdfcbank"]
    assert call_kwargs["template_hash"] == "a1b2c3d4e5f6"


@patch("app.graph.neo4j_client.get_driver")
def test_find_related_emails_via_upi_or_wallet(mock_get_driver):
    mock_driver, mock_session = _make_mock_driver()
    mock_get_driver.return_value = mock_driver

    mock_record = {
        "id": "gang-email-2",
        "subject": "Tax Refund Phish",
        "verdict": "Phishing/Scam",
        "shared_indicators": [{"type": "upi", "value": "gang.collector@okhdfcbank"}],
    }
    mock_session.run.return_value = [mock_record]

    result = find_related_emails("gang-email-1")

    assert result["campaign_size"] == 1
    rel = result["related_emails"][0]
    assert rel["id"] == "gang-email-2"
    assert rel["shared_via"] == "upi"
    assert rel["shared_value"] == "gang.collector@okhdfcbank"
    assert rel["shared_indicators"][0] == {"type": "upi", "value": "gang.collector@okhdfcbank"}
    assert rel["correlation_strength"] == "weak"


@patch("app.graph.neo4j_client.get_driver")
def test_find_related_emails_multi_indicator_strength(mock_get_driver):
    """When an email shares multiple indicator types, response should list all with correct strength."""
    mock_driver, mock_session = _make_mock_driver()
    mock_get_driver.return_value = mock_driver

    # Simulate Neo4j returning pre-aggregated indicators (as the new COLLECT query would)
    mock_record = {
        "id": "multi-link-email",
        "subject": "Same Campaign",
        "verdict": "Phishing/Scam",
        "shared_indicators": [
            {"type": "ip", "value": "1.2.3.4"},
            {"type": "domain", "value": "evil.com"},
            {"type": "template_hash", "value": "abc123"},
        ],
    }
    mock_session.run.return_value = [mock_record]

    result = find_related_emails("target-email")

    assert result["campaign_size"] == 1
    rel = result["related_emails"][0]
    assert len(rel["shared_indicators"]) == 3
    assert rel["correlation_strength"] == "strong"
    # Backward compat uses first indicator
    assert rel["shared_via"] == "ip"
    assert rel["shared_value"] == "1.2.3.4"


@patch("app.graph.neo4j_client.get_driver")
def test_find_related_emails_moderate_strength(mock_get_driver):
    """Two shared indicators → moderate correlation strength."""
    mock_driver, mock_session = _make_mock_driver()
    mock_get_driver.return_value = mock_driver

    mock_record = {
        "id": "two-link-email",
        "subject": "Shared IP and Domain",
        "verdict": "Suspicious",
        "shared_indicators": [
            {"type": "ip", "value": "5.6.7.8"},
            {"type": "domain", "value": "phish.net"},
        ],
    }
    mock_session.run.return_value = [mock_record]

    result = find_related_emails("another-email")

    rel = result["related_emails"][0]
    assert rel["correlation_strength"] == "moderate"
    assert len(rel["shared_indicators"]) == 2


@patch("app.graph.neo4j_client.get_driver")
def test_get_graph_visualizes_fingerprint_nodes(mock_get_driver):
    mock_driver, mock_session = _make_mock_driver()
    mock_get_driver.return_value = mock_driver

    mock_records = [
        {
            "eid": "4:0",
            "node_labels": ["Email"],
            "node_props": {"id": "email-1", "subject": "Invoice Scam", "verdict": "Phishing/Scam"},
            "rel_start_eid": "4:0",
            "rel_end_eid": "4:1",
            "rel_type": "PAYS_TO",
        },
        {
            "eid": "4:1",
            "node_labels": ["UPI"],
            "node_props": {"id": "fraud@ybl"},
            "rel_start_eid": "4:0",
            "rel_end_eid": "4:1",
            "rel_type": "PAYS_TO",
        },
        {
            "eid": "4:2",
            "node_labels": ["Wallet"],
            "node_props": {"address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"},
            "rel_start_eid": "4:0",
            "rel_end_eid": "4:2",
            "rel_type": "PAYS_TO",
        },
    ]
    mock_session.run.return_value = mock_records

    result = get_graph_for_visualization("email-1")
    types = {n["type"] for n in result["nodes"]}
    assert "email" in types
    assert "upi" in types
    assert "wallet" in types
    labels = {n["label"] for n in result["nodes"]}
    assert "UPI: fraud@ybl" in labels
