"""Unit tests for Neo4j graph client — all calls mocked at the driver level."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.graph.neo4j_client import (
    find_related_emails,
    get_graph_for_visualization,
    save_analysis,
)


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
        "shared_via": "domain",
        "shared_value": "evil.com",
    }
    mock_session.run.return_value = [mock_record]

    result = find_related_emails("test-email-hash")

    assert result["campaign_size"] == 1
    assert result["related_emails"][0]["id"] == "related-email-1"
    assert result["related_emails"][0]["shared_via"] == "domain"


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
        "shared_via": "upi",
        "shared_value": "gang.collector@okhdfcbank",
    }
    mock_session.run.return_value = [mock_record]

    result = find_related_emails("gang-email-1")

    assert result["campaign_size"] == 1
    assert result["related_emails"][0]["id"] == "gang-email-2"
    assert result["related_emails"][0]["shared_via"] == "upi"
    assert result["related_emails"][0]["shared_value"] == "gang.collector@okhdfcbank"


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
