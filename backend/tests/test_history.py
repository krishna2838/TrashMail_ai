"""Unit tests for SQLite investigation history persistence."""

from __future__ import annotations

import pytest
from sqlmodel import Session, SQLModel, create_engine

import app.db.history as history_module
from app.db.history import (
    Investigation,
    get_investigation,
    init_db,
    list_investigations,
    save_investigation,
)


@pytest.fixture(autouse=True)
def use_test_db(monkeypatch, tmp_path):
    """Use an isolated SQLite database file in a temp dir for tests."""
    test_db_path = tmp_path / "test_history.sqlite3"
    test_engine = create_engine(f"sqlite:///{test_db_path}", connect_args={"check_same_thread": False})

    monkeypatch.setattr(history_module, "DB_PATH", test_db_path)
    monkeypatch.setattr(history_module, "engine", test_engine)

    SQLModel.metadata.create_all(test_engine)
    yield test_engine


def test_init_db():
    init_db()


def test_save_and_list_investigations():
    analysis = {
        "email_hash": "test_hash_1",
        "subject": "Phishing Test 1",
        "sender": "attacker@evil.com",
        "verdict": "Phishing/Scam",
        "risk_score": 85,
        "indicators": ["SPF failed"],
    }
    save_investigation(analysis)

    items = list_investigations(limit=10)
    assert len(items) == 1
    assert items[0]["id"] == "test_hash_1"
    assert items[0]["subject"] == "Phishing Test 1"
    assert items[0]["sender"] == "attacker@evil.com"
    assert items[0]["verdict"] == "Phishing/Scam"
    assert items[0]["risk_score"] == 85
    # New indicator fields default to None/0 when the analysis dict didn't
    # include domains / origin_geo / campaign.
    assert items[0]["top_domain"] is None
    assert items[0]["origin_country"] is None
    assert items[0]["campaign_size"] == 0


def test_list_investigations_extracts_indicator_fields():
    analysis = {
        "email_hash": "indicator_hash",
        "subject": "With indicators",
        "sender": "x@bad.io",
        "verdict": "Phishing/Scam",
        "risk_score": 90,
        "domains": ["bad.io", "cdn.bad.io"],
        "origin_geo": {"country": "Russia", "city": "Moscow"},
        "campaign": {"campaign_size": 4, "related_emails": []},
    }
    save_investigation(analysis)

    items = list_investigations()
    assert len(items) == 1
    item = items[0]
    assert item["top_domain"] == "bad.io"
    assert item["origin_country"] == "Russia"
    assert item["campaign_size"] == 4


def test_list_investigations_handles_partial_indicator_data():
    """Older/partial records must not crash — missing sections → safe defaults."""
    partial = {
        "email_hash": "partial_hash",
        "subject": "Partial",
        "sender": "y@example.com",
        "verdict": "Suspicious",
        "risk_score": 55,
        "domains": [],
        "origin_geo": {},
    }
    save_investigation(partial)

    items = list_investigations()
    item = next(i for i in items if i["id"] == "partial_hash")
    assert item["top_domain"] is None
    assert item["origin_country"] is None
    assert item["campaign_size"] == 0


def test_get_investigation_found():
    analysis = {
        "email_hash": "test_hash_2",
        "subject": "Legit Test",
        "sender": "support@bank.com",
        "verdict": "Safe",
        "risk_score": 10,
        "hops": [{"sequence": 1, "from_ip": "1.1.1.1"}],
    }
    save_investigation(analysis)

    retrieved = get_investigation("test_hash_2")
    assert retrieved is not None
    assert retrieved["email_hash"] == "test_hash_2"
    assert retrieved["subject"] == "Legit Test"
    assert len(retrieved["hops"]) == 1


def test_get_investigation_not_found():
    assert get_investigation("non_existent_hash") is None


def test_save_investigation_upsert():
    analysis_initial = {
        "email_hash": "upsert_hash",
        "subject": "Initial Subject",
        "sender": "test@test.com",
        "verdict": "Suspicious",
        "risk_score": 50,
    }
    save_investigation(analysis_initial)

    analysis_updated = {
        "email_hash": "upsert_hash",
        "subject": "Updated Subject",
        "sender": "test@test.com",
        "verdict": "Phishing/Scam",
        "risk_score": 90,
    }
    save_investigation(analysis_updated)

    items = list_investigations()
    assert len(items) == 1
    assert items[0]["subject"] == "Updated Subject"
    assert items[0]["risk_score"] == 90

    full = get_investigation("upsert_hash")
    assert full["verdict"] == "Phishing/Scam"
