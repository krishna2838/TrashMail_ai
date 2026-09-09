"""Unit tests for campaign-level cluster report aggregation."""

from __future__ import annotations

import pytest
from sqlmodel import SQLModel, create_engine

import app.db.history as history_module
from app.db.history import save_investigation
from app.reports.cluster_report import get_cluster_report


@pytest.fixture(autouse=True)
def use_test_db(monkeypatch, tmp_path):
    test_db_path = tmp_path / "test_cluster_history.sqlite3"
    test_engine = create_engine(
        f"sqlite:///{test_db_path}", connect_args={"check_same_thread": False}
    )
    monkeypatch.setattr(history_module, "DB_PATH", test_db_path)
    monkeypatch.setattr(history_module, "engine", test_engine)
    SQLModel.metadata.create_all(test_engine)
    yield test_engine


def _seed(hash_id: str, **kwargs):
    base = {
        "email_hash": hash_id,
        "subject": kwargs.pop("subject", f"Subject {hash_id}"),
        "sender": kwargs.pop("sender", f"user-{hash_id}@example.com"),
        "verdict": kwargs.pop("verdict", "Phishing/Scam"),
        "risk_score": kwargs.pop("risk_score", 80),
        "analyzed_at": kwargs.pop("analyzed_at", "2026-09-01T12:00:00+00:00"),
    }
    base.update(kwargs)
    save_investigation(base)


def test_get_cluster_report_multi_email_with_shared_indicators():
    _seed(
        "h1",
        risk_score=95,
        analyzed_at="2026-09-01T10:00:00+00:00",
        domains=["evil.io", "cdn.evil.io"],
        origin_ip="1.2.3.4",
        payment_indicators={"upi": ["scam@upi"]},
    )
    _seed(
        "h2",
        risk_score=72,
        analyzed_at="2026-09-02T10:00:00+00:00",
        domains=["evil.io"],
        origin_ip="1.2.3.4",
        payment_indicators={"upi": ["scam@upi"]},
    )
    _seed(
        "h3",
        risk_score=60,
        analyzed_at="2026-09-03T10:00:00+00:00",
        domains=["evil.io"],
        origin_ip="9.9.9.9",  # not shared
    )

    report = get_cluster_report(["h1", "h2", "h3"])

    assert report["linked_complaints"] == 3
    assert report["risk_classification"] == "Critical"  # max risk 95 → >= 85
    assert report["highest_risk_score"] == 95
    assert report["first_observed"] == "2026-09-01T10:00:00+00:00"
    assert report["last_observed"] == "2026-09-03T10:00:00+00:00"

    ev = {(e["type"], e["value"]): e["complaint_count"] for e in report["shared_evidence"]}
    # evil.io appears in all 3 → count 3
    assert ev[("domain", "evil.io")] == 3
    # 1.2.3.4 in 2 → count 2
    assert ev[("ip", "1.2.3.4")] == 2
    # scam@upi in 2 → count 2
    assert ev[("upi", "scam@upi")] == 2
    # cdn.evil.io only in one → NOT present
    assert ("domain", "cdn.evil.io") not in ev
    # 9.9.9.9 only in one → NOT present
    assert ("ip", "9.9.9.9") not in ev

    assert "3 linked complaints" in report["executive_summary"]
    assert "domain" in report["executive_summary"].lower()

    assert set(report["victim_senders"]) == {
        "user-h1@example.com",
        "user-h2@example.com",
        "user-h3@example.com",
    }


def test_get_cluster_report_two_members_share_exactly_one_indicator():
    """Boundary: exactly the minimum that qualifies as 'shared evidence'."""
    _seed(
        "e1",
        risk_score=40,
        analyzed_at="2026-08-10T08:00:00+00:00",
        domains=["shared.example"],
        origin_ip="10.0.0.1",
    )
    _seed(
        "e2",
        risk_score=42,
        analyzed_at="2026-08-11T08:00:00+00:00",
        domains=["shared.example"],
        origin_ip="10.0.0.2",  # NOT shared with e1
    )

    report = get_cluster_report(["e1", "e2"])

    assert report["linked_complaints"] == 2
    assert report["risk_classification"] == "Medium"

    types_seen = {(e["type"], e["value"]): e["complaint_count"] for e in report["shared_evidence"]}
    # Only the domain qualifies as shared — IPs differ
    assert types_seen == {("domain", "shared.example"): 2}


def test_get_cluster_report_missing_members_do_not_crash():
    """Requesting hashes with no stored record must not blow up."""
    _seed("only1", risk_score=50, analyzed_at="2026-07-01T00:00:00+00:00")
    report = get_cluster_report(["only1", "does-not-exist"])
    # Only the one real member counts
    assert report["linked_complaints"] == 1
    assert report["shared_evidence"] == []


def test_first_last_observed_recovered_from_row_when_missing_in_json():
    """Regression: analysis dicts saved via the /api/analyze route don't
    contain `analyzed_at` themselves — the field lives on the SQLite row.
    The cluster report must still return real dates in that case.
    """
    # Deliberately omit analyzed_at from the payloads — matches production data.
    _seed_no_ts = lambda hid, **kw: save_investigation({
        "email_hash": hid,
        "subject": kw.pop("subject", f"S {hid}"),
        "sender": kw.pop("sender", f"u-{hid}@x.io"),
        "verdict": "Phishing/Scam",
        "risk_score": kw.pop("risk_score", 80),
        "domains": ["shared.example"],
        **kw,
    })
    _seed_no_ts("nt1")
    _seed_no_ts("nt2")

    report = get_cluster_report(["nt1", "nt2"])

    assert report["first_observed"] is not None
    assert report["last_observed"] is not None
    assert "unknown times" not in report["executive_summary"]


def test_get_cluster_report_empty_input():
    report = get_cluster_report([])
    assert report["linked_complaints"] == 0
    assert report["shared_evidence"] == []
