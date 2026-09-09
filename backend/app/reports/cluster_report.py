"""Campaign-level (cluster) report aggregation.

Aggregates data across all member emails of a cluster. Reads from SQLite
(via `get_investigation()`) rather than re-querying Neo4j — the full stored
analysis dict already contains every field needed for the report.
"""

from __future__ import annotations

import logging
from typing import Any

from app.db.history import get_investigation

logger = logging.getLogger(__name__)


# Same thresholds used by Phase 19 (Investigations) / Phase 20 (Clusters)
def _risk_classification(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 35:
        return "Medium"
    return "Safe"


_INDICATOR_LABELS = {
    "domain": "Domain",
    "ip": "IP Address",
    "upi": "UPI ID",
    "wallet": "Crypto Wallet",
    "attachment_hash": "Attachment Hash",
    "template_hash": "Template Hash",
}


def _collect_indicators(analysis: dict[str, Any]) -> dict[str, set[str]]:
    """Pull each indicator type's values out of a single stored analysis."""
    out: dict[str, set[str]] = {k: set() for k in _INDICATOR_LABELS}

    for d in analysis.get("domains") or []:
        if isinstance(d, str) and d:
            out["domain"].add(d.strip().lower())
        elif isinstance(d, dict):
            v = d.get("domain") or d.get("name")
            if v:
                out["domain"].add(str(v).strip().lower())

    origin = analysis.get("origin_ip")
    if isinstance(origin, str) and origin:
        out["ip"].add(origin.strip())

    for h in analysis.get("hops") or []:
        if isinstance(h, dict):
            for key in ("from_ip", "by_ip"):
                v = h.get(key)
                if isinstance(v, str) and v:
                    out["ip"].add(v.strip())

    payment = analysis.get("payment_indicators") or {}
    if isinstance(payment, dict):
        for u in payment.get("upi") or []:
            if isinstance(u, str) and u:
                out["upi"].add(u.strip())
            elif isinstance(u, dict):
                v = u.get("id") or u.get("value")
                if v:
                    out["upi"].add(str(v).strip())
        for w in payment.get("crypto") or payment.get("wallet") or []:
            if isinstance(w, str) and w:
                out["wallet"].add(w.strip())
            elif isinstance(w, dict):
                v = w.get("address") or w.get("value")
                if v:
                    out["wallet"].add(str(v).strip())

    for a in analysis.get("attachments") or []:
        if isinstance(a, dict):
            h = a.get("sha256") or a.get("hash")
            if isinstance(h, str) and h:
                out["attachment_hash"].add(h.strip().lower())

    tpl = analysis.get("template_hash")
    if isinstance(tpl, str) and tpl:
        out["template_hash"].add(tpl.strip().lower())
    fp = analysis.get("fingerprints")
    if isinstance(fp, dict):
        v = fp.get("template_hash")
        if isinstance(v, str) and v:
            out["template_hash"].add(v.strip().lower())

    return out


def _describe_top_types(shared_evidence: list[dict[str, Any]], n: int = 2) -> str:
    """Return a natural phrase for the top-N indicator types by member count."""
    if not shared_evidence:
        return "unknown shared infrastructure"

    by_type_count: dict[str, int] = {}
    for item in shared_evidence:
        t = item["type"]
        by_type_count[t] = by_type_count.get(t, 0) + item["complaint_count"]

    ranked = sorted(by_type_count.items(), key=lambda kv: (-kv[1], kv[0]))
    labels = [_INDICATOR_LABELS.get(t, t).lower() for t, _ in ranked[:n]]
    if not labels:
        return "shared infrastructure"
    if len(labels) == 1:
        return f"a shared {labels[0]}"
    return f"shared {labels[0]} and {labels[1]}"


def get_cluster_report(email_ids: list[str]) -> dict[str, Any]:
    """Aggregate a campaign report across the given member email hashes."""
    ids = [i for i in (email_ids or []) if isinstance(i, str) and i.strip()]
    if not ids:
        return {
            "linked_complaints": 0,
            "risk_classification": "Safe",
            "first_observed": None,
            "last_observed": None,
            "highest_risk_score": 0,
            "member_email_ids": [],
            "victim_senders": [],
            "shared_evidence": [],
            "executive_summary": "No emails in this cluster.",
        }

    members: list[dict[str, Any]] = []
    for hid in ids:
        try:
            a = get_investigation(hid)
        except Exception as exc:
            logger.warning("Failed to load investigation %s for cluster report: %s", hid, exc)
            a = None
        if a:
            members.append(a)

    if not members:
        return {
            "linked_complaints": 0,
            "risk_classification": "Safe",
            "first_observed": None,
            "last_observed": None,
            "highest_risk_score": 0,
            "member_email_ids": ids,
            "victim_senders": [],
            "shared_evidence": [],
            "executive_summary": "No stored analyses found for the requested cluster members.",
        }

    # Per-member indicator sets so we can count how many members share each value.
    member_indicators: list[dict[str, set[str]]] = [_collect_indicators(m) for m in members]

    # value_counts[type][value] = number of members that reference this value
    value_counts: dict[str, dict[str, int]] = {k: {} for k in _INDICATOR_LABELS}
    for mi in member_indicators:
        for t, values in mi.items():
            for v in values:
                value_counts[t][v] = value_counts[t].get(v, 0) + 1

    shared_evidence: list[dict[str, Any]] = []
    for t, counts in value_counts.items():
        for v, c in counts.items():
            if c >= 2:
                shared_evidence.append({
                    "type": t,
                    "type_label": _INDICATOR_LABELS.get(t, t),
                    "value": v,
                    "complaint_count": c,
                })
    shared_evidence.sort(key=lambda x: (-x["complaint_count"], x["type"], x["value"]))

    # Aggregate risk / dates / senders
    risk_scores = []
    for m in members:
        try:
            risk_scores.append(int(m.get("risk_score") or 0))
        except (TypeError, ValueError):
            risk_scores.append(0)
    highest = max(risk_scores) if risk_scores else 0

    dates = [m.get("analyzed_at") for m in members if m.get("analyzed_at")]
    dates_sorted = sorted(d for d in dates if isinstance(d, str))
    first_observed = dates_sorted[0] if dates_sorted else None
    last_observed = dates_sorted[-1] if dates_sorted else None

    # Preserve insertion order for senders
    seen_senders: set[str] = set()
    victim_senders: list[str] = []
    for m in members:
        s = m.get("sender")
        if isinstance(s, str) and s and s not in seen_senders:
            seen_senders.add(s)
            victim_senders.append(s)

    n = len(members)
    date_range = (
        f"between {first_observed} and {last_observed}"
        if first_observed and last_observed and first_observed != last_observed
        else (f"on {first_observed}" if first_observed else "at unknown times")
    )
    top_types = _describe_top_types(shared_evidence, n=2)
    executive_summary = (
        f"{n} linked complaints identified {date_range}, correlated via {top_types}."
    )

    return {
        "linked_complaints": n,
        "risk_classification": _risk_classification(highest),
        "highest_risk_score": highest,
        "first_observed": first_observed,
        "last_observed": last_observed,
        "member_email_ids": [m.get("email_hash") for m in members if m.get("email_hash")] or ids,
        "victim_senders": victim_senders,
        "shared_evidence": shared_evidence,
        "executive_summary": executive_summary,
    }
