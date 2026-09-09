"""Neo4j graph client for persisting and querying email analysis graphs.

Graph schema:
  (:Email {id, subject, sender, verdict, risk_score, analyzed_at})
  (:IP    {address, country, city, asn_org})
  (:Domain {name})
  (:UPI   {id})
  (:Wallet {address})
  (:AttachmentHash {hash})
  (:TemplateHash {hash})

  (:Email)-[:ORIGINATED_FROM]->(:IP)
  (:Email)-[:LINKS_TO]->(:Domain)
  (:Email)-[:PAYS_TO]->(:UPI)
  (:Email)-[:PAYS_TO]->(:Wallet)
  (:Email)-[:CONTAINS]->(:AttachmentHash)
  (:Email)-[:USES_TEMPLATE]->(:TemplateHash)

All nodes use MERGE to avoid duplicates across analyses.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError

from app.core.config import settings

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_driver():
    """Return a cached Neo4j driver singleton."""
    return GraphDatabase.driver(
        settings.NEO4J_URI,
        auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
    )


def save_analysis(analysis: dict[str, Any]) -> None:
    """Persist an analysis result into the Neo4j graph.

    Creates/merges Email, IP, Domain, UPI, Wallet, AttachmentHash, and TemplateHash
    nodes with appropriate relationships.
    Silently logs warnings on Neo4j failures — never breaks the /api/analyze response.
    """
    try:
        driver = get_driver()
        email_hash = analysis.get("email_hash", "")
        subject = analysis.get("subject", "")
        sender = analysis.get("sender", "")
        verdict = analysis.get("verdict", "")
        risk_score = analysis.get("risk_score", 0)
        origin_geo = analysis.get("origin_geo")
        domains = analysis.get("domains", [])
        upi_ids = analysis.get("upi_ids", [])
        wallet_addresses = analysis.get("wallet_addresses", [])
        attachment_hashes = analysis.get("attachment_hashes", [])
        template_hash = analysis.get("template_structure_hash")

        with driver.session() as session:
            cypher_parts = [
                "MERGE (e:Email {id: $email_hash})",
                "SET e.subject = $subject, e.sender = $sender, "
                "e.verdict = $verdict, e.risk_score = $risk_score, "
                "e.analyzed_at = datetime($analyzed_at)",
            ]
            params: dict[str, Any] = {
                "email_hash": email_hash,
                "subject": subject,
                "sender": sender,
                "verdict": verdict,
                "risk_score": risk_score,
                "analyzed_at": datetime.now(timezone.utc).isoformat(),
            }

            if origin_geo and isinstance(origin_geo, dict) and origin_geo.get("ip"):
                cypher_parts.append(
                    "MERGE (ip:IP {address: $ip_address}) "
                    "SET ip.country = $ip_country, ip.city = $ip_city, "
                    "ip.asn_org = $ip_asn_org"
                )
                cypher_parts.append("MERGE (e)-[:ORIGINATED_FROM]->(ip)")
                params["ip_address"] = origin_geo["ip"]
                params["ip_country"] = origin_geo.get("country")
                params["ip_city"] = origin_geo.get("city")
                params["ip_asn_org"] = origin_geo.get("asn_org")

            # Handle domains with UNWIND
            if domains:
                cypher_parts.append(
                    "WITH DISTINCT e "
                    "UNWIND $domains AS domain_name "
                    "MERGE (d:Domain {name: domain_name}) "
                    "MERGE (e)-[:LINKS_TO]->(d)"
                )
                params["domains"] = list(domains)

            # Handle UPI IDs (Phase 9 - additive)
            if upi_ids:
                cypher_parts.append(
                    "WITH DISTINCT e "
                    "UNWIND $upi_ids AS upi_id "
                    "MERGE (u:UPI {id: upi_id}) "
                    "MERGE (e)-[:PAYS_TO]->(u)"
                )
                params["upi_ids"] = list(upi_ids)

            # Handle crypto wallets (Phase 9 - additive)
            if wallet_addresses:
                cypher_parts.append(
                    "WITH DISTINCT e "
                    "UNWIND $wallet_addresses AS wallet "
                    "MERGE (w:Wallet {address: wallet}) "
                    "MERGE (e)-[:PAYS_TO]->(w)"
                )
                params["wallet_addresses"] = list(wallet_addresses)

            # Handle attachment hashes with filenames (Phase 17 - stores filename on relationship)
            attachment_details = analysis.get("attachment_hash_details", [])
            if attachment_details:
                cypher_parts.append(
                    "WITH DISTINCT e "
                    "UNWIND $attachment_details AS att "
                    "MERGE (a:AttachmentHash {hash: att.hash}) "
                    "MERGE (e)-[c:CONTAINS]->(a) "
                    "SET c.filename = att.filename"
                )
                params["attachment_details"] = list(attachment_details)
            elif attachment_hashes:
                # Backward compat: bare hash list without filenames
                cypher_parts.append(
                    "WITH DISTINCT e "
                    "UNWIND $attachment_hashes AS att_hash "
                    "MERGE (a:AttachmentHash {hash: att_hash}) "
                    "MERGE (e)-[:CONTAINS]->(a)"
                )
                params["attachment_hashes"] = list(attachment_hashes)

            # Handle HTML template structure hash (Phase 9 - additive)
            if template_hash:
                cypher_parts.append(
                    "WITH DISTINCT e "
                    "MERGE (t:TemplateHash {hash: $template_hash}) "
                    "MERGE (e)-[:USES_TEMPLATE]->(t)"
                )
                params["template_hash"] = template_hash

            cypher = "\n".join(cypher_parts)
            session.run(cypher, **params)

        logger.info("Saved analysis for email %s to Neo4j graph.", email_hash)

    except (ServiceUnavailable, OSError, AuthError) as exc:
        logger.warning(
            "Neo4j unavailable — skipping graph persistence: %s", str(exc)
        )
    except Exception as exc:
        logger.warning(
            "Unexpected error saving to Neo4j — skipping: %s", str(exc)
        )


def _correlation_strength(indicator_count: int) -> str:
    """Map indicator count to a human-readable correlation strength label."""
    if indicator_count >= 3:
        return "strong"
    if indicator_count == 2:
        return "moderate"
    return "weak"


def find_related_emails(email_hash: str) -> dict[str, Any]:
    """Find other emails connected via shared IP, Domain, UPI, Wallet, or Hash nodes (2-hop).

    Collects ALL shared indicators per related email, not just the first match.

    Returns:
        {
            "related_emails": [
                {"id": str, "subject": str, "verdict": str,
                 "shared_via": str,        # backward compat — first indicator type
                 "shared_value": str,       # backward compat — first indicator value
                 "shared_indicators": [{"type": str, "value": str}, ...],
                 "correlation_strength": "weak"|"moderate"|"strong"},
                ...
            ],
            "campaign_size": int
        }
    """
    empty_result: dict[str, Any] = {"related_emails": [], "campaign_size": 0}

    try:
        driver = get_driver()
        with driver.session() as session:
            result = session.run(
                """
                MATCH (e1:Email {id: $id})-[]-(shared)-[]-(e2:Email)
                WHERE e1 <> e2
                WITH e2, shared,
                    CASE
                        WHEN 'IP' IN labels(shared) THEN 'ip'
                        WHEN 'Domain' IN labels(shared) THEN 'domain'
                        WHEN 'UPI' IN labels(shared) THEN 'upi'
                        WHEN 'Wallet' IN labels(shared) THEN 'wallet'
                        WHEN 'AttachmentHash' IN labels(shared) THEN 'attachment_hash'
                        WHEN 'TemplateHash' IN labels(shared) THEN 'template_hash'
                        ELSE 'unknown'
                    END AS indicator_type,
                    CASE
                        WHEN 'IP' IN labels(shared) THEN shared.address
                        WHEN 'Domain' IN labels(shared) THEN shared.name
                        WHEN 'UPI' IN labels(shared) THEN shared.id
                        WHEN 'Wallet' IN labels(shared) THEN shared.address
                        WHEN 'AttachmentHash' IN labels(shared) THEN shared.hash
                        WHEN 'TemplateHash' IN labels(shared) THEN shared.hash
                        ELSE ''
                    END AS indicator_value
                WITH e2,
                     COLLECT(DISTINCT {type: indicator_type, value: indicator_value}) AS indicators
                RETURN
                    e2.id AS id,
                    e2.subject AS subject,
                    e2.verdict AS verdict,
                    indicators AS shared_indicators
                """,
                id=email_hash,
            )
            related = []
            for record in result:
                indicators = record["shared_indicators"] or []
                # Deduplicate (safety net in case COLLECT DISTINCT misses edge cases)
                seen_pairs: set[tuple[str, str]] = set()
                deduped: list[dict[str, str]] = []
                for ind in indicators:
                    pair = (ind["type"], ind["value"])
                    if pair not in seen_pairs:
                        deduped.append({"type": ind["type"], "value": ind["value"]})
                        seen_pairs.add(pair)

                first = deduped[0] if deduped else {"type": "unknown", "value": ""}
                related.append({
                    "id": record["id"],
                    "subject": record["subject"],
                    "verdict": record["verdict"],
                    "shared_via": first["type"],
                    "shared_value": first["value"],
                    "shared_indicators": deduped,
                    "correlation_strength": _correlation_strength(len(deduped)),
                })

        return {
            "related_emails": related,
            "campaign_size": len(related),
        }

    except (ServiceUnavailable, OSError, AuthError) as exc:
        logger.warning(
            "Neo4j unavailable — cannot query related emails: %s", str(exc)
        )
        return empty_result
    except Exception as exc:
        logger.warning(
            "Unexpected error querying related emails: %s", str(exc)
        )
        return empty_result


def _shape_node_from_labels(eid: str, labels: list[str], props: dict[str, Any]) -> dict[str, Any] | None:
    """Shape a Neo4j node record into the frontend graph-node schema.

    Returns None for label sets that don't match any known type — the caller
    should skip those rows.
    """
    if "Email" in labels:
        analyzed_at = props.get("analyzed_at")
        if analyzed_at is not None and hasattr(analyzed_at, "isoformat"):
            analyzed_at = analyzed_at.isoformat()
        elif analyzed_at is not None:
            analyzed_at = str(analyzed_at)
        return {
            "id": props.get("id", eid),
            "label": props.get("subject", "Email"),
            "type": "email",
            "verdict": props.get("verdict"),
            "risk_score": props.get("risk_score"),
            "subject": props.get("subject"),
            "sender": props.get("sender"),
            "analyzed_at": analyzed_at,
        }
    if "IP" in labels:
        addr = props.get("address", eid)
        return {"id": addr, "label": addr, "type": "ip", "verdict": None}
    if "Domain" in labels:
        name = props.get("name", eid)
        return {"id": name, "label": name, "type": "domain", "verdict": None}
    if "UPI" in labels:
        upi_id = props.get("id", eid)
        return {"id": upi_id, "label": f"UPI: {upi_id}", "type": "upi", "verdict": None}
    if "Wallet" in labels:
        addr = props.get("address", eid)
        short_addr = f"{addr[:6]}...{addr[-4:]}" if len(addr) > 12 else addr
        return {"id": addr, "label": f"Wallet: {short_addr}", "type": "wallet", "verdict": None}
    if "AttachmentHash" in labels:
        h = props.get("hash", eid)
        return {
            "id": h,
            "label": f"File: {h[:8]}..." if len(h) > 8 else h,
            "type": "attachment_hash",
            "verdict": None,
        }
    if "TemplateHash" in labels:
        h = props.get("hash", eid)
        return {
            "id": h,
            "label": f"Tmpl: {h[:8]}..." if len(h) > 8 else h,
            "type": "template_hash",
            "verdict": None,
        }
    return None


def _shape_graph_from_records(records) -> dict[str, Any]:
    """Convert Neo4j records with (eid, labels, props, rel_start, rel_end, rel_type)
    into the {nodes, edges} shape the frontend expects.
    """
    nodes_map: dict[str, dict[str, Any]] = {}
    edges_set: set[tuple[str, str, str]] = set()

    for record in records:
        eid = record["eid"]
        labels = record["node_labels"]
        props = record["node_props"]

        if eid not in nodes_map:
            shaped = _shape_node_from_labels(eid, labels, props)
            if shaped is None:
                continue
            nodes_map[eid] = shaped

        rel_start = record.get("rel_start_eid")
        rel_end = record.get("rel_end_eid")
        rel_type = record.get("rel_type")
        if rel_start and rel_end and rel_type:
            edges_set.add((rel_start, rel_end, rel_type))

    eid_to_id = {eid: node["id"] for eid, node in nodes_map.items()}
    edges = []
    for start_eid, end_eid, rel_type in edges_set:
        source = eid_to_id.get(start_eid)
        target = eid_to_id.get(end_eid)
        if source and target:
            edges.append({"source": source, "target": target, "type": rel_type})

    return {"nodes": list(nodes_map.values()), "edges": edges}


def get_graph_for_visualization(
    email_hash: str | None = None,
    depth: int = 2,
    email_hashes: list[str] | None = None,
) -> dict[str, Any]:
    """Return nodes and edges for frontend graph rendering.

    Supports querying for a single email_hash or a batch of email_hashes.
    Uses variable-length path matching up to the given depth.

    Returns:
        {
            "nodes": [{"id": str, "label": str, "type": "email"|"ip"|"domain"|"upi"|"wallet"|"attachment_hash"|"template_hash",
                        "verdict": str | None}, ...],
            "edges": [{"source": str, "target": str, "type": str}, ...]
        }
    """
    empty_result: dict[str, Any] = {"nodes": [], "edges": []}

    target_hashes: list[str] = []
    if email_hashes:
        target_hashes.extend(email_hashes)
    if email_hash and email_hash not in target_hashes:
        target_hashes.append(email_hash)

    if not target_hashes:
        return empty_result

    try:
        driver = get_driver()
        with driver.session() as session:
            # Clamp depth between 1 and 4 for safety
            safe_depth = max(1, min(depth, 4))

            result = session.run(
                f"""
                MATCH (e:Email)
                WHERE e.id IN $hashes
                OPTIONAL MATCH path = (e)-[*1..{safe_depth}]-(connected)
                UNWIND (CASE WHEN path IS NULL THEN [e] ELSE nodes(path) END) AS n
                UNWIND (CASE WHEN path IS NULL THEN [null] ELSE relationships(path) END) AS r
                RETURN DISTINCT
                    elementId(n) AS eid,
                    labels(n) AS node_labels,
                    properties(n) AS node_props,
                    elementId(startNode(r)) AS rel_start_eid,
                    elementId(endNode(r)) AS rel_end_eid,
                    type(r) AS rel_type
                """,
                hashes=target_hashes,
            )

            return _shape_graph_from_records(result)

    except (ServiceUnavailable, OSError, AuthError) as exc:
        logger.warning(
            "Neo4j unavailable — cannot build visualization graph: %s", str(exc)
        )
        return empty_result
    except Exception as exc:
        logger.warning(
            "Unexpected error building visualization graph: %s", str(exc)
        )
        return empty_result


def get_full_graph(limit: int = 100) -> dict[str, Any]:
    """Return the graph of the `limit` most recently analyzed emails and their indicators.

    Uses the same node/edge shaping as `get_graph_for_visualization`; ordering by
    `analyzed_at` matches `list_investigations()` for cross-view consistency.
    """
    empty_result: dict[str, Any] = {"nodes": [], "edges": []}
    safe_limit = max(1, min(int(limit or 100), 500))

    try:
        driver = get_driver()
        with driver.session() as session:
            result = session.run(
                """
                MATCH (root:Email)
                WITH root
                ORDER BY root.analyzed_at DESC
                LIMIT $limit
                OPTIONAL MATCH path = (root)-[*1..2]-(connected)
                UNWIND (CASE WHEN path IS NULL THEN [root] ELSE nodes(path) END) AS n
                UNWIND (CASE WHEN path IS NULL THEN [null] ELSE relationships(path) END) AS r
                RETURN DISTINCT
                    elementId(n) AS eid,
                    labels(n) AS node_labels,
                    properties(n) AS node_props,
                    elementId(startNode(r)) AS rel_start_eid,
                    elementId(endNode(r)) AS rel_end_eid,
                    type(r) AS rel_type
                """,
                limit=safe_limit,
            )
            return _shape_graph_from_records(result)

    except (ServiceUnavailable, OSError, AuthError) as exc:
        logger.warning("Neo4j unavailable — cannot build full graph: %s", str(exc))
        return empty_result
    except Exception as exc:
        logger.warning("Unexpected error building full graph: %s", str(exc))
        return empty_result


def compute_clusters(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Find connected components in the {nodes, edges} graph and summarize
    those containing 2+ Email nodes.

    Pure in-memory union-find over the given edge list — no Neo4j or GDS
    dependency. Component ordering is deterministic: by descending
    highest_risk_score, then by member email count, then by cluster_id.
    """
    if not nodes:
        return []

    parent: dict[str, str] = {n["id"]: n["id"] for n in nodes}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for e in edges or []:
        s = e.get("source")
        t = e.get("target")
        if s in parent and t in parent:
            union(s, t)

    # Group node dicts by component root
    components: dict[str, list[dict[str, Any]]] = {}
    for n in nodes:
        root = find(n["id"])
        components.setdefault(root, []).append(n)

    clusters: list[dict[str, Any]] = []
    for comp_nodes in components.values():
        emails = [n for n in comp_nodes if n.get("type") == "email"]
        if len(emails) < 2:
            continue

        def _risk(n: dict[str, Any]) -> int:
            try:
                return int(n.get("risk_score") or 0)
            except (TypeError, ValueError):
                return 0

        top = max(emails, key=_risk)
        clusters.append({
            "email_count": len(emails),
            "highest_risk_score": _risk(top),
            "representative_subject": top.get("subject") or top.get("label") or "(No Subject)",
            "member_email_ids": [n["id"] for n in emails],
        })

    clusters.sort(
        key=lambda c: (-c["highest_risk_score"], -c["email_count"], c["representative_subject"])
    )
    for idx, cluster in enumerate(clusters, start=1):
        cluster["cluster_id"] = f"CLU-{idx:02d}"

    # Move cluster_id to the front for readability in JSON payloads
    return [
        {
            "cluster_id": c["cluster_id"],
            "email_count": c["email_count"],
            "highest_risk_score": c["highest_risk_score"],
            "representative_subject": c["representative_subject"],
            "member_email_ids": c["member_email_ids"],
        }
        for c in clusters
    ]


def get_attachment_intelligence(email_hashes: list[str]) -> dict[str, Any]:
    """Query Neo4j for attachment reuse across a set of analyzed emails.

    Returns reused attachments (seen in 2+ emails) with distinct filenames per hash,
    plus aggregate counts: total instances, unique hashes, and reused hashes.

    Returns:
        {
            "reused_attachments": [
                {
                    "hash": str,
                    "filenames": [str, ...],
                    "seen_in_count": int,
                    "emails": [{"id": str, "subject": str, "verdict": str}, ...]
                },
                ...
            ],
            "total_attachments": int,
            "total_unique_attachments": int,
            "total_reused": int,
        }
    """
    empty_result: dict[str, Any] = {
        "reused_attachments": [],
        "total_attachments": 0,
        "total_unique_attachments": 0,
        "total_reused": 0,
    }

    if not email_hashes:
        return empty_result

    try:
        driver = get_driver()
        with driver.session() as session:
            result = session.run(
                """
                MATCH (e:Email)-[c:CONTAINS]->(a:AttachmentHash)
                WHERE e.id IN $hashes
                WITH a.hash AS hash,
                     COLLECT(DISTINCT e) AS emails,
                     COLLECT(DISTINCT c.filename) AS raw_filenames
                RETURN hash,
                       [em IN emails | {id: em.id, subject: em.subject, verdict: em.verdict}] AS email_list,
                       SIZE(emails) AS seen_in_count,
                       [fn IN raw_filenames WHERE fn IS NOT NULL AND fn <> ''] AS filenames
                ORDER BY seen_in_count DESC
                """,
                hashes=email_hashes,
            )

            all_attachments: list[dict[str, Any]] = []
            total_instances = 0

            for record in result:
                seen_count = record["seen_in_count"]
                total_instances += seen_count
                all_attachments.append({
                    "hash": record["hash"],
                    "filenames": record["filenames"] or [],
                    "seen_in_count": seen_count,
                    "emails": record["email_list"] or [],
                })

            reused = [a for a in all_attachments if a["seen_in_count"] >= 2]

            return {
                "reused_attachments": reused,
                "total_attachments": total_instances,
                "total_unique_attachments": len(all_attachments),
                "total_reused": len(reused),
            }

    except (ServiceUnavailable, OSError, AuthError) as exc:
        logger.warning(
            "Neo4j unavailable — cannot query attachment intelligence: %s", str(exc)
        )
        return empty_result
    except Exception as exc:
        logger.warning(
            "Unexpected error querying attachment intelligence: %s", str(exc)
        )
        return empty_result
