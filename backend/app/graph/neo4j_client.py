"""Neo4j graph client for persisting and querying email analysis graphs.

Graph schema:
  (:Email {id, subject, sender, verdict, risk_score, analyzed_at})
  (:IP    {address, country, city, asn_org})
  (:Domain {name})

  (:Email)-[:ORIGINATED_FROM]->(:IP)
  (:Email)-[:LINKS_TO]->(:Domain)

All IP/Domain nodes use MERGE to avoid duplicates across analyses.
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

    Creates/merges Email, IP, and Domain nodes with appropriate relationships.
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

        with driver.session() as session:
            # Build a single Cypher query to persist everything atomically
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

            # Handle domains with UNWIND for efficiency
            if domains:
                cypher_parts.append(
                    "WITH e "
                    "UNWIND $domains AS domain_name "
                    "MERGE (d:Domain {name: domain_name}) "
                    "MERGE (e)-[:LINKS_TO]->(d)"
                )
                params["domains"] = list(domains)

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


def find_related_emails(email_hash: str) -> dict[str, Any]:
    """Find other emails connected via a shared IP or Domain node (2-hop pattern).

    Returns:
        {
            "related_emails": [
                {"id": str, "subject": str, "verdict": str,
                 "shared_via": "ip"|"domain", "shared_value": str},
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
                MATCH (e1:Email {id: $id})-[r1]-(shared)-[r2]-(e2:Email)
                WHERE e1 <> e2
                RETURN DISTINCT
                    e2.id AS id,
                    e2.subject AS subject,
                    e2.verdict AS verdict,
                    CASE
                        WHEN 'IP' IN labels(shared) THEN 'ip'
                        WHEN 'Domain' IN labels(shared) THEN 'domain'
                        ELSE 'unknown'
                    END AS shared_via,
                    CASE
                        WHEN 'IP' IN labels(shared) THEN shared.address
                        WHEN 'Domain' IN labels(shared) THEN shared.name
                        ELSE ''
                    END AS shared_value
                """,
                id=email_hash,
            )
            related = []
            seen_ids: set[str] = set()
            for record in result:
                eid = record["id"]
                if eid not in seen_ids:
                    related.append({
                        "id": eid,
                        "subject": record["subject"],
                        "verdict": record["verdict"],
                        "shared_via": record["shared_via"],
                        "shared_value": record["shared_value"],
                    })
                    seen_ids.add(eid)

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


def get_graph_for_visualization(email_hash: str, depth: int = 2) -> dict[str, Any]:
    """Return nodes and edges for frontend graph rendering.

    Uses variable-length path matching up to the given depth.

    Returns:
        {
            "nodes": [{"id": str, "label": str, "type": "email"|"ip"|"domain",
                        "verdict": str | None}, ...],
            "edges": [{"source": str, "target": str, "type": str}, ...]
        }
    """
    empty_result: dict[str, Any] = {"nodes": [], "edges": []}

    try:
        driver = get_driver()
        with driver.session() as session:
            # Clamp depth between 1 and 4 for safety
            safe_depth = max(1, min(depth, 4))

            result = session.run(
                f"""
                MATCH path = (e:Email {{id: $id}})-[*1..{safe_depth}]-(connected)
                UNWIND nodes(path) AS n
                UNWIND relationships(path) AS r
                RETURN DISTINCT
                    elementId(n) AS eid,
                    labels(n) AS node_labels,
                    properties(n) AS node_props,
                    elementId(startNode(r)) AS rel_start_eid,
                    elementId(endNode(r)) AS rel_end_eid,
                    type(r) AS rel_type
                """,
                id=email_hash,
            )

            nodes_map: dict[str, dict[str, Any]] = {}
            edges_set: set[tuple[str, str, str]] = set()

            for record in result:
                # Process node
                eid = record["eid"]
                labels = record["node_labels"]
                props = record["node_props"]

                if eid not in nodes_map:
                    if "Email" in labels:
                        node_id = props.get("id", eid)
                        node_label = props.get("subject", "Email")
                        node_type = "email"
                        node_verdict = props.get("verdict")
                    elif "IP" in labels:
                        node_id = props.get("address", eid)
                        node_label = props.get("address", "IP")
                        node_type = "ip"
                        node_verdict = None
                    elif "Domain" in labels:
                        node_id = props.get("name", eid)
                        node_label = props.get("name", "Domain")
                        node_type = "domain"
                        node_verdict = None
                    else:
                        continue

                    nodes_map[eid] = {
                        "id": node_id,
                        "label": node_label,
                        "type": node_type,
                        "verdict": node_verdict,
                    }

                # Process relationship
                rel_start = record["rel_start_eid"]
                rel_end = record["rel_end_eid"]
                rel_type = record["rel_type"]
                edges_set.add((rel_start, rel_end, rel_type))

            # Convert edges from elementId references to our node ids
            eid_to_id = {eid: node["id"] for eid, node in nodes_map.items()}
            edges = []
            for start_eid, end_eid, rel_type in edges_set:
                source = eid_to_id.get(start_eid)
                target = eid_to_id.get(end_eid)
                if source and target:
                    edges.append({
                        "source": source,
                        "target": target,
                        "type": rel_type,
                    })

            return {
                "nodes": list(nodes_map.values()),
                "edges": edges,
            }

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
