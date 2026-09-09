"""Graph query API routes for TraceMail AI campaign visualization."""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Query

from app.graph.neo4j_client import (
    compute_clusters,
    find_related_emails,
    get_attachment_intelligence,
    get_full_graph,
    get_graph_for_visualization,
)
from app.reports.cluster_report import get_cluster_report

router = APIRouter(tags=["Graph"])


# Static routes MUST be declared before parameterized routes to avoid
# FastAPI matching e.g. "attachments" as an {email_hash} path parameter.

@router.get(
    "/graph/overview",
    summary="Cross-Database Graph Overview",
    description="Returns the full graph of recently analyzed emails plus computed clusters (connected components).",
)
async def graph_overview(limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    """Return nodes, edges, and clusters across the most recent analyses."""
    graph = get_full_graph(limit=limit)
    clusters = compute_clusters(graph.get("nodes", []), graph.get("edges", []))
    return {
        "nodes": graph.get("nodes", []),
        "edges": graph.get("edges", []),
        "clusters": clusters,
    }


@router.get(
    "/graph/report",
    summary="Cluster Report Aggregation",
    description="Aggregates a campaign-level report across the given cluster member email hashes.",
)
async def cluster_report(
    ids: str = Query(..., description="Comma-separated list of member email hashes."),
) -> dict[str, Any]:
    """Return the aggregated cluster report for the given member email IDs."""
    id_list = [h.strip() for h in ids.split(",") if h.strip()]
    return get_cluster_report(id_list)


@router.get(
    "/graph/attachments",
    summary="Attachment Intelligence",
    description="Returns reused attachments across a set of analyzed emails, with filenames and reuse counts.",
)
async def attachment_intelligence(
    hashes: str = Query(
        ...,
        description="Comma-separated list of email hashes to scope the query.",
    ),
) -> dict[str, Any]:
    """Return attachment reuse data for the given email hashes."""
    hash_list = [h.strip() for h in hashes.split(",") if h.strip()]
    return get_attachment_intelligence(hash_list)


@router.get(
    "/graph/{email_hash}",
    summary="Get Graph Visualization Data",
    description="Returns nodes and edges for rendering the email analysis graph in the frontend.",
)
async def get_graph(email_hash: str, depth: int = 2) -> dict[str, Any]:
    """Return graph nodes and edges for the given email hash."""
    return get_graph_for_visualization(email_hash, depth=depth)


@router.get(
    "/graph/{email_hash}/related",
    summary="Find Related Emails (Campaign Detection)",
    description="Finds other analyzed emails sharing the same originating IP or linked domains.",
)
async def get_related(email_hash: str) -> dict[str, Any]:
    """Return emails connected via shared infrastructure (IP or domain)."""
    return find_related_emails(email_hash)
