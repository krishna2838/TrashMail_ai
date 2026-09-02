"""Graph query API routes for TraceMail AI campaign visualization."""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter

from app.graph.neo4j_client import find_related_emails, get_graph_for_visualization

router = APIRouter(tags=["Graph"])


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
