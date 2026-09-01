"""Graph persistence package — Neo4j client for campaign clustering."""

from __future__ import annotations

from app.graph.neo4j_client import (
    find_related_emails,
    get_graph_for_visualization,
    save_analysis,
)

__all__ = ["save_analysis", "find_related_emails", "get_graph_for_visualization"]
