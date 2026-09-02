"""Batch email analysis API routes."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.api.routes_analyze import analyze_email_bytes
from app.core.config import settings
from app.graph.neo4j_client import get_graph_for_visualization

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Batch Analysis"])


def compute_cluster_count(combined_graph: dict[str, Any], batch_email_hashes: set[str]) -> int:
    """Calculate the number of multi-email connected components (clusters) across the batch.

    A campaign cluster is defined as a connected component in the graph containing
    at least 2 analyzed emails from the batch.
    """
    if len(batch_email_hashes) < 2:
        return 0

    adj: dict[str, set[str]] = {}
    for node in combined_graph.get("nodes", []):
        adj[node["id"]] = set()

    for edge in combined_graph.get("edges", []):
        u = edge.get("source")
        v = edge.get("target")
        if u and v:
            adj.setdefault(u, set()).add(v)
            adj.setdefault(v, set()).add(u)

    visited: set[str] = set()
    cluster_count = 0

    for email_id in batch_email_hashes:
        if email_id not in visited and email_id in adj:
            component: set[str] = set()
            queue = [email_id]
            visited.add(email_id)

            while queue:
                curr = queue.pop(0)
                component.add(curr)
                for neighbor in adj.get(curr, []):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)

            emails_in_comp = component.intersection(batch_email_hashes)
            if len(emails_in_comp) >= 2:
                cluster_count += 1

    return cluster_count


@router.post(
    "/analyze/batch",
    summary="Batch analyze multiple .eml files",
    response_description="Analysis results for each file, combined graph visualization, and detected campaign clusters.",
)
async def analyze_batch(
    files: list[UploadFile] = File(...),
) -> dict[str, Any]:
    """Analyze multiple .eml complaint files simultaneously.

    Persists each email to Neo4j and SQLite, detects campaign links across the batch,
    and returns a combined network visualization and cluster count.
    """
    if not files:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No files provided in batch upload.",
        )

    if len(files) > settings.MAX_BATCH_FILES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Batch file count ({len(files)}) exceeds maximum limit of {settings.MAX_BATCH_FILES} files.",
        )

    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    analyzed_hashes: list[str] = []

    for upload_file in files:
        filename = upload_file.filename or "unknown.eml"
        try:
            raw_bytes = await upload_file.read()

            if len(raw_bytes) > settings.MAX_EMAIL_SIZE_BYTES:
                errors.append({
                    "filename": filename,
                    "error": f"File size ({len(raw_bytes)} bytes) exceeds limit ({settings.MAX_EMAIL_SIZE_BYTES} bytes).",
                })
                continue

            if not raw_bytes.strip():
                errors.append({
                    "filename": filename,
                    "error": "File content is empty.",
                })
                continue

            analysis = analyze_email_bytes(raw_bytes)
            # Tag original filename for easier UI mapping
            analysis["filename"] = filename
            results.append(analysis)

            ehash = analysis.get("email_hash")
            if ehash:
                analyzed_hashes.append(ehash)

        except Exception as exc:
            logger.warning("Failed analyzing '%s' in batch: %s", filename, str(exc))
            errors.append({
                "filename": filename,
                "error": str(exc),
            })

    # Query multi-root graph visualization across all analyzed emails
    combined_graph = {"nodes": [], "edges": []}
    cluster_count = 0

    if analyzed_hashes:
        combined_graph = get_graph_for_visualization(
            email_hashes=analyzed_hashes,
            depth=2,
        )
        cluster_count = compute_cluster_count(
            combined_graph=combined_graph,
            batch_email_hashes=set(analyzed_hashes),
        )

    return {
        "results": results,
        "errors": errors,
        "combined_graph": combined_graph,
        "cluster_count": cluster_count,
    }
