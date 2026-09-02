"""Investigation history API routes for TraceMail AI."""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Query, status

from app.db.history import get_investigation, list_investigations

router = APIRouter(tags=["History"])


@router.get(
    "/history",
    summary="List Recent Investigations",
    description="Returns a lightweight list of past email analyses sorted by recency.",
)
async def get_history(
    limit: int = Query(50, ge=1, le=100, description="Max investigations to return")
) -> list[dict[str, Any]]:
    """Return recent email investigations from SQLite."""
    return list_investigations(limit=limit)


@router.get(
    "/history/{id}",
    summary="Get Detailed Investigation by Hash",
    description="Returns the full JSON forensic analysis result for a past email hash.",
)
async def get_history_item(id: str) -> dict[str, Any]:
    """Retrieve full analysis result by email_hash."""
    result = get_investigation(id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with hash '{id}' not found.",
        )
    return result
