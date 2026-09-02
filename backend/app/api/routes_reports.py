"""Forensic PDF report API routes for TrashMail AI."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response, status

from app.api.routes_analyze import get_cached_analysis
from app.db.history import get_investigation
from app.reports.pdf_report import generate_report

router = APIRouter(tags=["Reports"])


@router.get(
    "/reports/{email_hash}.pdf",
    summary="Download Forensic PDF Report",
    description="Generate and download a comprehensive forensic PDF report for an analyzed email.",
    response_class=Response,
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "Returns the generated forensic analysis PDF document.",
        },
        404: {"description": "Investigation or email hash not found."},
    },
)
async def get_forensic_report(email_hash: str) -> Response:
    """Generate and stream PDF report for the given email_hash."""
    # First, look up from persistent SQLite investigation history
    analysis = get_investigation(email_hash)

    # Fall back to in-memory recent cache if SQLite record is pending or in-flight
    if not analysis:
        analysis = get_cached_analysis(email_hash)

    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Forensic investigation with hash '{email_hash}' not found.",
        )

    try:
        pdf_bytes = generate_report(analysis)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate forensic PDF report: {str(exc)}",
        ) from exc

    short_hash = email_hash[:8] if len(email_hash) >= 8 else email_hash
    filename = f"trashmail-report-{short_hash}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Type": "application/pdf",
        },
    )
