"""Chat assistant API routes — explain findings and freeform scam check."""

from __future__ import annotations

from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.api.routes_analyze import get_cached_analysis
from app.chat.ollama_client import OllamaUnavailableError, ask_ollama
from app.chat.prompts import build_explain_prompt, build_freeform_prompt

router = APIRouter(tags=["Chat"])


class ExplainRequest(BaseModel):
    """Request body for the explain endpoint."""

    email_hash: Optional[str] = Field(
        None, description="Hash of a recently analyzed email to explain."
    )
    analysis: Optional[Dict[str, Any]] = Field(
        None,
        description="Full analysis JSON (alternative to email_hash if the analysis isn't cached).",
    )



class FreeformRequest(BaseModel):
    """Request body for the freeform scam check endpoint."""

    message: str = Field(..., description="Text to analyze for scam/phishing indicators.")
    context: Optional[Dict[str, Any]] = Field(
        None, description="Optional current email or batch analysis context to guide the assistant."
    )


@router.post(
    "/chat/explain",
    summary="Explain Email Analysis",
    description=(
        "Given an email_hash (from a recent /api/analyze call) or a full analysis JSON, "
        "returns a plain-language explanation of the findings from the local Ollama LLM."
    ),
)
async def chat_explain(body: ExplainRequest) -> dict[str, str]:
    """Explain an email analysis in plain language using the local LLM."""
    analysis: dict[str, Any] | None = None

    # Try email_hash lookup first
    if body.email_hash:
        analysis = get_cached_analysis(body.email_hash)

    # Fall back to provided analysis dict
    if analysis is None and body.analysis:
        analysis = body.analysis

    if analysis is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Analysis not found. Provide a valid email_hash from a recent analysis, "
                "or include the full analysis JSON in the 'analysis' field."
            ),
        )

    system, prompt = build_explain_prompt(analysis)

    try:
        explanation = await ask_ollama(prompt, system)
        return {"explanation": explanation}
    except OllamaUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc


@router.post(
    "/chat/ask",
    summary="Freeform Scam Check",
    description=(
        "Paste any text (email snippet, message, etc.) and get a scam/phishing analysis "
        "from the local Ollama LLM."
    ),
)
async def chat_ask(body: FreeformRequest) -> dict[str, str]:
    """Analyze freeform text for scam/phishing indicators using the local LLM."""
    if not body.message.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message cannot be empty.",
        )

    system, prompt = build_freeform_prompt(body.message, context=body.context)

    try:
        response_text = await ask_ollama(prompt, system)
        return {"response": response_text}
    except OllamaUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
