"""Analysis and model metadata routes for TraceMail AI."""

from __future__ import annotations

import json
from collections import OrderedDict
from pathlib import Path
from typing import Any
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.core.config import settings
from app.db.history import save_investigation
from app.geo.geoip import geolocate_ip
from app.graph.neo4j_client import find_related_emails, save_analysis
from app.intel.virustotal import check_domain, check_ip
from app.ml.classifier import classify_text, explain_classification
from app.ml.risk_scoring import compute_risk
from app.parsing.email_parser import parse_email
from app.parsing.hops import extract_hops, get_originating_ip

router = APIRouter(tags=["Analysis"])

# In-memory LRU cache of recent analysis results (max 50 entries)
_RECENT_ANALYSES: OrderedDict[str, dict[str, Any]] = OrderedDict()
_MAX_CACHE_SIZE = 50


def get_cached_analysis(email_hash: str) -> dict[str, Any] | None:
    """Look up a recent analysis by email_hash."""
    return _RECENT_ANALYSES.get(email_hash)


def _cache_analysis(response: dict[str, Any]) -> None:
    """Cache an analysis result, evicting oldest if over limit."""
    email_hash = response.get("email_hash", "")
    if email_hash:
        _RECENT_ANALYSES[email_hash] = response
        _RECENT_ANALYSES.move_to_end(email_hash)
        while len(_RECENT_ANALYSES) > _MAX_CACHE_SIZE:
            _RECENT_ANALYSES.popitem(last=False)

MODEL_METADATA_PATH = Path(__file__).parent.parent / "ml" / "model" / "model_metadata.json"


class AnalyzeEmailRequest(BaseModel):
    """Schema for JSON raw email analysis request."""

    raw_email: str = Field(..., description="Raw RFC 822 email text string")


@router.get(
    "/model-info",
    summary="Get ML Model Metadata",
    description="Returns pre-trained model accuracy, dataset sources, training counts, and evaluation metrics.",
)
async def get_model_info() -> dict[str, Any]:
    """Return model metadata JSON verbatim."""
    if not MODEL_METADATA_PATH.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Model metadata file not found.",
        )
    try:
        content = MODEL_METADATA_PATH.read_text(encoding="utf-8")
        return json.loads(content)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read model metadata: {str(exc)}",
        ) from exc


def analyze_email_bytes(raw_bytes: bytes) -> dict[str, Any]:
    """Execute the full email forensic analysis pipeline on raw email bytes.

    Shared between single-email POST /api/analyze and batch POST /api/analyze/batch.
    """
    # 1. Parse standard headers, indicators, body, and authentication
    email_data = parse_email(raw_bytes)

    # 2. Extract received headers for hop analysis
    raw_received = email_data.get("raw_headers", {}).get("received", [])
    if isinstance(raw_received, str):
        raw_received = [raw_received]
    elif not isinstance(raw_received, list):
        raw_received = []

    hops = extract_hops(raw_received)
    originating_ip = get_originating_ip(hops)

    # 3. Sender Geolocation (MaxMind GeoIP2)
    origin_geo = geolocate_ip(originating_ip) if originating_ip else None

    # 4. Threat Intelligence (VirusTotal, top 5 domains + originating IP)
    ip_reputation = check_ip(originating_ip) if originating_ip else {"available": False}
    domain_reputations: dict[str, Any] = {}
    for dom in email_data.get("domains", [])[:5]:
        domain_reputations[dom] = check_domain(dom)

    threat_intel = {
        "originating_ip_reputation": ip_reputation,
        "domain_reputations": domain_reputations,
    }

    # 5. ML text classification
    ml_result = classify_text(
        subject=email_data.get("subject", ""),
        body=email_data.get("body_text", ""),
    )

    # 5b. ML explainability — top contributing phrases (read-only analysis of same model)
    top_phrases = explain_classification(
        subject=email_data.get("subject", ""),
        body=email_data.get("body_text", ""),
    )

    # 6. Composite risk scoring (incorporating threat intel)
    risk_result = compute_risk(
        parsed=email_data,
        ml_result=ml_result,
        threat_intel=threat_intel,
    )

    # 7. Build the response dict
    response = {
        **email_data,
        "hops": hops,
        "originating_ip": originating_ip,
        "origin_geo": origin_geo,
        "threat_intel": threat_intel,
        "ml_phishing_probability": risk_result["ml_phishing_probability"],
        "top_phrases": top_phrases,
        "risk_score": risk_result["risk_score"],
        "verdict": risk_result["verdict"],
        "indicators": list(risk_result["indicators"]),
    }

    # 8. Persist to Neo4j graph (fire-and-forget, never fails the response)
    save_analysis(response)

    # 9. Campaign detection — find related emails via shared infrastructure
    campaign = find_related_emails(response.get("email_hash", ""))
    response["campaign"] = campaign

    # 10. Boost risk score if part of a known campaign
    if campaign["campaign_size"] > 0:
        n = campaign["campaign_size"]
        response["indicators"].append(
            f"Sender infrastructure matches {n} other analyzed email(s) — part of a known campaign"
        )
        boosted_score = min(100, response["risk_score"] + 15)
        response["risk_score"] = boosted_score
        # Re-evaluate verdict after campaign boost
        if boosted_score >= 70:
            response["verdict"] = "Phishing/Scam"
        elif boosted_score >= 35:
            response["verdict"] = "Suspicious"

    # 11. Persist to SQLite investigation history
    save_investigation(response)

    # 12. Cache for chat explain lookups
    _cache_analysis(response)

    return response


@router.post(
    "/analyze",
    summary="Analyze an email for phishing and scam signals",
    response_description="Detailed forensic analysis including headers, hops, ML score, geolocation, and threat intel.",
)
async def analyze_email(request: Request) -> dict[str, Any]:
    """
    Accept an email via multipart file upload (recommended) or raw email text in a JSON body.
    Returns complete parsed headers, hop chain, threat intelligence, and risk assessment.
    """
    content_type = request.headers.get("content-type", "").lower()
    raw_bytes: bytes = b""

    if "multipart/form-data" in content_type:
        form = await request.form()
        file_obj = form.get("file")
        raw_email_field = form.get("raw_email")

        if file_obj and hasattr(file_obj, "read"):
            raw_bytes = await file_obj.read()
        elif isinstance(raw_email_field, str):
            raw_bytes = raw_email_field.encode("utf-8")
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No email file or raw_email field provided in multipart form.",
            )
    elif "application/json" in content_type:
        try:
            body_bytes = await request.body()
            if len(body_bytes) > settings.MAX_EMAIL_SIZE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail=f"Email payload exceeds maximum size of {settings.MAX_EMAIL_SIZE_BYTES} bytes.",
                )
            body = json.loads(body_bytes.decode("utf-8"))
            if not isinstance(body, dict) or "raw_email" not in body or not body["raw_email"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="JSON payload must contain a non-empty 'raw_email' string field.",
                )
            raw_bytes = body["raw_email"].encode("utf-8")
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON body.",
            )
    else:
        # Fallback to reading raw body directly
        body_bytes = await request.body()
        if body_bytes:
            raw_bytes = body_bytes
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported Content-Type or empty request body. Use multipart/form-data or application/json.",
            )

    # Size validation
    if len(raw_bytes) > settings.MAX_EMAIL_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Email payload size ({len(raw_bytes)} bytes) exceeds limit ({settings.MAX_EMAIL_SIZE_BYTES} bytes).",
        )

    if not raw_bytes.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provided email content is empty.",
        )

    try:
        return analyze_email_bytes(raw_bytes)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to parse email: {str(exc)}",
        ) from exc
