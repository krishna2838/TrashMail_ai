"""VirusTotal API v3 client with in-memory caching and free-tier rate limiting."""

from __future__ import annotations

import base64
import time
from typing import Any
import httpx

from app.core.config import settings

VT_BASE_URL = "https://www.virustotal.com/api/v3"
RATE_LIMIT_WINDOW = 60.0  # seconds
MAX_REQUESTS_PER_WINDOW = 4

# In-memory IOC cache: key -> dict
_IOC_CACHE: dict[str, dict[str, Any]] = {}
_REQUEST_TIMESTAMPS: list[float] = []


def _wait_for_rate_limit() -> None:
    """Enforce VirusTotal free-tier rate limit (max 4 requests per 60s window)."""
    global _REQUEST_TIMESTAMPS
    now = time.time()
    _REQUEST_TIMESTAMPS = [t for t in _REQUEST_TIMESTAMPS if now - t < RATE_LIMIT_WINDOW]

    if len(_REQUEST_TIMESTAMPS) >= MAX_REQUESTS_PER_WINDOW:
        oldest = _REQUEST_TIMESTAMPS[0]
        sleep_duration = max(0.0, (oldest + RATE_LIMIT_WINDOW) - now + 0.5)
        if sleep_duration > 0:
            time.sleep(sleep_duration)

    _REQUEST_TIMESTAMPS.append(time.time())


def _query_vt_api(endpoint: str) -> dict[str, Any]:
    """Execute a single query to VirusTotal API v3 with rate limit and retry handling."""
    api_key = settings.VIRUSTOTAL_API_KEY.strip()
    if not api_key:
        return {"available": False}

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }
    url = f"{VT_BASE_URL}/{endpoint}"

    for attempt in range(2):
        _wait_for_rate_limit()
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    stats = (
                        data.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {})
                    )
                    malicious = int(stats.get("malicious", 0))
                    suspicious = int(stats.get("suspicious", 0))
                    harmless = int(stats.get("harmless", 0))
                    undetected = int(stats.get("undetected", 0))

                    if malicious > 0:
                        reputation = "malicious"
                    elif suspicious > 3:
                        reputation = "suspicious"
                    else:
                        reputation = "clean"

                    return {
                        "available": True,
                        "reputation": reputation,
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "undetected": undetected,
                        "total_vendors": malicious + suspicious + harmless + undetected,
                    }
                elif resp.status_code == 404:
                    # Entity not seen/indexed in VirusTotal -> treat as unflagged
                    return {
                        "available": True,
                        "reputation": "clean",
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 0,
                        "undetected": 0,
                        "total_vendors": 0,
                    }
                elif resp.status_code == 429 and attempt == 0:
                    # Rate limited: back off for 60s and retry once
                    time.sleep(60.0)
                    continue
                else:
                    return {"available": False}
        except Exception:
            return {"available": False}

    return {"available": False}


def check_ip(ip: str | None) -> dict[str, Any]:
    """Check IP address reputation on VirusTotal."""
    if not ip or not isinstance(ip, str):
        return {"available": False}

    clean_ip = ip.strip()
    cache_key = f"ip:{clean_ip}"
    if cache_key in _IOC_CACHE:
        return _IOC_CACHE[cache_key]

    result = _query_vt_api(f"ip_addresses/{clean_ip}")
    _IOC_CACHE[cache_key] = result
    return result


def check_domain(domain: str | None) -> dict[str, Any]:
    """Check domain reputation on VirusTotal."""
    if not domain or not isinstance(domain, str):
        return {"available": False}

    clean_domain = domain.strip().lower()
    cache_key = f"domain:{clean_domain}"
    if cache_key in _IOC_CACHE:
        return _IOC_CACHE[cache_key]

    result = _query_vt_api(f"domains/{clean_domain}")
    _IOC_CACHE[cache_key] = result
    return result


def check_url(url: str | None) -> dict[str, Any]:
    """
    Check URL reputation on VirusTotal.
    URL must be base64-urlsafe-encoded without trailing '=' padding per VT spec.
    """
    if not url or not isinstance(url, str):
        return {"available": False}

    clean_url = url.strip()
    cache_key = f"url:{clean_url}"
    if cache_key in _IOC_CACHE:
        return _IOC_CACHE[cache_key]

    # Base64 urlsafe encode without padding
    url_id = base64.urlsafe_b64encode(clean_url.encode("utf-8")).decode("utf-8").rstrip("=")
    result = _query_vt_api(f"urls/{url_id}")
    _IOC_CACHE[cache_key] = result
    return result
