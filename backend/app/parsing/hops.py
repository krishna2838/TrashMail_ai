"""Email Received header forensic analysis and hop reconstruction."""

from __future__ import annotations

import email.utils
import ipaddress
import re
from typing import Any

# Regex patterns for parsing Received headers
FROM_CLAUSE_REGEX = re.compile(r"\bfrom\s+([^\s;()]+)(?:\s*\(([^;]*?)\))?", re.IGNORECASE)
BY_CLAUSE_REGEX = re.compile(r"\bby\s+([^\s;()]+)", re.IGNORECASE)
IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
IPV6_REGEX = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b|(?:\b[0-9a-fA-F]{1,4})?::[0-9a-fA-F]{0,4}\b"
)
BRACKETED_IP_REGEX = re.compile(r"\[([0-9a-fA-F:\.]+)\]")


def _is_valid_ip(candidate: str) -> bool:
    """Check if candidate string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(candidate.strip())
        return True
    except ValueError:
        return False


def _check_public_ip(ip_str: str | None) -> bool:
    """
    Determine if IP address is a publicly routable address.
    Filters out RFC1918 private, loopback, link-local, unspecified, and multicast.
    """
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_unspecified
            or ip.is_multicast
        )
    except ValueError:
        return False


def _extract_ip_from_text(text: str) -> str | None:
    """Extract first valid IPv4 or IPv6 address from a text snippet."""
    if not text:
        return None

    # First check bracketed IPs e.g. [192.0.2.1]
    for match in BRACKETED_IP_REGEX.findall(text):
        if _is_valid_ip(match):
            return match.strip()

    # Search for IPv4
    for match in IPV4_REGEX.findall(text):
        if _is_valid_ip(match):
            return match.strip()

    # Search for IPv6
    for match in IPV6_REGEX.findall(text):
        if _is_valid_ip(match):
            return match.strip()

    return None


def _parse_single_hop(raw_header: str) -> dict[str, Any]:
    """Parse a single Received header line into its forensic components."""
    # Normalize whitespace
    raw_cleaned = " ".join(raw_header.split())

    from_host: str | None = None
    from_ip: str | None = None
    by_host: str | None = None
    timestamp: str | None = None

    # Date is typically after the last semicolon
    if ";" in raw_cleaned:
        clause_part, date_part = raw_cleaned.rsplit(";", 1)
        date_str = date_part.strip()
        # Clean trailing comments e.g. (UTC)
        clean_date_str = re.sub(r"\s*\([^\)]*\)\s*$", "", date_str).strip()
        try:
            parsed_dt = email.utils.parsedate_to_datetime(clean_date_str or date_str)
            timestamp = parsed_dt.isoformat()
        except Exception:
            # Fallback to keeping the raw date string
            timestamp = date_str if date_str else None
    else:
        clause_part = raw_cleaned

    # Extract 'from' host and parenthesized info
    from_match = FROM_CLAUSE_REGEX.search(clause_part)
    if from_match:
        from_host = from_match.group(1).strip("[] \t")
        paren_info = from_match.group(2) or ""

        # Look for IP in parenthesized section first (more authoritative)
        from_ip = _extract_ip_from_text(paren_info)

        # If from_host itself is an IP
        if not from_ip and _is_valid_ip(from_host):
            from_ip = from_host

    # If no IP found yet, scan the clause before 'by' or entire clause for any IP
    if not from_ip:
        by_idx = clause_part.lower().find("by ")
        search_section = clause_part[:by_idx] if by_idx != -1 else clause_part
        from_ip = _extract_ip_from_text(search_section)

    # If from_host is still None, scan for any hostname after 'from'
    if not from_host:
        simple_from = re.search(r"\bfrom\s+([^\s;()]+)", clause_part, re.IGNORECASE)
        if simple_from:
            from_host = simple_from.group(1).strip("[] \t")

    # Extract 'by' host
    by_match = BY_CLAUSE_REGEX.search(clause_part)
    if by_match:
        by_host = by_match.group(1).strip("[] \t")

    is_public = _check_public_ip(from_ip)

    return {
        "from_host": from_host,
        "from_ip": from_ip,
        "by_host": by_host,
        "timestamp": timestamp,
        "is_public_ip": is_public,
        "raw": raw_cleaned,
    }


def extract_hops(raw_headers_multi: list[str]) -> list[dict[str, Any]]:
    """
    Parse a list of Received header strings into structured hops,
    ordered chronologically (oldest / originating hop first).
    """
    if not raw_headers_multi:
        return []

    parsed_hops: list[dict[str, Any]] = []

    # Received headers in raw emails are prepended newest-first.
    # Reversing gives chronological order (oldest first).
    chronological_headers = list(reversed(raw_headers_multi))

    for idx, header_text in enumerate(chronological_headers, start=1):
        if not header_text:
            continue
        hop_data = _parse_single_hop(header_text)
        hop_data["sequence"] = idx
        parsed_hops.append(hop_data)

    return parsed_hops


def get_originating_ip(hops: list[dict[str, Any]]) -> str | None:
    """
    Return the first public IP encountered when walking hops from oldest to newest.
    Returns None if no public IP is found.
    """
    for hop in hops:
        ip = hop.get("from_ip")
        if ip and hop.get("is_public_ip"):
            return str(ip)
    return None
