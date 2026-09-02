"""Raw email parsing and indicator extraction module."""

from __future__ import annotations

import email
from email import policy
from email.utils import parseaddr
import hashlib
import html
import re
from typing import Any
from urllib.parse import urlparse

from app.parsing.fingerprints import extract_fingerprints

SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".ps1",
    ".iso",
    ".jar",
}

URL_REGEX = re.compile(r'https?://[^\s<>"\'\)\]]+', re.IGNORECASE)
HTML_TAG_REGEX = re.compile(r"<[^>]+>")


def _extract_domain(header_value: str | None) -> tuple[str, str]:
    """Extract full string and domain from an email header value."""
    if not header_value:
        return "", ""
    raw_str = str(header_value).strip()
    _, addr = parseaddr(raw_str)
    addr = addr.strip()
    if "@" in addr:
        domain = addr.split("@")[-1].strip().lower()
        return raw_str, domain

    # Fallback if parseaddr failed but @ exists in string
    if "@" in raw_str:
        match = re.search(r"[\w\.-]+@([\w\.-]+\.[a-zA-Z]{2,})", raw_str)
        if match:
            return raw_str, match.group(1).lower()

    return raw_str, ""


def _clean_url(raw_url: str) -> str:
    """Strip common trailing punctuation from captured URLs."""
    url = raw_url.rstrip(".,;!?:")
    return url


def _extract_body_and_html(msg: email.message.EmailMessage) -> tuple[str, str]:
    """Extract plain text and raw HTML from email parts."""
    plain_parts: list[str] = []
    html_parts: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            # Skip container multipart parts and attachments
            if part.is_multipart() or part.get_content_disposition() == "attachment":
                continue

            content_type = part.get_content_type()
            try:
                content = part.get_content()
                if not isinstance(content, str):
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or "utf-8"
                    content = payload.decode(charset, errors="replace") if payload else ""
            except Exception:
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or "utf-8"
                content = payload.decode(charset, errors="replace") if payload else ""

            if content_type == "text/plain":
                plain_parts.append(content)
            elif content_type == "text/html":
                html_parts.append(content)
    else:
        content_type = msg.get_content_type()
        try:
            content = msg.get_content()
            if not isinstance(content, str):
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or "utf-8"
                content = payload.decode(charset, errors="replace") if payload else ""
        except Exception:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or "utf-8"
            content = payload.decode(charset, errors="replace") if payload else ""

        if content_type == "text/plain":
            plain_parts.append(content)
        elif content_type == "text/html":
            html_parts.append(content)

    raw_html = "\n".join(html_parts) if html_parts else ""

    if plain_parts:
        body = "\n".join(plain_parts)
    elif html_parts:
        # Strip HTML tags and unescape entities
        stripped = HTML_TAG_REGEX.sub(" ", raw_html)
        body = html.unescape(stripped)
        # Normalize whitespace
        body = re.sub(r"[ \t]+", " ", body)
        body = re.sub(r"\n\s*\n", "\n\n", body).strip()
    else:
        body = ""

    # Truncate to 8000 characters
    return body[:8000], raw_html


def _extract_body(msg: email.message.EmailMessage) -> str:
    """Extract plain text or stripped HTML from email parts."""
    body, _ = _extract_body_and_html(msg)
    return body


def _extract_authentication(msg: email.message.EmailMessage) -> dict[str, str]:
    """Parse Authentication-Results headers for SPF, DKIM, and DMARC results."""
    auth_headers = msg.get_all("Authentication-Results", [])
    combined_auth = " ".join(str(h) for h in auth_headers)

    spf_match = re.search(r"spf=([a-zA-Z0-9_-]+)", combined_auth, re.IGNORECASE)
    dkim_match = re.search(r"dkim=([a-zA-Z0-9_-]+)", combined_auth, re.IGNORECASE)
    dmarc_match = re.search(r"dmarc=([a-zA-Z0-9_-]+)", combined_auth, re.IGNORECASE)

    # Fallback to Received-SPF header if SPF not found in Authentication-Results
    if not spf_match:
        received_spf = msg.get("Received-SPF", "")
        if received_spf:
            rec_spf_match = re.match(r"^([a-zA-Z0-9_-]+)", received_spf.strip(), re.IGNORECASE)
            if rec_spf_match:
                spf_match = rec_spf_match

    return {
        "spf": spf_match.group(1).lower() if spf_match else "unknown",
        "dkim": dkim_match.group(1).lower() if dkim_match else "unknown",
        "dmarc": dmarc_match.group(1).lower() if dmarc_match else "unknown",
    }


def parse_email(raw_bytes: bytes) -> dict[str, Any]:
    """
    Parse a raw email into a structured dictionary of headers, body, indicators,
    authentication results, and alignment checks.
    """
    email_hash = hashlib.sha256(raw_bytes).hexdigest()
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    subject = str(msg.get("subject", "") or "")
    sender_raw, sender_domain = _extract_domain(msg.get("from"))
    reply_to_raw, reply_to_domain = _extract_domain(msg.get("reply-to"))
    return_path_raw, return_path_domain = _extract_domain(msg.get("return-path"))
    to_val = str(msg.get("to", "") or "")
    date_val = str(msg.get("date", "") or "")
    message_id = str(msg.get("message-id", "") or "")

    body_text, html_body = _extract_body_and_html(msg)

    # Extract and deduplicate URLs
    raw_urls = URL_REGEX.findall(body_text)
    urls: list[str] = []
    domains: list[str] = []
    seen_urls: set[str] = set()
    seen_domains: set[str] = set()

    for u in raw_urls:
        cleaned_u = _clean_url(u)
        if cleaned_u and cleaned_u not in seen_urls:
            seen_urls.add(cleaned_u)
            urls.append(cleaned_u)
            parsed = urlparse(cleaned_u)
            netloc = parsed.netloc.split(":")[0].lower()
            if netloc and netloc not in seen_domains:
                seen_domains.add(netloc)
                domains.append(netloc)

    # Extract attachments and collect raw bytes for fingerprinting
    attachments: list[str] = []
    suspicious_attachments: list[str] = []
    attachments_raw: list[bytes] = []

    for part in msg.walk():
        fn = part.get_filename()
        is_attachment = part.get_content_disposition() == "attachment" or bool(fn)
        if is_attachment:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes) and payload:
                attachments_raw.append(payload)

        if fn:
            fn_clean = str(fn).strip()
            attachments.append(fn_clean)
            if any(fn_clean.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
                suspicious_attachments.append(fn_clean)

    # Extract financial and technical fingerprints (Phase 9 - additive)
    fingerprints = extract_fingerprints(
        body_text=body_text,
        urls=urls,
        attachments_raw=attachments_raw,
        html_body=html_body,
    )

    # Authentication
    authentication = _extract_authentication(msg)

    # Domain alignment check
    reply_to_mismatch = bool(sender_domain and reply_to_domain and sender_domain != reply_to_domain)
    return_path_mismatch = bool(sender_domain and return_path_domain and sender_domain != return_path_domain)

    # Raw headers mapping (lowercased keys)
    raw_headers: dict[str, Any] = {}
    for key, value in msg.items():
        k = key.lower()
        if k in raw_headers:
            if isinstance(raw_headers[k], list):
                raw_headers[k].append(str(value))
            else:
                raw_headers[k] = [raw_headers[k], str(value)]
        else:
            raw_headers[k] = str(value)

    return {
        "email_hash": email_hash,
        "subject": subject,
        "sender": sender_raw,
        "sender_domain": sender_domain,
        "reply_to": reply_to_raw,
        "reply_to_domain": reply_to_domain,
        "return_path": return_path_raw,
        "return_path_domain": return_path_domain,
        "to": to_val,
        "date": date_val,
        "message_id": message_id,
        "body_text": body_text,
        "urls": urls,
        "domains": domains,
        "attachments": attachments,
        "suspicious_attachments": suspicious_attachments,
        "authentication": authentication,
        "domain_mismatches": {
            "reply_to_mismatch": reply_to_mismatch,
            "return_path_mismatch": return_path_mismatch,
        },
        "raw_headers": raw_headers,
        # Fingerprints (Phase 9 - additive)
        "upi_ids": fingerprints["upi_ids"],
        "wallet_addresses": fingerprints["wallet_addresses"],
        "possible_bank_accounts": fingerprints["possible_bank_accounts"],
        "attachment_hashes": fingerprints["attachment_hashes"],
        "template_structure_hash": fingerprints["template_structure_hash"],
    }
