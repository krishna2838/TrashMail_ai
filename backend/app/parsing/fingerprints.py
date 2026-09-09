"""Financial and technical fingerprint extraction for TraceMail AI.

Extracts:
1. UPI IDs (banking and wallet handles, e.g. user@paytm, merchant@okhdfcbank)
2. Crypto wallet addresses (Bitcoin Bech32/Base58, Ethereum 0x...)
3. Possible bank account numbers (9-18 digits near banking keywords)
4. Attachment content hashes (SHA-256 of raw file bytes)
5. HTML template structural hash (SHA-256 of tag skeleton stripped of content & attributes)
"""

from __future__ import annotations

import hashlib
import html.parser
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

# Common email domains / TLDs to explicitly exclude from UPI extraction
EXCLUDED_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com",
    "proton.me", "protonmail.com", "aol.com", "mail.com", "zoho.com",
    "example.com", "acme.com", "google.com", "microsoft.com", "apple.com",
}

# Known Indian UPI handle suffixes (Google Pay, PhonePe, Paytm, BHIM, Banks)
KNOWN_UPI_HANDLES = {
    "okhdfcbank", "okicici", "oksbi", "okaxis", "paytm", "ybl", "upi",
    "axl", "ibl", "apl", "ptaxis", "ptsbi", "pthdfc", "ptyes", "barodampay",
    "kotak", "icici", "hdfcbank", "sbi", "cnrb", "federal", "indus", "kbl",
    "pnb", "rbl", "aubank", "jupiteraxis", "slice", "freecharge", "postbank",
    "boi", "citi", "dbs", "hsbc", "idbi", "idfcbank", "iob", "mahb", "scb",
    "sib", "uco", "unionbank", "yesbank", "axisbank", "fbl", "tapicici",
}

# Bitcoin regexes
BTC_BECH32_REGEX = re.compile(r"\bbc1[a-z0-9]{25,90}\b", re.IGNORECASE)
BTC_BASE58_REGEX = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")

# Ethereum regex (40 hex chars after 0x)
ETH_REGEX = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

# Bank account proximity keywords
BANK_KEYWORDS = [
    r"account\s*(?:number|no\.?|num\.?)",
    r"a/c\s*(?:no\.?|number)?",
    r"acc(?:t)?\s*(?:no\.?|number)?",
    r"bank\s*account",
    r"ifsc",
    r"routing\s*(?:number|no\.?)",
]
BANK_KEYWORD_PATTERN = re.compile("|".join(BANK_KEYWORDS), re.IGNORECASE)
ACCOUNT_NUMBER_PATTERN = re.compile(r"\b\d{9,18}\b")


class _HTMLSkeletonParser(html.parser.HTMLParser):
    """Extracts only tag names and nesting structure, stripping all attributes and text."""

    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(f"<{tag.lower()}>")

    def handle_endtag(self, tag: str) -> None:
        self.tags.append(f"</{tag.lower()}>")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(f"<{tag.lower()}/>")

    def get_skeleton(self) -> str:
        return "".join(self.tags)


def _extract_upi_ids(body_text: str, urls: list[str]) -> list[str]:
    """Extract and validate UPI IDs from text and payment URLs."""
    upi_set: set[str] = set()

    # 1. Look for explicit upi://pay?pa=... URLs or deep links
    for u in urls:
        if u.lower().startswith("upi://") or "upi://" in u.lower():
            try:
                parsed = urlparse(u)
                qs = parse_qs(parsed.query)
                if "pa" in qs and qs["pa"]:
                    pa_val = qs["pa"][0].strip().lower()
                    if "@" in pa_val:
                        upi_set.add(pa_val)
            except Exception:
                pass

    # 2. General regex pattern: [\w.\-]{2,256}@[a-zA-Z]{2,64}
    # Matches handles like user@okhdfcbank, 9876543210@paytm, payment.desk@ybl
    raw_candidates = re.findall(r"\b([\w.\-]{2,256}@([a-zA-Z0-9]{2,64}))\b", body_text)
    for full_match, handle in raw_candidates:
        handle_lower = handle.lower()
        full_lower = full_match.lower().strip(".-_")

        # Exclude known email domains or common email TLD structures
        if full_lower in upi_set:
            continue
        if any(full_lower.endswith(f"@{dom}") for dom in EXCLUDED_EMAIL_DOMAINS):
            continue

        # Check if handle has a dot (e.g. gmail.com has '.', but UPI handles usually do not)
        if "." in handle_lower:
            continue

        # Check if handle is known bank/wallet suffix or ends with bank/upi/pay
        if (
            handle_lower in KNOWN_UPI_HANDLES
            or handle_lower.endswith("bank")
            or handle_lower.endswith("upi")
            or handle_lower.endswith("pay")
        ):
            upi_set.add(full_lower)

    return sorted(list(upi_set))


def _extract_crypto_wallets(body_text: str) -> list[str]:
    """Extract Bitcoin and Ethereum cryptocurrency wallet addresses."""
    wallets: set[str] = set()

    # Bitcoin Bech32 (bc1...)
    for match in BTC_BECH32_REGEX.findall(body_text):
        wallets.add(match.lower())

    # Bitcoin Base58 (1... or 3...)
    for match in BTC_BASE58_REGEX.findall(body_text):
        # Additional length and char check
        if 26 <= len(match) <= 35:
            wallets.add(match)

    # Ethereum (0x...)
    for match in ETH_REGEX.findall(body_text):
        wallets.add(match)

    return sorted(list(wallets))


def _extract_bank_accounts(body_text: str) -> list[str]:
    """Extract possible bank account numbers (9-18 digits) occurring near banking keywords."""
    possible_accounts: set[str] = set()

    # Search lines or sentences around keywords
    lines = body_text.splitlines()
    for line in lines:
        if BANK_KEYWORD_PATTERN.search(line):
            for num in ACCOUNT_NUMBER_PATTERN.findall(line):
                # Avoid trivial repeating digits like 000000000 or 111111111
                if len(set(num)) > 1:
                    possible_accounts.add(num)

    # Also check a sliding window across the entire text in case of multiline formatting
    for match in BANK_KEYWORD_PATTERN.finditer(body_text):
        start = max(0, match.start() - 50)
        end = min(len(body_text), match.end() + 80)
        window = body_text[start:end]
        for num in ACCOUNT_NUMBER_PATTERN.findall(window):
            if len(set(num)) > 1:
                possible_accounts.add(num)

    return sorted(list(possible_accounts))


def _extract_attachment_hashes(attachments_raw: list[bytes]) -> list[str]:
    """Compute SHA-256 hash for each raw attachment byte buffer."""
    hashes: set[str] = set()
    for raw in attachments_raw:
        if raw:
            h = hashlib.sha256(raw).hexdigest()
            hashes.add(h)
    return sorted(list(hashes))


def _extract_attachment_hashes_with_names(
    attachments_raw: list[bytes], filenames: list[str]
) -> list[dict[str, str]]:
    """Compute SHA-256 hash for each attachment, paired with its filename.

    Returns a list of {"hash": str, "filename": str} dicts.
    If filenames list is shorter than attachments_raw, missing names default to "".
    """
    results: list[dict[str, str]] = []
    for idx, raw in enumerate(attachments_raw):
        if raw:
            h = hashlib.sha256(raw).hexdigest()
            fn = filenames[idx] if idx < len(filenames) else ""
            results.append({"hash": h, "filename": fn})
    return results


def _compute_template_hash(html_body: str) -> str | None:
    """Compute structural SHA-256 hash of the HTML template skeleton."""
    if not html_body or not html_body.strip():
        return None

    parser = _HTMLSkeletonParser()
    try:
        parser.feed(html_body)
        skeleton = parser.get_skeleton()
        if not skeleton:
            return None
        return hashlib.sha256(skeleton.encode("utf-8")).hexdigest()
    except Exception:
        # Fallback to simple tag regex if parser encounters broken HTML
        tag_matches = re.findall(r"</?[a-zA-Z0-9]+(?:\s*/>|>)", html_body)
        cleaned_tags = "".join(re.sub(r"\s+", "", t.lower()) for t in tag_matches)
        if cleaned_tags:
            return hashlib.sha256(cleaned_tags.encode("utf-8")).hexdigest()
        return None


def extract_fingerprints(
    body_text: str,
    urls: list[str],
    attachments_raw: list[bytes],
    html_body: str = "",
    attachment_filenames: list[str] | None = None,
) -> dict[str, Any]:
    """Extract financial and technical fingerprints from email content.

    Returns:
        {
            "upi_ids": list[str],
            "wallet_addresses": list[str],
            "possible_bank_accounts": list[str],
            "attachment_hashes": list[str],
            "attachment_hash_details": list[dict],  # [{"hash": str, "filename": str}, ...]
            "template_structure_hash": str | None,
        }
    """
    fnames = attachment_filenames or []
    return {
        "upi_ids": _extract_upi_ids(body_text, urls),
        "wallet_addresses": _extract_crypto_wallets(body_text),
        "possible_bank_accounts": _extract_bank_accounts(body_text),
        "attachment_hashes": _extract_attachment_hashes(attachments_raw),
        "attachment_hash_details": _extract_attachment_hashes_with_names(attachments_raw, fnames),
        "template_structure_hash": _compute_template_hash(html_body),
    }
