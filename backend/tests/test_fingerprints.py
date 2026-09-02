"""Unit tests for financial and technical fingerprint extraction."""

import hashlib
from app.parsing.fingerprints import extract_fingerprints


def test_extract_upi_ids():
    text = (
        "Please send immediate payment of Rs 5000 to our official UPI ID: "
        "refund.desk@okhdfcbank or merchant99@paytm to avoid account block. "
        "Contact support at support@gmail.com or help@acme.com for queries."
    )
    urls = [
        "https://example.com/pay",
        "upi://pay?pa=cyberfraud@ybl&pn=Helpdesk&am=5000",
    ]

    res = extract_fingerprints(body_text=text, urls=urls, attachments_raw=[])
    upi_ids = res["upi_ids"]

    assert "refund.desk@okhdfcbank" in upi_ids
    assert "merchant99@paytm" in upi_ids
    assert "cyberfraud@ybl" in upi_ids
    # Common email addresses MUST NOT be treated as UPI IDs
    assert "support@gmail.com" not in upi_ids
    assert "help@acme.com" not in upi_ids


def test_extract_crypto_wallets():
    text = (
        "Send 0.05 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or SegWit "
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq. "
        "Alternatively send ETH to 0x742d35Cc6634C0532925a3b844Bc454e4438f44e."
    )

    res = extract_fingerprints(body_text=text, urls=[], attachments_raw=[])
    wallets = res["wallet_addresses"]

    assert "1a1zp1ep5qgefidmptftl5slmv7divfna" in [w.lower() for w in wallets] or "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in wallets
    assert "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" in wallets
    assert "0x742d35Cc6634C0532925a3b844Bc454e4438f44e" in wallets


def test_extract_possible_bank_accounts():
    text = (
        "Your transaction failed. Transfer immediately to Bank Account No: 123456789012, "
        "IFSC code HDFC0001234. Tracking code is 98765432109876 (this is not an account)."
    )

    res = extract_fingerprints(body_text=text, urls=[], attachments_raw=[])
    accounts = res["possible_bank_accounts"]

    assert "123456789012" in accounts


def test_extract_attachment_hashes():
    raw1 = b"MALICIOUS INVOICE CONTENT"
    raw2 = b"MALWARE PAYLOAD EXE"
    h1 = hashlib.sha256(raw1).hexdigest()
    h2 = hashlib.sha256(raw2).hexdigest()

    res = extract_fingerprints(
        body_text="See attached invoice",
        urls=[],
        attachments_raw=[raw1, raw2],
    )
    att_hashes = res["attachment_hashes"]

    assert h1 in att_hashes
    assert h2 in att_hashes
    assert len(att_hashes) == 2


def test_html_template_structural_hash_identical_for_phishing_kit():
    html_template1 = """
    <html>
      <body>
        <div class="banner">
          <h1>Security Notice for Alice</h1>
          <p>Your account has been locked. Click <a href="http://evil1.com">here</a>.</p>
        </div>
      </body>
    </html>
    """

    html_template2 = """
    <html>
      <body>
        <div class="different-class">
          <h1>Security Notice for Bob</h1>
          <p>Your payment has failed. Click <a href="http://evil2.com">verify now</a>.</p>
        </div>
      </body>
    </html>
    """

    res1 = extract_fingerprints(body_text="", urls=[], attachments_raw=[], html_body=html_template1)
    res2 = extract_fingerprints(body_text="", urls=[], attachments_raw=[], html_body=html_template2)

    assert res1["template_structure_hash"] is not None
    assert res2["template_structure_hash"] is not None
    # Both share the exact same tag structure: <html><body><div><h1></h1><p><a></a></p></div></body></html>
    assert res1["template_structure_hash"] == res2["template_structure_hash"]


def test_empty_fingerprints_on_benign_plain_email():
    res = extract_fingerprints(
        body_text="Hello team, meeting is scheduled for tomorrow at 10 AM.",
        urls=["https://acme.corp/calendar"],
        attachments_raw=[],
        html_body="",
    )

    assert res["upi_ids"] == []
    assert res["wallet_addresses"] == []
    assert res["possible_bank_accounts"] == []
    assert res["attachment_hashes"] == []
    assert res["template_structure_hash"] is None


def test_parse_email_with_upi_gang_fixtures():
    from pathlib import Path
    from app.parsing.email_parser import parse_email

    fixtures_dir = Path(__file__).parent / "fixtures"
    gang1_path = fixtures_dir / "sample_upi_gang1.eml"
    gang2_path = fixtures_dir / "sample_upi_gang2.eml"

    data1 = parse_email(gang1_path.read_bytes())
    data2 = parse_email(gang2_path.read_bytes())

    # Completely different senders & domains
    assert data1["sender_domain"] == "billing-service-corp.com"
    assert data2["sender_domain"] == "quick-refund-portal.net"
    assert data1["sender_domain"] != data2["sender_domain"]

    # Shared UPI ID fingerprint
    assert "gang.collector@okhdfcbank" in data1["upi_ids"]
    assert "gang.collector@okhdfcbank" in data2["upi_ids"]

    # Bank account detected in gang1
    assert "9876543210123" in data1["possible_bank_accounts"]
