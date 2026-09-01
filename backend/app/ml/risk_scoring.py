"""Composite risk scoring engine combining ML classification, header signals, and threat intelligence."""

from __future__ import annotations

from typing import Any


def compute_risk(
    parsed: dict[str, Any],
    ml_result: dict[str, Any],
    threat_intel: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Compute a consolidated 0-100 risk score and verdict from parsed email indicators,
    ML probability output, and optional VirusTotal threat intelligence results.

    Weighting:
      - ML classifier: 0–50 pts (phishing_probability * 50)
      - SPF fail/softfail: +15 pts
      - DKIM fail: +15 pts
      - DMARC fail: +10 pts
      - Reply-To domain mismatch: +10 pts
      - Return-Path domain mismatch: +5 pts
      - Suspicious attachment present: +15 pts
      - Threat Intel malicious IP / domain: +20 pts each

    Verdict thresholds:
      - >= 70: "Phishing/Scam"
      - >= 35: "Suspicious"
      - < 35:  "Safe"
    """
    score: float = 0.0
    indicators: list[str] = []

    # 1. ML probability contribution (0 - 50 points)
    ml_prob = float(ml_result.get("phishing_probability", 0.0))
    ml_score = ml_prob * 50.0
    score += ml_score

    if ml_prob >= 0.70:
        indicators.append(f"High ML phishing probability score ({round(ml_prob * 100, 1)}%)")
    elif ml_prob >= 0.50:
        indicators.append(f"Moderate ML phishing probability score ({round(ml_prob * 100, 1)}%)")

    # 2. SPF authentication
    auth = parsed.get("authentication", {})
    spf_status = str(auth.get("spf", "")).lower()
    if spf_status in ("fail", "softfail"):
        score += 15.0
        indicators.append(f"SPF authentication failed ({spf_status})")

    # 3. DKIM authentication
    dkim_status = str(auth.get("dkim", "")).lower()
    if dkim_status == "fail":
        score += 15.0
        indicators.append("DKIM authentication failed")

    # 4. DMARC authentication
    dmarc_status = str(auth.get("dmarc", "")).lower()
    if dmarc_status == "fail":
        score += 10.0
        indicators.append("DMARC authentication failed")

    # 5. Domain alignment: Reply-To mismatch
    mismatches = parsed.get("domain_mismatches", {})
    if mismatches.get("reply_to_mismatch"):
        score += 10.0
        reply_to_dom = parsed.get("reply_to_domain") or "unknown"
        sender_dom = parsed.get("sender_domain") or "unknown"
        indicators.append(
            f"Reply-To domain ({reply_to_dom}) does not match sender domain ({sender_dom})"
        )

    # 6. Domain alignment: Return-Path mismatch
    if mismatches.get("return_path_mismatch"):
        score += 5.0
        return_path_dom = parsed.get("return_path_domain") or "unknown"
        sender_dom = parsed.get("sender_domain") or "unknown"
        indicators.append(
            f"Return-Path domain ({return_path_dom}) does not match sender domain ({sender_dom})"
        )

    # 7. Suspicious attachments
    suspicious_attachments = parsed.get("suspicious_attachments", [])
    if suspicious_attachments:
        score += 15.0
        att_str = ", ".join(suspicious_attachments)
        indicators.append(f"Suspicious executable or script attachment detected: {att_str}")

    # 8. Threat Intelligence Signals (VirusTotal)
    if threat_intel:
        ip_rep = threat_intel.get("originating_ip_reputation", {})
        if isinstance(ip_rep, dict) and ip_rep.get("reputation") == "malicious":
            score += 20.0
            mal_count = ip_rep.get("malicious", 0)
            indicators.append(
                f"Sending IP flagged malicious on VirusTotal ({mal_count} security vendors)"
            )

        domain_reps = threat_intel.get("domain_reputations", {})
        if isinstance(domain_reps, dict):
            for domain, dom_data in domain_reps.items():
                if isinstance(dom_data, dict) and dom_data.get("reputation") == "malicious":
                    score += 20.0
                    dom_mal = dom_data.get("malicious", 0)
                    indicators.append(
                        f"Domain '{domain}' flagged malicious on VirusTotal ({dom_mal} security vendors)"
                    )

    # Cap score at 100
    final_score = min(100, max(0, int(round(score))))

    # Determine verdict
    if final_score >= 70:
        verdict = "Phishing/Scam"
    elif final_score >= 35:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return {
        "risk_score": final_score,
        "verdict": verdict,
        "ml_phishing_probability": ml_prob,
        "indicators": indicators,
    }
