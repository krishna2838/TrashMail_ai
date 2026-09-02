"""Forensic PDF evidence report generator using ReportLab Platypus."""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Design palette matching TraceMail AI
COLOR_PRIMARY = colors.HexColor("#1D4ED8")      # Deep blue accent
COLOR_TEXT_MAIN = colors.HexColor("#111827")    # Charcoal
COLOR_TEXT_MUTED = colors.HexColor("#4B5563")   # Muted gray
COLOR_BG_LIGHT = colors.HexColor("#F8F9FB")     # Light gray fill
COLOR_BORDER = colors.HexColor("#E5E7EB")       # Border rule

COLOR_SAFE = colors.HexColor("#15803D")         # Green
COLOR_SUSPICIOUS = colors.HexColor("#B45309")   # Amber
COLOR_PHISH = colors.HexColor("#B91C1C")        # Red


def _get_verdict_color(verdict: str) -> colors.HexColor:
    v = (verdict or "").lower()
    if "safe" in v:
        return COLOR_SAFE
    if "suspicious" in v:
        return COLOR_SUSPICIOUS
    return COLOR_PHISH


def generate_report(analysis: dict[str, Any]) -> bytes:
    """Generate a high-fidelity forensic PDF analysis report.

    Args:
        analysis: Complete dictionary output from /api/analyze

    Returns:
        Raw bytes of the generated PDF document.
    """
    buffer = io.BytesIO()

    # Document geometry: Letter with 0.5-inch margins
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    # Custom Typography Styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=COLOR_PRIMARY,
        spaceAfter=2,
    )

    subtitle_style = ParagraphStyle(
        "DocSubTitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=COLOR_TEXT_MUTED,
    )

    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=COLOR_PRIMARY,
        spaceBefore=8,
        spaceAfter=4,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=COLOR_TEXT_MAIN,
    )

    mono_style = ParagraphStyle(
        "MonoStyle",
        parent=body_style,
        fontName="Courier",
        fontSize=7.5,
        leading=9.5,
    )

    meta_label_style = ParagraphStyle(
        "MetaLabel",
        parent=body_style,
        fontName="Helvetica-Bold",
        textColor=COLOR_TEXT_MUTED,
    )

    indicator_style = ParagraphStyle(
        "IndicatorText",
        parent=body_style,
        textColor=COLOR_PHISH,
        leftIndent=12,
        firstLineIndent=-8,
    )

    footer_style = ParagraphStyle(
        "FooterDisclaimer",
        parent=body_style,
        fontName="Helvetica-Oblique",
        fontSize=7.5,
        leading=10,
        textColor=COLOR_TEXT_MUTED,
        alignment=1,  # Center
    )

    story = []

    # ─────────────────────────────────────────────────────────────────
    # 1. Header & Case Identification
    # ─────────────────────────────────────────────────────────────────
    email_hash = analysis.get("email_hash", "UNKNOWN")
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    header_data = [
        [
            Paragraph("<b>TRACEMAIL AI</b> — Forensic Incident Evidence Report", title_style),
            Paragraph(f"<b>Generated:</b> {now_str}<br/><b>Case ID:</b> {email_hash[:16]}...", subtitle_style),
        ]
    ]
    header_table = Table(header_data, colWidths=[360, 180])
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(header_table)
    story.append(HRFlowable(width="100%", thickness=1.5, color=COLOR_PRIMARY, spaceBefore=4, spaceAfter=8))

    # ─────────────────────────────────────────────────────────────────
    # 2. Executive Verdict & Risk Scoring
    # ─────────────────────────────────────────────────────────────────
    verdict = analysis.get("verdict", "Unknown")
    risk_score = analysis.get("risk_score", 0)
    ml_prob = analysis.get("ml_phishing_probability", 0.0)
    v_color = _get_verdict_color(verdict)

    verdict_text = f"<font size='14' color='{v_color.hexval()}'><b>{verdict.upper()}</b></font>"
    score_text = f"<font size='12'>Composite Threat Score: <b>{risk_score}/100</b></font>"
    ml_text = f"ML Phishing Probability: <b>{ml_prob * 100:.1f}%</b>"

    verdict_table_data = [
        [
            Paragraph(f"{verdict_text}<br/>{score_text}", body_style),
            Paragraph(
                f"<b>Target Sender:</b> {analysis.get('sender_domain', 'N/A')}<br/>"
                f"<b>Originating IP:</b> {analysis.get('originating_ip', 'N/A')}<br/>"
                f"{ml_text}",
                body_style,
            ),
        ]
    ]
    verdict_table = Table(verdict_table_data, colWidths=[270, 270])
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_BG_LIGHT),
        ("BOX", (0, 0), (-1, -1), 1.5, v_color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 10))

    # ─────────────────────────────────────────────────────────────────
    # 3. Email Headers & Metadata
    # ─────────────────────────────────────────────────────────────────
    story.append(Paragraph("1. Email Message Metadata", section_heading))
    meta_rows = [
        [Paragraph("Subject", meta_label_style), Paragraph(str(analysis.get("subject", "(No Subject)")), body_style)],
        [Paragraph("From", meta_label_style), Paragraph(str(analysis.get("sender", "N/A")), body_style)],
        [Paragraph("Reply-To", meta_label_style), Paragraph(str(analysis.get("reply_to", "None")), body_style)],
        [Paragraph("Return-Path", meta_label_style), Paragraph(str(analysis.get("return_path", "None")), body_style)],
        [Paragraph("Date Header", meta_label_style), Paragraph(str(analysis.get("date", "N/A")), body_style)],
        [Paragraph("Message-ID", meta_label_style), Paragraph(str(analysis.get("message_id", "N/A")), mono_style)],
        [Paragraph("SHA256 Hash", meta_label_style), Paragraph(email_hash, mono_style)],
    ]
    meta_table = Table(meta_rows, colWidths=[90, 450])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), COLOR_BG_LIGHT),
        ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8))

    # ─────────────────────────────────────────────────────────────────
    # 4. Authentication Verification & Indicators
    # ─────────────────────────────────────────────────────────────────
    auth = analysis.get("authentication", {})
    spf_val = str(auth.get("spf", "none")).upper()
    dkim_val = str(auth.get("dkim", "none")).upper()
    dmarc_val = str(auth.get("dmarc", "none")).upper()

    def _auth_color(val: str) -> str:
        return "#15803D" if "PASS" in val else "#B91C1C"

    auth_summary = (
        f"SPF: <font color='{_auth_color(spf_val)}'><b>{spf_val}</b></font> &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"DKIM: <font color='{_auth_color(dkim_val)}'><b>{dkim_val}</b></font> &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"DMARC: <font color='{_auth_color(dmarc_val)}'><b>{dmarc_val}</b></font>"
    )

    story.append(Paragraph("2. Authentication & Threat Indicators", section_heading))
    story.append(Paragraph(auth_summary, body_style))
    story.append(Spacer(1, 4))

    indicators = analysis.get("indicators", [])
    if indicators:
        for ind in indicators:
            story.append(Paragraph(f"• {ind}", indicator_style))
    else:
        story.append(Paragraph("• No malicious indicators detected.", body_style))
    story.append(Spacer(1, 8))

    # ─────────────────────────────────────────────────────────────────
    # 5. MTA Relay Hop Sequence (Chronological)
    # ─────────────────────────────────────────────────────────────────
    hops = analysis.get("hops", [])
    story.append(Paragraph(f"3. Sender Relay Trace ({len(hops)} Recorded Hops)", section_heading))

    if hops:
        hop_table_data = [
            [
                Paragraph("<b>Seq</b>", meta_label_style),
                Paragraph("<b>From Host</b>", meta_label_style),
                Paragraph("<b>From IP</b>", meta_label_style),
                Paragraph("<b>Received By</b>", meta_label_style),
                Paragraph("<b>Scope</b>", meta_label_style),
            ]
        ]
        for h in hops:
            is_origin = (h.get("from_ip") == analysis.get("originating_ip"))
            scope_str = "Origin (Public)" if is_origin else ("Public" if h.get("is_public_ip") else "Internal Relay")
            from_ip_txt = h.get("from_ip") or "N/A"
            if is_origin:
                from_ip_txt = f"<b>{from_ip_txt} *</b>"

            hop_table_data.append([
                Paragraph(str(h.get("sequence", "-")), body_style),
                Paragraph(str(h.get("from_host") or "N/A"), mono_style),
                Paragraph(from_ip_txt, mono_style),
                Paragraph(str(h.get("by_host") or "N/A"), mono_style),
                Paragraph(scope_str, body_style),
            ])

        hop_table = Table(hop_table_data, colWidths=[30, 160, 110, 160, 80])
        hop_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_BG_LIGHT),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ]))
        story.append(hop_table)
    else:
        story.append(Paragraph("No Received headers extracted.", body_style))
    story.append(Spacer(1, 8))

    # ─────────────────────────────────────────────────────────────────
    # 6. Geolocation & Threat Intelligence (VirusTotal)
    # ─────────────────────────────────────────────────────────────────
    geo = analysis.get("origin_geo") or {}
    intel = analysis.get("threat_intel") or {}
    ip_rep = intel.get("originating_ip_reputation") or {}
    dom_reps = intel.get("domain_reputations") or {}

    geo_text = (
        f"<b>IP Address:</b> {geo.get('ip', 'N/A')}<br/>"
        f"<b>Country:</b> {geo.get('country', 'N/A')} ({geo.get('country_code', 'N/A')})<br/>"
        f"<b>City:</b> {geo.get('city', 'Unknown')}<br/>"
        f"<b>ASN Org:</b> {geo.get('asn_org', 'Unknown')}<br/>"
        f"<b>Coordinates:</b> {geo.get('latitude', 'N/A')}, {geo.get('longitude', 'N/A')}"
    ) if geo.get("ip") else "No public originating IP geolocated."

    ip_status = ip_rep.get("reputation", "unavailable").upper()
    ip_mal = ip_rep.get("malicious", 0)
    intel_text = (
        f"<b>VirusTotal IP Reputation:</b> {ip_status} ({ip_mal} malicious vendor detections)<br/>"
    )
    if dom_reps:
        dom_lines = []
        for d_name, d_data in dom_reps.items():
            d_status = d_data.get("reputation", "clean").upper()
            d_mal = d_data.get("malicious", 0)
            dom_lines.append(f"• <b>{d_name}</b>: {d_status} ({d_mal} detections)")
        intel_text += "<b>Domain Scans:</b><br/>" + "<br/>".join(dom_lines)
    else:
        intel_text += "<b>Domain Scans:</b> None extracted."

    geo_intel_data = [
        [Paragraph("<b>Sender Geolocation</b>", meta_label_style), Paragraph("<b>VirusTotal Threat Intelligence</b>", meta_label_style)],
        [Paragraph(geo_text, body_style), Paragraph(intel_text, body_style)],
    ]
    geo_intel_table = Table(geo_intel_data, colWidths=[270, 270])
    geo_intel_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_BG_LIGHT),
        ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(Paragraph("4. Origin Geolocation & Threat Intelligence", section_heading))
    story.append(geo_intel_table)
    story.append(Spacer(1, 8))

    # ─────────────────────────────────────────────────────────────────
    # 7. Linked Campaign Infrastructure (Neo4j Clusters)
    # ─────────────────────────────────────────────────────────────────
    campaign = analysis.get("campaign") or {}
    c_size = campaign.get("campaign_size", 0)
    c_related = campaign.get("related_emails", [])

    story.append(Paragraph(
        "5. Linked Infrastructure — Other Analyzed Emails Sharing This Sender's Network",
        section_heading
    ))

    if c_size > 0:
        story.append(Paragraph(
            f"<b>CAMPAIGN DETECTED:</b> This sender's infrastructure matches <b>{c_size}</b> "
            f"other previously investigated email(s) stored in the Neo4j cluster database.",
            body_style
        ))
        story.append(Spacer(1, 4))

        camp_table_data = [
            [
                Paragraph("<b>Related Case ID</b>", meta_label_style),
                Paragraph("<b>Subject Line</b>", meta_label_style),
                Paragraph("<b>Verdict</b>", meta_label_style),
                Paragraph("<b>Shared Vector</b>", meta_label_style),
            ]
        ]
        for rel in c_related[:8]:  # show top 8
            camp_table_data.append([
                Paragraph(str(rel.get("id", ""))[:14] + "...", mono_style),
                Paragraph(str(rel.get("subject", "N/A"))[:32], body_style),
                Paragraph(str(rel.get("verdict", "N/A")), body_style),
                Paragraph(f"{rel.get('shared_via', '').upper()}: {rel.get('shared_value', '')}", mono_style),
            ])

        camp_table = Table(camp_table_data, colWidths=[100, 200, 90, 150])
        camp_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_BG_LIGHT),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(camp_table)
    else:
        story.append(Paragraph(
            "No linked infrastructure detected — this is the first recorded sighting of this sender's IP/domains.",
            body_style
        ))

    story.append(Spacer(1, 14))

    # ─────────────────────────────────────────────────────────────────
    # 8. Disclaimer & Legal Footer
    # ─────────────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=COLOR_BORDER, spaceBefore=4, spaceAfter=6))
    disclaimer = (
        "Generated automatically by TraceMail AI (SIH26106). This document constitutes forensic analysis "
        "evidence intended to support security operations and incident investigation. Findings should be "
        "independently verified prior to legal enforcement or administrative blocking actions."
    )
    story.append(Paragraph(disclaimer, footer_style))

    # Build the document
    doc.build(story)

    return buffer.getvalue()
