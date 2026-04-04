from __future__ import annotations

from io import BytesIO
from typing import Iterable
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .models import AnalysisResult


def _bool_label(value: bool) -> str:
    return "Yes" if value else "No"


def _paragraph_list(items: Iterable[str], style: ParagraphStyle) -> list[Paragraph]:
    return [Paragraph(f"- {escape(item)}", style) for item in items]


def build_report_pdf(report: AnalysisResult) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
        title=f"Privacy Sentinel Report {report.report_id}",
    )

    styles = getSampleStyleSheet()
    body = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontSize=10,
        leading=14,
        spaceAfter=4,
    )
    heading = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=12,
        leading=16,
        spaceBefore=10,
        spaceAfter=6,
    )

    content = []
    content.append(Paragraph("Privacy Sentinel Report", styles["Title"]))
    content.append(Spacer(1, 8))
    content.append(Paragraph(f"Report ID: {escape(report.report_id)}", body))
    content.append(Paragraph(f"URL: {escape(report.url)}", body))
    content.append(Paragraph(f"Scanned At: {report.scanned_at.isoformat()}", body))

    content.append(Spacer(1, 8))
    content.append(Paragraph("Risk Summary", heading))
    summary_rows = [
        ["Risk Score", str(report.risk_score)],
        ["Severity", report.severity.title()],
        ["Total Cookies", str(report.total_cookies)],
        ["First-Party Cookies", str(report.first_party_cookies)],
        ["Third-Party Cookies", str(report.third_party_cookies)],
        ["Tracking Indicators", str(report.tracking_indicators)],
        ["Insecure Cookies", str(report.insecure_cookies)],
    ]
    table_style = TableStyle(
        [
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
    )
    summary_table = Table(summary_rows, colWidths=[170, 320])
    summary_table.setStyle(table_style)
    content.append(summary_table)

    content.append(Paragraph("Page Privacy Signals", heading))
    signals = report.page_signals
    signal_rows = [
        ["Microphone Access", _bool_label(signals.microphone)],
        ["Camera Access", _bool_label(signals.camera)],
        ["Location Access", _bool_label(signals.location)],
        ["Third-Party Data Alert", _bool_label(signals.third_party_data_alert)],
    ]
    signals_table = Table(signal_rows, colWidths=[170, 320])
    signals_table.setStyle(table_style)
    content.append(signals_table)

    if signals.third_party_endpoints:
        content.append(Spacer(1, 6))
        content.append(Paragraph("Detected Third-Party Endpoints", body))
        content.extend(_paragraph_list(signals.third_party_endpoints, body))

    content.append(Paragraph("Recommendations", heading))
    if report.recommendations:
        content.extend(_paragraph_list(report.recommendations, body))
    else:
        content.append(Paragraph("- No recommendations generated.", body))

    content.append(Paragraph("Cookie Findings", heading))
    if report.findings:
        for finding in report.findings:
            content.append(
                Paragraph(
                    f"{escape(finding.cookie_name)} ({escape(finding.domain)}) - {escape(finding.risk_level.title())}",
                    body,
                )
            )
            if finding.reasons:
                content.extend(_paragraph_list(finding.reasons, body))
            content.append(Spacer(1, 4))
    else:
        content.append(Paragraph("- No high-risk cookie findings detected.", body))

    doc.build(content)
    return buffer.getvalue()