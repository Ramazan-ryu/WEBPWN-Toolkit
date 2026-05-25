#!/usr/bin/env python3
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing, Rect, Line, String, Polygon

OUTPUT_PATH = Path("webpwn_toolkit_audit_report.pdf")


def build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="TitleCenter", parent=styles["Title"], alignment=TA_CENTER, spaceAfter=18))
    styles.add(ParagraphStyle(name="SectionHeader", parent=styles["Heading2"], spaceBefore=16, spaceAfter=8))
    styles.add(ParagraphStyle(name="SubHeader", parent=styles["Heading3"], spaceBefore=12, spaceAfter=6))
    styles.add(ParagraphStyle(name="Body", parent=styles["BodyText"], fontSize=11, leading=16, spaceAfter=10))
    styles.add(ParagraphStyle(name="CustomBullet", parent=styles["BodyText"], leftIndent=14, bulletIndent=4, bulletFontName="Helvetica-Bold", bulletFontSize=9, fontSize=11, leading=16, spaceAfter=6))
    return styles


def bullet_paragraph(text, styles):
    return Paragraph(text, styles["CustomBullet"], bulletText="•")


def build_architecture_diagram():
    drawing = Drawing(520, 220)
    drawing.add(Rect(30, 168, 160, 30, strokeColor=colors.HexColor("#0D3B66"), fillColor=colors.HexColor("#D0E1F9")))
    drawing.add(String(55, 185, "Browser UI", fontSize=11, fillColor=colors.HexColor("#0D3B66")))
    drawing.add(Rect(190, 168, 160, 30, strokeColor=colors.HexColor("#0D3B66"), fillColor=colors.HexColor("#FFFFFF")))
    drawing.add(String(210, 185, "Flask Web Server", fontSize=11, fillColor=colors.HexColor("#0D3B66")))
    drawing.add(Rect(350, 168, 160, 30, strokeColor=colors.HexColor("#0D3B66"), fillColor=colors.HexColor("#D0E1F9")))
    drawing.add(String(380, 185, "Scanner Engine", fontSize=11, fillColor=colors.HexColor("#0D3B66")))
    drawing.add(Line(190, 182, 230, 182, strokeColor=colors.black))
    drawing.add(Line(350, 182, 390, 182, strokeColor=colors.black))
    drawing.add(Polygon([220, 182, 215, 178, 225, 178], fillColor=colors.black))
    drawing.add(Polygon([360, 182, 355, 178, 365, 178], fillColor=colors.black))
    drawing.add(Line(100, 168, 100, 134, strokeColor=colors.black))
    drawing.add(String(60, 118, "SocketIO / API sync", fontSize=8, fillColor=colors.black))
    drawing.add(Rect(100, 90, 320, 30, strokeColor=colors.HexColor("#0D3B66"), fillColor=colors.HexColor("#F6F8FF")))
    drawing.add(String(145, 105, "Session + Scan State / Reports", fontSize=9, fillColor=colors.HexColor("#0D3B66")))
    return drawing


def build_report():
    styles = build_styles()
    doc = SimpleDocTemplate(str(OUTPUT_PATH), pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)

    elements = []
    elements.append(Paragraph("WebPwn Toolkit — Audit, Fixes, and Senior-Level Review", styles["TitleCenter"]))
    elements.append(Paragraph("Generated: May 25, 2026", styles["Body"]))
    elements.append(Paragraph("Objective", styles["SectionHeader"]))
    elements.append(Paragraph(
        "Create a professional, senior-level technical audit of the WebPwn Toolkit workspace, with a strong focus on UI/backend synchronization, secure scan progress feedback, false-positive mitigation in admin detection, and actionable recommendations.",
        styles["Body"],
    ))
    elements.append(Paragraph("Scope", styles["SubHeader"]))
    for item in [
        "Backend API module ordering and response contract stability.",
        "Frontend module rendering, selection semantics, and progress state visibility.",
        "Admin Hunter false-positive filtering for login-protected routes.",
        "Professional recommendations, validation notes, and architecture review.",
    ]:
        elements.append(bullet_paragraph(item, styles))

    elements.append(PageBreak())
    elements.append(Paragraph("1. Executive Summary", styles["SectionHeader"]))
    elements.append(Paragraph(
        "The WebPwn Toolkit is a modular penetration testing platform that combines a Flask-based backend, a lightweight browser UI, and extensible scanner modules. Recent updates improve system reliability by aligning backend task definitions with frontend render logic, making progress reporting meaningful, and avoiding false-positive admin panel vulnerabilities.",
        styles["Body"],
    ))
    elements.append(Paragraph("Key improvements delivered", styles["SubHeader"]))
    for item in [
        "The /api/modules endpoint now returns an ordered array for web attack tasks with explicit display labels and backend keys.",
        "Frontend task rendering now preserves order and binds each visible module item to the correct execution key.",
        "Real-time progress events include module-level current/total data, improving scan visibility.",
        "Admin Hunter logic now intelligently skips passive leak checks for login-required pages, reducing false positives.",
    ]:
        elements.append(bullet_paragraph(item, styles))

    elements.append(PageBreak())
    elements.append(Paragraph("2. Architecture and Code Structure", styles["SectionHeader"]))
    elements.append(Paragraph(
        "The repository separates concerns cleanly: web UI assets live in webui/, scanning modules are under modules/, and the backend server coordinates session state and scan execution. This split is appropriate for a lightweight web management experience with extensible attack module capabilities.",
        styles["Body"],
    ))
    elements.append(Paragraph("Primary components", styles["SubHeader"]))
    for name, desc in [
        ("web_server.py", "Flask + SocketIO backend that serves UI assets, exposes configuration and report endpoints, and orchestrates scan threads."),
        ("webui/app.js", "Browser-side module rendering, selection behavior, scan lifecycle control, and real-time progress handling."),
        ("modules/web/admin_hunter.py", "Admin panel discovery and credential-aware validation logic, including login-form detection and deep authenticated scanning."),
    ]:
        elements.append(Paragraph(f"{name}: {desc}", styles["Bullet"], bulletText="•"))
    table_data = [
        ["Component", "Purpose", "Outcome"],
        ["Module ordering API", "Stable UI/scan contract", "Prevents mismatch and hidden execution errors"],
        ["SocketIO progress events", "Live scan state", "Improves user confidence during long-running scans"],
        ["Admin Hunter gating", "Auth-aware detection", "Reduces false positives while preserving coverage"],
    ]
    table = Table(table_data, colWidths=[140, 180, 180])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4B7BEC")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
    ]))
    elements.append(KeepTogether([table]))

    elements.append(PageBreak())
    elements.append(Paragraph("3. Backend Fixes", styles["SectionHeader"]))
    for item in [
        "get_modules() now returns ordered web attack tasks as an array of objects with explicit display metadata.",
        "WEB_ATTACK_TASK_ORDER governs the order of modules, eliminating reliance on dictionary iteration order.",
        "Session configuration persists target, domain, thread count, timeout, and findings, enabling consistent scan state across API calls.",
        "ACTIVE_SCANS supports clean scan cancellation through threading.Event objects.",
    ]:
        elements.append(bullet_paragraph(item, styles))
    elements.append(Paragraph(
        "These backend changes strengthen the data contract that the UI depends on and ensure that displayed module labels map directly to executable task keys.",
        styles["Body"],
    ))

    elements.append(PageBreak())
    elements.append(Paragraph("4. Frontend Fixes", styles["SectionHeader"]))
    for item in [
        "buildModuleList() supports both object and array payloads, allowing the backend to choose stable ordering formats without breaking the UI.",
        "Module cards now preserve their numeric display label while using the true backend task key for execution.",
        "Selection controls and search filtering improve usability for reconnaissance, web attack, and mobile task sets.",
        "Live scan progress now updates a professional progress bar with module-level context and current/total metrics.",
    ]:
        elements.append(bullet_paragraph(item, styles))
    elements.append(Paragraph(
        "This frontend refinement favors a senior-level UX by making scan state obvious and by avoiding hidden mismatches between selected items and executed tasks.",
        styles["Body"],
    ))

    elements.append(PageBreak())
    elements.append(Paragraph("5. Admin Hunter False-Positive Mitigation", styles["SectionHeader"]))
    for item in [
        "Access checks now identify login forms and dashboards separately.",
        "Passive leak analysis is skipped for pages with a login form, avoiding false positives on auth-protected admin endpoints.",
        "Only unauthenticated dashboard-like pages are flagged as broken access control issues.",
        "Authenticated deep scans still proceed after a successful credential discovery, preserving high-risk coverage.",
    ]:
        elements.append(bullet_paragraph(item, styles))
    elements.append(Paragraph(
        "This update is critical for correctly handling Juice Shop-style admin routes where login forms exist intentionally. The system now distinguishes between login gate pages and exposed admin dashboards.",
        styles["Body"],
    ))

    elements.append(PageBreak())
    elements.append(Paragraph("6. Validation and Recommendations", styles["SectionHeader"]))
    elements.append(Paragraph(
        "The environment supports Python 3.14 and ReportLab, allowing high-quality PDF report generation without external dependencies. For further maturity, the following improvements should be considered.",
        styles["Body"],
    ))
    for item in [
        "Add a reusable report generator module under modules/reporter for PDF and slide export.",
        "Introduce unit tests for module list ordering and admin hunter false-positive gating.",
        "Adopt a stronger session model for multi-user or multi-tab browser support.",
        "Install python-pptx to generate companion presentation slides from the same audit data.",
    ]:
        elements.append(bullet_paragraph(item, styles))
    elements.append(Paragraph(
        "The next step should be to formalize these updates with tests, documentation, and a clean report generation utility so the toolkit can be maintained at a senior engineering level.",
        styles["Body"],
    ))

    elements.append(PageBreak())
    elements.append(Paragraph("7. Appendix: Architecture Diagram", styles["SectionHeader"]))
    elements.append(Paragraph(
        "The following diagram summarizes the runtime flow between the browser UI, the Flask web server, and the scanning engine.",
        styles["Body"],
    ))
    elements.append(build_architecture_diagram())

    doc.build(elements)
    print(f"GENERATED:{OUTPUT_PATH}")


if __name__ == "__main__":
    build_report()
