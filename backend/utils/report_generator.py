#backend\utils\report_generator.py

import os
import json
from datetime import datetime, timezone, timedelta
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch
from sqlalchemy.orm import Session
from sqlalchemy import func
import models

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports_out")
os.makedirs(REPORTS_DIR, exist_ok=True)


def _get_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="TitleCustom",
        parent=styles["Title"],
        fontSize=24,
        textColor=HexColor("#2E75B6"),
        spaceAfter=20,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeader",
        parent=styles["Heading2"],
        textColor=HexColor("#E6EDF3"),
        fontSize=14,
        spaceAfter=10,
        spaceBefore=20,
    ))
    return styles


def generate_ioc_report(investigation_id: int, db: Session) -> str:
    """Generate PDF report for an IOC investigation."""
    record = db.query(models.IOCResult).filter(models.IOCResult.id == investigation_id).first()
    if not record:
        raise ValueError("Investigation not found")

    filename = f"ioc_report_{record.ioc.replace('.', '_').replace(':', '_')}_{record.id}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)
    styles = _get_styles()

    doc = SimpleDocTemplate(filepath, pagesize=letter)
    elements = []

    # Title
    elements.append(Paragraph("ThreatHawk IOC Investigation Report", styles["TitleCustom"]))
    elements.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
    elements.append(Spacer(1, 20))

    # IOC Summary
    elements.append(Paragraph("IOC Summary", styles["SectionHeader"]))
    summary_data = [
        ["IOC Value", record.ioc],
        ["IOC Type", record.ioc_type],
        ["Threat Score", f"{record.threat_score}/100"],
        ["Severity", record.severity],
        ["Investigated At", str(record.created_at)],
    ]
    t = Table(summary_data, colWidths=[2 * inch, 4.5 * inch])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#30363D")),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 20))

    # Per-source evidence
    results = json.loads(record.raw_results) if record.raw_results else {}
    for source, data in results.items():
        elements.append(Paragraph(f"Source: {source.upper()}", styles["SectionHeader"]))
        if isinstance(data, dict) and data.get("success"):
            source_data = data.get("data", {})
            rows = [[str(k), str(v)[:80]] for k, v in source_data.items() if v]
            if rows:
                t = Table(rows, colWidths=[2 * inch, 4.5 * inch])
                t.setStyle(TableStyle([
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("GRID", (0, 0), (-1, -1), 0.25, HexColor("#30363D")),
                ]))
                elements.append(t)
        elif isinstance(data, dict):
            elements.append(Paragraph(f"Error: {data.get('error', 'Unknown')}", styles["Normal"]))
        elements.append(Spacer(1, 10))

    # Recommendations
    elements.append(Paragraph("Recommendations", styles["SectionHeader"]))
    if record.severity == "Critical":
        elements.append(Paragraph("⚠ CRITICAL: Immediate action required. Block this IOC at all perimeter defenses and investigate any internal connections.", styles["Normal"]))
    elif record.severity == "High":
        elements.append(Paragraph("⚠ HIGH: This IOC should be blocked and monitored. Review logs for any historical connections.", styles["Normal"]))
    elif record.severity == "Medium":
        elements.append(Paragraph("This IOC shows moderate risk. Add to watchlist and monitor for further activity.", styles["Normal"]))
    else:
        elements.append(Paragraph("This IOC appears to be low risk. Continue monitoring.", styles["Normal"]))

    doc.build(elements)

    # Save to DB
    report = models.Report(
        title=f"IOC Report: {record.ioc}",
        report_type="ioc",
        file_path=filename,
        case_id=record.case_id,
        created_at=datetime.now(timezone.utc),
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    return report.id


def generate_case_report(case_id: int, db: Session) -> str:
    """Generate PDF report for a case."""
    case = db.query(models.Case).filter(models.Case.id == case_id).first()
    if not case:
        raise ValueError("Case not found")

    filename = f"case_report_{case.id}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)
    styles = _get_styles()

    doc = SimpleDocTemplate(filepath, pagesize=letter)
    elements = []

    elements.append(Paragraph("ThreatHawk Case Report", styles["TitleCustom"]))
    elements.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
    elements.append(Spacer(1, 20))

    # Case Summary
    elements.append(Paragraph("Case Summary", styles["SectionHeader"]))
    summary_data = [
        ["Title", case.title],
        ["Status", case.status],
        ["Severity", case.severity],
        ["Created", str(case.created_at)],
        ["Last Updated", str(case.updated_at)],
    ]
    t = Table(summary_data, colWidths=[2 * inch, 4.5 * inch])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#30363D")),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 10))

    if case.description:
        elements.append(Paragraph("Description", styles["SectionHeader"]))
        elements.append(Paragraph(case.description, styles["Normal"]))

    if case.notes:
        elements.append(Paragraph("Analyst Notes", styles["SectionHeader"]))
        elements.append(Paragraph(case.notes, styles["Normal"]))

    # Linked IOCs
    linked_iocs = db.query(models.IOCResult).filter(models.IOCResult.case_id == case_id).all()
    if linked_iocs:
        elements.append(Paragraph(f"Linked IOCs ({len(linked_iocs)})", styles["SectionHeader"]))
        ioc_rows = [["IOC", "Type", "Score", "Severity"]]
        for ioc in linked_iocs:
            ioc_rows.append([ioc.ioc, ioc.ioc_type, str(ioc.threat_score), ioc.severity])
        t = Table(ioc_rows, colWidths=[2.5 * inch, 1 * inch, 1 * inch, 1.5 * inch])
        t.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.25, HexColor("#30363D")),
        ]))
        elements.append(t)

    # Linked Victims
    linked_victims = db.query(models.DarkWebVictim).filter(models.DarkWebVictim.case_id == case_id).all()
    if linked_victims:
        elements.append(Paragraph(f"Linked Dark Web Victims ({len(linked_victims)})", styles["SectionHeader"]))
        victim_rows = [["Victim", "Gang", "Country", "Sector"]]
        for v in linked_victims:
            victim_rows.append([v.victim_name, v.gang, v.country or "—", v.sector or "—"])
        t = Table(victim_rows, colWidths=[2 * inch, 1.5 * inch, 1 * inch, 1.5 * inch])
        t.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.25, HexColor("#30363D")),
        ]))
        elements.append(t)

    doc.build(elements)

    report = models.Report(
        title=f"Case Report: {case.title}",
        report_type="case",
        file_path=filename,
        case_id=case_id,
        created_at=datetime.now(timezone.utc),
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    return report.id


def generate_darkweb_report(db: Session) -> str:
    """Generate weekly dark web summary report."""
    now = datetime.now(timezone.utc)
    week_ago = now - timedelta(days=7)

    filename = f"darkweb_weekly_{now.strftime('%Y%m%d')}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)
    styles = _get_styles()

    doc = SimpleDocTemplate(filepath, pagesize=letter)
    elements = []

    elements.append(Paragraph("ThreatHawk Dark Web Weekly Report", styles["TitleCustom"]))
    elements.append(Paragraph(f"Period: {week_ago.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')}", styles["Normal"]))
    elements.append(Spacer(1, 20))

    # New victims this week
    new_victims = db.query(models.DarkWebVictim).filter(
        models.DarkWebVictim.created_at >= week_ago
    ).all()

    elements.append(Paragraph(f"New Victims This Week: {len(new_victims)}", styles["SectionHeader"]))
    if new_victims:
        rows = [["Victim", "Gang", "Country", "Sector", "Date"]]
        for v in new_victims[:30]:
            rows.append([v.victim_name, v.gang, v.country or "—", v.sector or "—", str(v.created_at)[:10]])
        t = Table(rows, colWidths=[1.8 * inch, 1.2 * inch, 0.8 * inch, 1 * inch, 1 * inch])
        t.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.25, HexColor("#30363D")),
        ]))
        elements.append(t)

    # By gang
    by_gang = db.query(
        models.DarkWebVictim.gang, func.count(models.DarkWebVictim.id)
    ).filter(
        models.DarkWebVictim.created_at >= week_ago
    ).group_by(models.DarkWebVictim.gang).all()

    if by_gang:
        elements.append(Paragraph("Breakdown by Gang", styles["SectionHeader"]))
        rows = [["Gang", "Victims"]]
        for g, c in by_gang:
            rows.append([g, str(c)])
        t = Table(rows, colWidths=[3 * inch, 1.5 * inch])
        t.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.25, HexColor("#30363D")),
        ]))
        elements.append(t)

    # Paste intelligence
    new_pastes = db.query(models.PasteEntry).filter(
        models.PasteEntry.created_at >= week_ago
    ).count()
    elements.append(Paragraph(f"Paste Intelligence Signals: {new_pastes}", styles["SectionHeader"]))

    doc.build(elements)

    report = models.Report(
        title=f"Dark Web Weekly: {now.strftime('%Y-%m-%d')}",
        report_type="darkweb",
        file_path=filename,
        created_at=datetime.now(timezone.utc),
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    return report.id
