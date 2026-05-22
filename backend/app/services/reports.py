from __future__ import annotations

from collections import Counter
from io import BytesIO
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Assessment, Asset, Finding
from app.services.rules import SEVERITY_ORDER

REPORT_TYPES = {
    "executive-summary": "Executive Summary",
    "technical-findings": "Technical Findings Report",
    "asset-inventory": "Asset Inventory Report",
    "remediation-plan": "Remediation Plan",
    "backup-readiness": "Backup and Recovery Readiness Report",
}


def template_env() -> Environment:
    root = Path(__file__).resolve().parents[3]
    return Environment(
        loader=FileSystemLoader(str(root / "reports" / "templates")),
        autoescape=select_autoescape(["html", "xml"]),
    )


def report_context(db: Session, assessment: Assessment) -> dict[str, Any]:
    assets = list(db.scalars(select(Asset).where(Asset.assessment_id == assessment.id)))
    findings = list(db.scalars(select(Finding).where(Finding.assessment_id == assessment.id)))
    open_findings = [finding for finding in findings if finding.status == "Open"]
    severity_counts = Counter(finding.severity for finding in open_findings)
    category_counts = Counter(finding.category for finding in open_findings)
    weighted = sum((SEVERITY_ORDER.get(f.severity, 0) + 1) * 6 for f in open_findings)
    risk_score = min(100, weighted)
    backup_covered = [
        asset
        for asset in assets
        if str((asset.metadata_json or {}).get("backup_status", "")).lower()
        in {"covered", "healthy", "success"}
    ]
    endpoint_security_reported = [
        asset
        for asset in assets
        if (asset.metadata_json or {}).get("endpoint_security_status")
        not in {None, "", "unknown", "not_reported", "none", "missing"}
    ]
    top_risks = sorted(
        open_findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.severity, 0),
            finding.confidence_score,
            finding.last_seen,
        ),
        reverse=True,
    )[:10]

    return {
        "assessment": assessment,
        "client": assessment.client,
        "assets": assets,
        "findings": findings,
        "open_findings": open_findings,
        "top_risks": top_risks,
        "severity_counts": dict(severity_counts),
        "category_counts": dict(category_counts),
        "risk_score": risk_score,
        "backup_coverage_percent": (
            round((len(backup_covered) / len(assets)) * 100, 1) if assets else 0
        ),
        "endpoint_coverage_percent": (
            round((len(endpoint_security_reported) / len(assets)) * 100, 1) if assets else 0
        ),
        "backup_missing": [asset for asset in assets if asset not in backup_covered],
        "report_types": REPORT_TYPES,
    }


def render_report_html(db: Session, assessment: Assessment, report_type: str) -> str:
    if report_type not in REPORT_TYPES:
        raise ValueError("Unknown report type.")
    env = template_env()
    template = env.get_template(f"{report_type}.html")
    return template.render(**report_context(db, assessment), report_title=REPORT_TYPES[report_type])


def render_report_pdf(db: Session, assessment: Assessment, report_type: str) -> bytes:
    if report_type not in REPORT_TYPES:
        raise ValueError("Unknown report type.")
    context = report_context(db, assessment)
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=LETTER, title=REPORT_TYPES[report_type])
    styles = getSampleStyleSheet()
    story: list[Any] = [
        Paragraph(REPORT_TYPES[report_type], styles["Title"]),
        Paragraph(f"{assessment.client.name} - {assessment.name}", styles["Heading2"]),
        Spacer(1, 12),
        Paragraph(
            "This report summarizes risk indicators and recommended remediation based on imported, "
            "authorized assessment evidence.",
            styles["BodyText"],
        ),
        Spacer(1, 12),
        Paragraph(f"Overall risk indicator score: {context['risk_score']}/100", styles["Heading3"]),
        Spacer(1, 12),
    ]

    findings = context["open_findings"] if report_type != "asset-inventory" else []
    if findings:
        table_rows = [["Severity", "Category", "Finding", "Status"]]
        for finding in findings[:40]:
            table_rows.append([finding.severity, finding.category, finding.title, finding.status])
        table = Table(table_rows, colWidths=[75, 105, 260, 80])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(table)
    else:
        table_rows = [["Hostname", "IP address", "OS", "Criticality", "Last seen"]]
        for asset in context["assets"][:60]:
            table_rows.append(
                [
                    asset.hostname,
                    asset.ip_address or "",
                    " ".join(item for item in [asset.os_family, asset.os_version] if item),
                    asset.criticality,
                    asset.last_seen.isoformat() if asset.last_seen else "",
                ]
            )
        table = Table(table_rows, colWidths=[130, 90, 150, 80, 100])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(table)

    story.append(Spacer(1, 16))
    story.append(
        Paragraph(
            "PDF output is generated locally from the platform data model. Use the HTML preview for "
            "full detail and styling when deeper evidence review is needed.",
            styles["Italic"],
        )
    )
    doc.build(story)
    return buffer.getvalue()
