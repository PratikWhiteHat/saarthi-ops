"""Persistent Phase 8A reporting runner.

Assembles the engagement's confirmed/actionable findings into a report model,
renders the pack's `.docx` template (plus a JSON sidecar), and persists an
ASSESSMENT_REPORT evidence record with [8A] audit events. Findings and
severities are deterministic; only the executive-summary prose is (optionally)
model-written and is passed in by the caller.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from saarthi_ai.knowledge.loader import report_template_path
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceCreate,
    EvidenceRecord,
    EvidenceType,
)
from saarthi_ai.reporting.builder import build_report_model
from saarthi_ai.reporting.docx_renderer import render_report_docx
from saarthi_ai.reporting.html_renderer import render_report_html
from saarthi_ai.reporting.json_renderer import render_report_json
from saarthi_ai.reporting.markdown_renderer import render_report_markdown
from saarthi_ai.reporting.models import EngagementMeta, ReportModel
from saarthi_ai.reporting.narrative import fallback_summary
from saarthi_ai.reporting.pdf import render_report_pdf


@dataclass
class TrackedReportResult:
    model: ReportModel
    evidence: EvidenceRecord | None
    docx_path: str
    json_path: str
    markdown_path: str
    html_path: str
    pdf_path: str | None = None


def run_tracked_report(
    database: SaarthiDatabase,
    execution_id: str,
    *,
    orchestration_id: str,
    evidence_root: Path,
    engagement: EngagementMeta | None = None,
    executive_summary: str | None = None,
    actor: str = "8a-report",
) -> TrackedReportResult:
    """Build and persist the Phase 8A assessment report."""

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_STARTED,
        actor=actor,
        message="[8A] Report generation started.",
        details={
            "phase_code": "8A",
            "tool": "report",
            "orchestration_id": orchestration_id,
        },
    )

    model = build_report_model(
        database,
        orchestration_id=orchestration_id,
        engagement=engagement,
    )
    if executive_summary:
        model.executive_summary = executive_summary
        model.ai_narrative_used = True
    else:
        model.executive_summary = fallback_summary(model)
        model.ai_narrative_used = False

    evidence_root.mkdir(parents=True, exist_ok=True)
    template = report_template_path()

    json_sha = hashlib.sha256(
        json.dumps(model.as_dict(), indent=2).encode("utf-8")
    ).hexdigest()
    slug = json_sha[:12]

    docx_path = evidence_root / f"assessment-report-{slug}.docx"
    json_path = evidence_root / f"assessment-report-{slug}.json"
    markdown_path = evidence_root / f"assessment-report-{slug}.md"
    html_path = evidence_root / f"assessment-report-{slug}.html"
    pdf_path = evidence_root / f"assessment-report-{slug}.pdf"

    render_report_docx(model, docx_path, template_path=template)
    render_report_json(model, json_path)
    render_report_markdown(model, markdown_path)
    render_report_html(model, html_path)
    # PDF is best-effort (needs a local LibreOffice); never abort on failure.
    produced_pdf = render_report_pdf(docx_path, pdf_path)

    docx_bytes = docx_path.read_bytes()
    docx_sha = hashlib.sha256(docx_bytes).hexdigest()

    counts = model.severity_counts
    evidence = database.add_evidence(
        execution_id,
        EvidenceCreate(
            evidence_type=EvidenceType.ASSESSMENT_REPORT,
            source="report",
            path=str(docx_path),
            sha256=docx_sha,
            size_bytes=len(docx_bytes),
            content_type=(
                "application/vnd.openxmlformats-officedocument."
                "wordprocessingml.document"
            ),
            step_id="phase8a-report-001",
            tool_name="report",
            metadata={
                "classification": "report_generated",
                "status": "completed",
                "findings": len(model.findings),
                "highest_severity": model.highest_severity.value,
                "overall_posture": model.overall_posture,
                "ai_narrative_used": model.ai_narrative_used,
                "template_used": template is not None,
                "critical": counts["critical"],
                "high": counts["high"],
                "json_path": str(json_path),
                "markdown_path": str(markdown_path),
                "html_path": str(html_path),
                "pdf_path": str(produced_pdf) if produced_pdf else None,
                "formats": [
                    fmt
                    for fmt, present in (
                        ("docx", True),
                        ("json", True),
                        ("md", True),
                        ("html", True),
                        ("pdf", produced_pdf is not None),
                    )
                    if present
                ],
            },
        ),
        actor=actor,
    )

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_COMPLETED,
        actor=actor,
        message=(
            f"[8A] Report generated: {len(model.findings)} finding(s); "
            f"highest {model.highest_severity.value}; "
            f"template_used={template is not None}."
        ),
        details={
            "phase_code": "8A",
            "tool": "report",
            "findings": len(model.findings),
            "evidence_id": evidence.evidence_id,
            "docx_path": str(docx_path),
            "json_path": str(json_path),
            "markdown_path": str(markdown_path),
            "html_path": str(html_path),
            "pdf_path": str(produced_pdf) if produced_pdf else None,
        },
    )

    return TrackedReportResult(
        model=model,
        evidence=evidence,
        docx_path=str(docx_path),
        json_path=str(json_path),
        markdown_path=str(markdown_path),
        html_path=str(html_path),
        pdf_path=str(produced_pdf) if produced_pdf else None,
    )


__all__ = ["TrackedReportResult", "run_tracked_report"]
