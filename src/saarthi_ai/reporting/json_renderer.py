"""Render a :class:`ReportModel` to a machine-readable JSON sidecar."""

from __future__ import annotations

import json
from pathlib import Path

from saarthi_ai.reporting.models import (
    ReportModel,
    priority_band,
    severity_rating_key,
)


def render_report_json(model: ReportModel, destination: str | Path) -> Path:
    """Write ``model`` to ``destination`` as structured JSON and return it."""

    payload = {
        "schema": "saarthi.report/2",
        "orchestration_id": model.orchestration_id,
        "target": model.target,
        "engagement": model.engagement.model_dump(mode="json"),
        "overall_posture": model.overall_posture,
        "ai_narrative_used": model.ai_narrative_used,
        "executive_summary": model.executive_summary,
        "methodology": model.methodology,
        "tools_used": model.tools_used,
        "severity_key": severity_rating_key(),
        "severity_counts": model.severity_counts,
        "highest_severity": model.highest_severity.value,
        "findings": [
            {
                **finding.model_dump(mode="json"),
                "section_id": finding.section_id,
                "priority": priority_band(finding.severity)[0],
                "cvss_range": priority_band(finding.severity)[2],
            }
            for finding in model.sorted_findings
        ],
        "remediation_roadmap": [
            item.model_dump(mode="json")
            for item in model.remediation_roadmap
        ],
    }
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


__all__ = ["render_report_json"]
