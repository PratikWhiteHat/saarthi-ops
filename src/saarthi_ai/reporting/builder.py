"""Assemble a :class:`ReportModel` from an engagement's stored evidence."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from saarthi_ai.exploit_confirmation.models import severity_rank
from saarthi_ai.knowledge.loader import BibleNotAvailableError, load_bible_catalog
from saarthi_ai.knowledge.models import BibleCatalog, CoverageResult, CoverageStatus
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import EvidenceType
from saarthi_ai.reporting.cvss import classify as classify_cvss
from saarthi_ai.reporting.models import (
    DEFAULT_METHODOLOGY,
    EngagementMeta,
    ReportFinding,
    ReportModel,
    estimate_effort,
)

_POSTURE_BY_HIGHEST = {
    "critical": "Critical — Immediate Action Required",
    "high": "Poor — Significant Weaknesses",
    "medium": "Needs Improvement",
    "low": "Fair",
    "info": "Good",
}


def _load_latest_evidence_json(
    database: SaarthiDatabase,
    orchestration_id: str,
    evidence_type: EvidenceType,
) -> dict | None:
    """Return the most recent evidence JSON of ``evidence_type`` for a run."""

    try:
        executions = database.list_executions(limit=1_000)
    except Exception:
        return None

    latest: dict | None = None
    for execution in executions:
        meta = execution.metadata or {}
        if meta.get("orchestration_id") != orchestration_id:
            continue
        for evidence in database.list_evidence(execution.execution_id):
            if evidence.evidence_type is evidence_type and evidence.path:
                try:
                    latest = json.loads(
                        Path(evidence.path).read_text(encoding="utf-8")
                    )
                except (OSError, json.JSONDecodeError):
                    continue
    return latest


def _resolve_target(
    database: SaarthiDatabase,
    orchestration_id: str,
) -> str:
    try:
        executions = database.list_executions(limit=1_000)
    except Exception:
        return ""
    for execution in executions:
        meta = execution.metadata or {}
        if (
            meta.get("orchestration_id") == orchestration_id
            and execution.targets
        ):
            return str(execution.targets[0])
    return ""


def _collect_tools_used(
    database: SaarthiDatabase,
    orchestration_id: str,
) -> list[str]:
    """Return the distinct real tools recorded across the run's evidence."""

    try:
        executions = database.list_executions(limit=1_000)
    except Exception:
        return []

    seen: dict[str, None] = {}
    for execution in executions:
        meta = execution.metadata or {}
        if meta.get("orchestration_id") != orchestration_id:
            continue
        for evidence in database.list_evidence(execution.execution_id):
            tool = (evidence.tool_name or "").strip()
            # Skip the reporting phase's own synthetic tool name.
            if tool and tool.lower() != "report":
                seen.setdefault(tool, None)
    return sorted(seen)


def _confirmed_titles(exploit_payload: dict | None) -> set[str]:
    """Return lowercased kinds/tools of confirmed 6E findings for cross-ref."""

    if not exploit_payload:
        return set()
    titles: set[str] = set()
    for finding in exploit_payload.get("findings", []) or []:
        if not isinstance(finding, dict):
            continue
        if finding.get("verdict") == "confirmed_impact":
            for key in ("kind", "source_tool"):
                value = finding.get(key)
                if value:
                    titles.add(str(value).lower())
    return titles


def build_report_model(
    database: SaarthiDatabase,
    *,
    orchestration_id: str,
    engagement: EngagementMeta | None = None,
    catalog: BibleCatalog | None = None,
) -> ReportModel:
    """Build a report model from the run's coverage + confirmation evidence."""

    if catalog is None:
        try:
            catalog = load_bible_catalog()
        except BibleNotAvailableError:
            catalog = BibleCatalog()

    target = _resolve_target(database, orchestration_id)
    meta = engagement or EngagementMeta()
    if meta.org_name == "ORGNAME" and target:
        host = urlparse(target).netloc or target
        meta = meta.model_copy(update={"org_name": host, "app_name": target})
    if not meta.scope_urls and target:
        meta = meta.model_copy(update={"scope_urls": [target]})

    coverage_payload = _load_latest_evidence_json(
        database, orchestration_id, EvidenceType.BIBLE_COVERAGE_RESULT
    )
    exploit_payload = _load_latest_evidence_json(
        database, orchestration_id, EvidenceType.EXPLOIT_CONFIRMATION_RESULT
    )
    confirmed_refs = _confirmed_titles(exploit_payload)

    findings: list[ReportFinding] = []
    if coverage_payload:
        coverage = CoverageResult.model_validate(coverage_payload)
        actionable = coverage.actionable
        # Worst severity first so report numbering follows the summary table.
        actionable.sort(key=lambda c: (-severity_rank(c.severity), c.entry_id))
        number = 0
        for item in actionable:
            entry = catalog.get(item.entry_id)
            number += 1
            exploited = item.status == CoverageStatus.CONFIRMED or any(
                token in item.entry_id for token in confirmed_refs
            )
            cvss = classify_cvss(item.title, item.severity)
            findings.append(
                ReportFinding(
                    finding_id=item.entry_id,
                    number=number,
                    title=item.title,
                    severity=item.severity,
                    rating_label=(entry.rating if entry else ""),
                    exploited_verified=exploited,
                    affected_urls=list(meta.scope_urls) or ([target] if target else []),
                    description=(entry.description if entry else ""),
                    security_risk=(entry.security_risk if entry else ""),
                    recommendation=(entry.recommendation if entry else ""),
                    references=(entry.references if entry else ""),
                    proof_of_concept=(entry.proof_of_concept if entry else ""),
                    cvss_vector=cvss.vector,
                    cvss_score=cvss.score,
                    remediation_effort=estimate_effort(
                        item.title, item.severity
                    ),
                    source="bible-coverage",
                    coverage_status=item.status.value,
                )
            )

    model = ReportModel(
        engagement=meta,
        orchestration_id=orchestration_id,
        target=target,
        findings=findings,
        methodology=DEFAULT_METHODOLOGY,
        tools_used=_collect_tools_used(database, orchestration_id),
    )
    model.overall_posture = _POSTURE_BY_HIGHEST.get(
        model.highest_severity.value, "Needs Improvement"
    )
    return model


__all__ = ["build_report_model"]
