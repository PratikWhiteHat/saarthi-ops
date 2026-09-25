"""Shared wiring to run Phase 4E (bible coverage) and Phase 8A (report).

Both the CLI (`workflow run`, `report`) and the TUI drive the same sequence:
create a phase child, optionally enrich with the local model, run the tracked
workflow, and mark the phase complete. Centralizing it here keeps the callers
tiny and the behavior identical.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from saarthi_ai.config import Settings, get_settings
from saarthi_ai.knowledge.coverage import build_evidence_corpus, classify_with_llm
from saarthi_ai.knowledge.loader import BibleNotAvailableError, load_bible_catalog
from saarthi_ai.llm.ollama_client import OllamaUnavailableError, SaarthiOllamaClient
from saarthi_ai.orchestration.models import OrchestrationContext, OrchestrationPhase
from saarthi_ai.persistence.bible_coverage_workflow import (
    TrackedBibleCoverageResult,
    run_tracked_bible_coverage,
)
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.orchestration_workflow import (
    complete_phase_execution,
    create_phase_execution,
)
from saarthi_ai.persistence.reporting_workflow import (
    TrackedReportResult,
    run_tracked_report,
)
from saarthi_ai.reporting.builder import build_report_model
from saarthi_ai.reporting.models import EngagementMeta
from saarthi_ai.reporting.narrative import generate_executive_summary

LogFn = Callable[[str], None]


def _ordinal_date() -> str:
    """Return today's date as e.g. '11th Aug 2026' to match the template."""

    today = date.today()
    day = today.day
    if 11 <= day % 100 <= 13:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")
    return f"{day}{suffix} {today.strftime('%b %Y')}"


def engagement_from_settings(
    settings: Settings | None = None,
    **overrides: object,
) -> EngagementMeta:
    """Build engagement metadata from SAARTHI_REPORT_* settings + overrides."""

    cfg = settings or get_settings()
    meta = EngagementMeta(
        company=cfg.report_company,
        company_short=cfg.report_company_short,
        author=cfg.report_author,
        reviewer=cfg.report_reviewer,
        classification=cfg.report_classification,
        report_date=_ordinal_date(),
    )
    if overrides:
        meta = meta.model_copy(update={k: v for k, v in overrides.items() if v is not None})
    return meta


@dataclass
class ReportingPhasesResult:
    coverage: TrackedBibleCoverageResult
    report: TrackedReportResult


def run_reporting_phases(
    database: SaarthiDatabase,
    context: OrchestrationContext,
    *,
    evidence_root: Path,
    engagement: EngagementMeta | None = None,
    use_ai: bool = True,
    on_log: LogFn | None = None,
) -> ReportingPhasesResult:
    """Run Phase 4E bible coverage then Phase 8A report for an orchestration."""

    log = on_log or (lambda _message: None)
    oid = context.orchestration_id

    # --- Phase 4E: bible coverage -------------------------------------------
    coverage_child = create_phase_execution(
        database,
        context,
        phase=OrchestrationPhase.BIBLE_COVERAGE,
        phase_name="bible-coverage",
        active_testing_allowed=False,
    )

    ai_verdicts = None
    if use_ai:
        try:
            catalog = load_bible_catalog()
        except BibleNotAvailableError:
            catalog = None
        if catalog is not None:
            corpus = build_evidence_corpus(database, oid)
            try:
                client = SaarthiOllamaClient(get_settings())
                ai_verdicts = asyncio.run(
                    classify_with_llm(client, catalog, corpus)
                )
            except OllamaUnavailableError:
                log(
                    "[4E] Local model unavailable — deterministic coverage "
                    "only."
                )
                ai_verdicts = None

    coverage = run_tracked_bible_coverage(
        database,
        coverage_child.execution_id,
        orchestration_id=oid,
        evidence_root=evidence_root / "bible-coverage",
        ai_verdicts=ai_verdicts,
    )
    complete_phase_execution(
        database, coverage_child.execution_id, actor="4e-bible-coverage"
    )
    if coverage.catalog_available:
        log(
            f"[4E] Bible coverage: {len(coverage.result.actionable)} "
            f"actionable of {coverage.result.catalog_size}."
        )
    else:
        log("[4E] No vulnerability library installed — coverage skipped.")

    # --- Phase 8A: report ----------------------------------------------------
    report_child = create_phase_execution(
        database,
        context,
        phase=OrchestrationPhase.REPORT,
        phase_name="reporting",
        active_testing_allowed=False,
    )

    meta = engagement or engagement_from_settings()
    executive_summary = None
    if use_ai:
        try:
            preview = build_report_model(
                database, orchestration_id=oid, engagement=meta
            )
            client = SaarthiOllamaClient(get_settings())
            executive_summary = asyncio.run(
                generate_executive_summary(client, preview)
            )
        except OllamaUnavailableError:
            log("[8A] Local model unavailable — templated executive summary.")
            executive_summary = None

    report = run_tracked_report(
        database,
        report_child.execution_id,
        orchestration_id=oid,
        evidence_root=evidence_root / "reports",
        engagement=meta,
        executive_summary=executive_summary,
    )
    complete_phase_execution(
        database, report_child.execution_id, actor="8a-report"
    )
    log(
        f"[8A] Report written: {report.docx_path} "
        f"({len(report.model.findings)} finding(s))."
    )

    return ReportingPhasesResult(coverage=coverage, report=report)


__all__ = [
    "ReportingPhasesResult",
    "engagement_from_settings",
    "run_reporting_phases",
]
