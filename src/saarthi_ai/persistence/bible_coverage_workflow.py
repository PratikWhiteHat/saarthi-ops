"""Persistent Phase 4E bible-coverage runner.

Loads the local vulnerability library, matches it against the run's gathered
Phase 3/4 evidence (deterministic keyword pass + optional local-LLM verdicts),
and persists a BIBLE_COVERAGE_RESULT with [4E] audit events. No network, no new
active testing — pure evaluation of already-collected evidence.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from saarthi_ai.knowledge.coverage import (
    apply_ai_classifications,
    build_evidence_corpus,
    classify_deterministic,
)
from saarthi_ai.knowledge.loader import BibleNotAvailableError, load_bible_catalog
from saarthi_ai.knowledge.models import CoverageResult, CoverageStatus
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceCreate,
    EvidenceRecord,
    EvidenceType,
)

DEFAULT_ORCHESTRATION_EVIDENCE_ROOT = Path("evidence/orchestrations")


@dataclass
class TrackedBibleCoverageResult:
    result: CoverageResult
    evidence: EvidenceRecord | None
    evidence_path: str | None
    catalog_available: bool


def run_tracked_bible_coverage(
    database: SaarthiDatabase,
    execution_id: str,
    *,
    orchestration_id: str,
    evidence_root: Path,
    ai_verdicts: dict[str, tuple[CoverageStatus, str]] | None = None,
    actor: str = "4e-bible-coverage",
) -> TrackedBibleCoverageResult:
    """Evaluate the vulnerability library against the run and persist a 4E result."""

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_STARTED,
        actor=actor,
        message="[4E] Bible coverage evaluation started.",
        details={
            "phase_code": "4E",
            "tool": "bible-coverage",
            "orchestration_id": orchestration_id,
        },
    )

    try:
        catalog = load_bible_catalog()
    except BibleNotAvailableError as exc:
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message=(
                "[4E] Bible coverage not applicable — no vulnerability "
                "library installed."
            ),
            details={
                "phase_code": "4E",
                "tool": "bible-coverage",
                "classification": "not_applicable",
                "reason": str(exc),
            },
        )
        return TrackedBibleCoverageResult(
            result=CoverageResult(),
            evidence=None,
            evidence_path=None,
            catalog_available=False,
        )

    corpus = build_evidence_corpus(database, orchestration_id)
    result = classify_deterministic(catalog, corpus)
    if ai_verdicts:
        result = apply_ai_classifications(result, ai_verdicts)

    for item in result.actionable:
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.FINDING_CREATED,
            actor=actor,
            message=(
                f"[4E] {item.status.value} ({item.severity.value}): "
                f"{item.title}"
            ),
            details={
                "phase_code": "4E",
                "tool": "bible-coverage",
                "entry_id": item.entry_id,
                "severity": item.severity.value,
                "status": item.status.value,
                "classification": item.status.value,
                "source": item.source,
            },
        )

    body = json.dumps(result.as_dict(), indent=2).encode("utf-8")
    sha = hashlib.sha256(body).hexdigest()
    evidence_root.mkdir(parents=True, exist_ok=True)
    path = evidence_root / f"bible-coverage-{sha[:12]}.json"
    path.write_bytes(body)

    counts = result.status_counts
    actionable = len(result.actionable)
    classification = "matches_found" if actionable else "no_matches"
    evidence = database.add_evidence(
        execution_id,
        EvidenceCreate(
            evidence_type=EvidenceType.BIBLE_COVERAGE_RESULT,
            source="bible-coverage",
            path=str(path),
            sha256=sha,
            size_bytes=len(body),
            content_type="application/json",
            step_id="phase4e-bible-coverage-001",
            tool_name="bible-coverage",
            metadata={
                "classification": classification,
                "status": "completed",
                "catalog_size": result.catalog_size,
                "ai_used": result.ai_used,
                "actionable": actionable,
                "confirmed": counts.get(CoverageStatus.CONFIRMED.value, 0),
                "likely": counts.get(CoverageStatus.LIKELY.value, 0),
                "manual_review": counts.get(
                    CoverageStatus.MANUAL_REVIEW.value, 0
                ),
            },
        ),
        actor=actor,
    )

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_COMPLETED,
        actor=actor,
        message=(
            f"[4E] Bible coverage completed: {actionable} actionable of "
            f"{result.catalog_size} checklist item(s); "
            f"ai_used={result.ai_used}."
        ),
        details={
            "phase_code": "4E",
            "tool": "bible-coverage",
            "actionable": actionable,
            "catalog_size": result.catalog_size,
            "classification": classification,
            "evidence_id": evidence.evidence_id,
        },
    )

    return TrackedBibleCoverageResult(
        result=result,
        evidence=evidence,
        evidence_path=str(path),
        catalog_available=True,
    )


__all__ = [
    "TrackedBibleCoverageResult",
    "run_tracked_bible_coverage",
]
