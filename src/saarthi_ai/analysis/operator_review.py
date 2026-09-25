"""Append-only human verdicts for integrity-checked AI quality findings."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from saarthi_ai.analysis.quality import QualityAnalysisResult
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import AuditEventType, EvidenceRecord, EvidenceType

MAX_ANALYSIS_BYTES = 10_000_000
MAX_REVIEW_NOTE = 500


class OperatorVerdict(StrEnum):
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    NEEDS_EVIDENCE = "needs_more_evidence"


@dataclass(frozen=True)
class OperatorReview:
    evidence_id: str
    finding_id: str
    verdict: OperatorVerdict
    note: str
    actor: str
    reviewed_at: str


def load_quality_analysis(evidence: EvidenceRecord) -> QualityAnalysisResult:
    """Read a registered analysis only when its size and digest match."""

    if evidence.evidence_type is not EvidenceType.AI_QUALITY_ANALYSIS:
        raise ValueError("Selected evidence is not an AI quality analysis.")
    if not evidence.sha256 or len(evidence.sha256) != 64:
        raise ValueError("AI analysis has no registered SHA-256 digest.")
    path = Path(evidence.path)
    if not path.is_file() or path.stat().st_size > MAX_ANALYSIS_BYTES:
        raise ValueError("AI analysis is missing or exceeds the review size limit.")
    content = path.read_bytes()
    if hashlib.sha256(content).hexdigest() != evidence.sha256.lower():
        raise ValueError("AI analysis digest does not match its registered evidence.")
    result = QualityAnalysisResult.model_validate_json(content)
    finding_ids = [item.finding_id for item in result.findings]
    if len(finding_ids) != len(set(finding_ids)):
        raise ValueError("AI analysis contains duplicate finding IDs.")
    return result


def latest_quality_analysis(
    database: SaarthiDatabase,
) -> tuple[EvidenceRecord, QualityAnalysisResult] | None:
    """Return the newest integrity-checked analysis with reviewable findings."""

    for evidence in database.list_recent_evidence(EvidenceType.AI_QUALITY_ANALYSIS):
        try:
            result = load_quality_analysis(evidence)
        except (OSError, ValueError):
            continue
        # Interim snapshots can be superseded by later evidence. Only final
        # analyses are eligible for operator finding verdicts.
        if result.analysis_stage == "final" and result.findings:
            return evidence, result
    return None


def latest_operator_reviews(
    database: SaarthiDatabase,
    execution_id: str,
    evidence_id: str,
) -> dict[str, OperatorReview]:
    """Collapse immutable audit events to the latest verdict per finding."""

    reviews: dict[str, OperatorReview] = {}
    for event in database.list_audit_events(execution_id):
        if event.event_type is not AuditEventType.FINDING_REVIEWED:
            continue
        details = event.details
        if details.get("evidence_id") != evidence_id:
            continue
        try:
            verdict = OperatorVerdict(str(details.get("verdict")))
        except ValueError:
            continue
        finding_id = details.get("finding_id")
        if not isinstance(finding_id, str):
            continue
        reviews[finding_id] = OperatorReview(
            evidence_id=evidence_id,
            finding_id=finding_id,
            verdict=verdict,
            note=str(details.get("note", "")),
            actor=event.actor,
            reviewed_at=event.created_at.isoformat(),
        )
    return reviews


def operator_review_counts(database: SaarthiDatabase) -> dict[OperatorVerdict, int]:
    """Count latest human verdicts across saved analyses, excluding revisions."""

    latest: dict[tuple[str, str], OperatorVerdict] = {}
    with database.connect() as connection:
        rows = connection.execute(
            """SELECT details_json FROM audit_events WHERE event_type = ?
               ORDER BY created_at ASC, rowid ASC""",
            (AuditEventType.FINDING_REVIEWED.value,),
        ).fetchall()
    for row in rows:
        try:
            details = json.loads(row["details_json"])
            evidence_id = details["evidence_id"]
            finding_id = details["finding_id"]
            verdict = OperatorVerdict(details["verdict"])
        except (KeyError, TypeError, ValueError):
            continue
        if isinstance(evidence_id, str) and isinstance(finding_id, str):
            latest[(evidence_id, finding_id)] = verdict
    return {
        verdict: sum(item is verdict for item in latest.values())
        for verdict in OperatorVerdict
    }


def record_operator_review(
    database: SaarthiDatabase,
    evidence: EvidenceRecord,
    finding_id: str,
    verdict: OperatorVerdict,
    note: str,
    *,
    actor: str = "operator",
) -> OperatorReview:
    """Record a human decision without changing the AI result or scanners."""

    registered = next(
        (
            item for item in database.list_evidence(evidence.execution_id)
            if item.evidence_id == evidence.evidence_id
        ),
        None,
    )
    if registered is None or registered.sha256 != evidence.sha256:
        raise ValueError("AI analysis is not registered to this execution.")
    result = load_quality_analysis(registered)
    if finding_id not in {item.finding_id for item in result.findings}:
        raise ValueError("Finding ID is absent from this AI analysis.")
    if not isinstance(verdict, OperatorVerdict):
        raise ValueError("Operator verdict is invalid.")
    clean_note = note.strip()
    if not clean_note or len(clean_note) > MAX_REVIEW_NOTE:
        raise ValueError("Enter a review reason of 1–500 characters.")
    if not actor.strip() or len(actor) > 100:
        raise ValueError("Operator identity is invalid.")
    event = database.add_audit_event(
        evidence.execution_id,
        event_type=AuditEventType.FINDING_REVIEWED,
        actor=actor,
        message="Operator reviewed an AI quality finding.",
        details={
            "evidence_id": evidence.evidence_id,
            "analysis_sha256": evidence.sha256,
            "finding_id": finding_id,
            "verdict": verdict.value,
            "note": clean_note,
        },
    )
    return OperatorReview(
        evidence_id=evidence.evidence_id,
        finding_id=finding_id,
        verdict=verdict,
        note=clean_note,
        actor=actor,
        reviewed_at=event.created_at.isoformat(),
    )
