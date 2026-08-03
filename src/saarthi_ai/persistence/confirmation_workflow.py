"""Persistent Phase 4D confirmation workflow."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from uuid import uuid4

from saarthi_ai.confirmation.engine import evaluate_confirmation
from saarthi_ai.confirmation.models import (
    ConfirmationCandidate,
    ConfirmationDecision,
    ConfirmationStatus,
)
from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceCreate,
    EvidenceRecord,
    EvidenceType,
)

DEFAULT_EVIDENCE_ROOT = Path("evidence") / "confirmation-results"


class ConfirmationWorkflowError(RuntimeError):
    """Raised when confirmation evidence cannot be persisted safely."""


def _serialize_confirmation(
    candidate: ConfirmationCandidate,
    decision: ConfirmationDecision,
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "phase": "4D",
        "evidence_type": EvidenceType.CONFIRMATION_RESULT.value,
        "candidate": candidate.model_dump(mode="json"),
        "decision": decision.model_dump(mode="json"),
    }


def _write_evidence_atomically(
    payload: dict[str, object],
    *,
    evidence_root: Path | None = None,
) -> tuple[str, str, int]:
    evidence_directory = evidence_root or DEFAULT_EVIDENCE_ROOT
    evidence_directory.mkdir(parents=True, exist_ok=True)

    evidence_path = (
        evidence_directory
        / f"confirmation-result-{uuid4()}.json"
    )

    serialized = json.dumps(
        payload,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")

    temporary_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=evidence_directory,
            prefix=".confirmation-result-",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_file.write(serialized)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
            temporary_path = Path(temporary_file.name)

        os.replace(temporary_path, evidence_path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()

    return (
        str(evidence_path),
        hashlib.sha256(serialized).hexdigest(),
        len(serialized),
    )


def run_confirmation_workflow(
    database: SaarthiDatabase,
    candidate: ConfirmationCandidate,
    evidence_records: list[EvidenceRecord],
    *,
    actor: str = "saarthi-confirmation-engine",
    evidence_root: Path | None = None,
) -> tuple[ConfirmationDecision, EvidenceRecord]:
    """Evaluate and persist one deterministic confirmation decision."""

    execution = database.get_execution(candidate.execution_id)

    if not execution.authorization_confirmed:
        raise InvalidStateTransitionError(
            "Execution does not have confirmed authorization."
        )

    database.add_audit_event(
        candidate.execution_id,
        event_type=AuditEventType.TOOL_STARTED,
        actor=actor,
        message="Saarthi Phase 4D confirmation evaluation started.",
        details={
            "tool": "saarthi-confirmation-engine",
            "candidate_id": candidate.candidate_id,
            "candidate_type": candidate.candidate_type,
        },
    )

    try:
        decision = evaluate_confirmation(
            candidate,
            evidence_records,
        )

        payload = _serialize_confirmation(
            candidate,
            decision,
        )

        evidence_path, evidence_sha256, evidence_size = (
            _write_evidence_atomically(
                payload,
                evidence_root=evidence_root,
            )
        )

        evidence = database.add_evidence(
            candidate.execution_id,
            EvidenceCreate(
                evidence_type=EvidenceType.CONFIRMATION_RESULT,
                source="saarthi-confirmation-engine",
                path=evidence_path,
                sha256=evidence_sha256,
                size_bytes=evidence_size,
                content_type="application/json",
                step_id="confirmation-001",
                tool_name="saarthi-confirmation-engine",
                metadata={
                    "phase": "4D",
                    "candidate_id": candidate.candidate_id,
                    "candidate_type": candidate.candidate_type,
                    "status": decision.status.value,
                    "supporting_evidence_ids": list(
                        decision.supporting_evidence_ids
                    ),
                    "rejected_evidence_ids": list(
                        decision.rejected_evidence_ids
                    ),
                },
            ),
            actor=actor,
        )

        if decision.status is ConfirmationStatus.CONFIRMED:
            database.add_audit_event(
                candidate.execution_id,
                event_type=AuditEventType.FINDING_CREATED,
                actor=actor,
                message="Confirmed finding created from explicit evidence.",
                details={
                    "tool": "saarthi-confirmation-engine",
                    "candidate_id": candidate.candidate_id,
                    "candidate_type": candidate.candidate_type,
                    "confirmation_evidence_id": evidence.evidence_id,
                    "supporting_evidence_ids": list(
                        decision.supporting_evidence_ids
                    ),
                },
            )

        database.add_audit_event(
            candidate.execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message="Saarthi Phase 4D confirmation evaluation completed.",
            details={
                "tool": "saarthi-confirmation-engine",
                "candidate_id": candidate.candidate_id,
                "status": decision.status.value,
                "evidence_id": evidence.evidence_id,
                "evidence_sha256": evidence_sha256,
            },
        )

        return decision, evidence

    except (OSError, TypeError, ValueError) as exc:
        database.add_audit_event(
            candidate.execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message="Saarthi Phase 4D confirmation evaluation failed.",
            details={
                "tool": "saarthi-confirmation-engine",
                "candidate_id": candidate.candidate_id,
                "error": str(exc),
            },
        )

        raise ConfirmationWorkflowError(
            f"Unable to persist confirmation result: {exc}"
        ) from exc
