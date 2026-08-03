"""Persistent Phase 4C OAST-observation workflow."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from saarthi_ai.oast.models import (
    OastCorrelation,
    OastObservation,
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

DEFAULT_EVIDENCE_ROOT = Path("evidence") / "oast-observations"


class OastObservationWorkflowError(RuntimeError):
    """Raised when an OAST observation cannot be persisted safely."""


def _serialize_observation(
    observation: OastObservation,
    correlation: OastCorrelation,
) -> dict[str, object]:
    observation_payload = asdict(observation)

    return {
        "schema_version": "1.0",
        "phase": "4C",
        "evidence_type": EvidenceType.OAST_OBSERVATION.value,
        "recorded_at": datetime.now(UTC).isoformat(),
        "correlation": {
            "token_id": correlation.token_id,
            "token_hash": correlation.token_hash,
            "execution_id": correlation.execution_id,
            "protocol": correlation.protocol.value,
            "created_at": correlation.created_at.isoformat(),
            "expires_at": correlation.expires_at.isoformat(),
            "status": correlation.status.value,
        },
        "observation": {
            **observation_payload,
            "protocol": observation.protocol.value,
            "observed_at": observation.observed_at.isoformat(),
        },
    }


def _validate_safe_observation(
    observation: OastObservation,
    correlation: OastCorrelation,
) -> None:
    if observation.execution_id != correlation.execution_id:
        raise OastObservationWorkflowError(
            "Observation execution does not match its correlation."
        )

    if observation.token_id != correlation.token_id:
        raise OastObservationWorkflowError(
            "Observation token ID does not match its correlation."
        )

    if "[REDACTED]" not in observation.request_path:
        raise OastObservationWorkflowError(
            "Observation path must contain a redacted callback token."
        )

    if correlation.token_hash in observation.request_path:
        raise OastObservationWorkflowError(
            "Correlation hash must not appear in the callback path."
        )


def _write_evidence_atomically(
    payload: dict[str, object],
    *,
    evidence_root: Path | None = None,
) -> tuple[str, str, int]:
    evidence_directory = evidence_root or DEFAULT_EVIDENCE_ROOT
    evidence_directory.mkdir(parents=True, exist_ok=True)

    evidence_name = f"oast-observation-evidence-{uuid4()}"
    evidence_path = evidence_directory / f"{evidence_name}.json"

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
            prefix=".oast-observation-",
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


def persist_oast_observation(
    database: SaarthiDatabase,
    observation: OastObservation,
    correlation: OastCorrelation,
    *,
    actor: str = "oast-callback-manager",
    evidence_root: Path | None = None,
) -> EvidenceRecord:
    """Persist one already-correlated and redacted OAST observation."""

    execution = database.get_execution(observation.execution_id)

    if not execution.authorization_confirmed:
        raise InvalidStateTransitionError(
            "Execution does not have confirmed authorization."
        )

    if not execution.active_testing_allowed:
        raise InvalidStateTransitionError(
            "Execution does not allow active testing."
        )

    _validate_safe_observation(
        observation,
        correlation,
    )

    database.add_audit_event(
        observation.execution_id,
        event_type=AuditEventType.TOOL_STARTED,
        actor=actor,
        message="Saarthi Phase 4C OAST observation processing started.",
        details={
            "tool": "saarthi-oast-manager",
            "observation_id": observation.observation_id,
            "token_id": correlation.token_id,
            "protocol": observation.protocol.value,
            "request_method": observation.request_method,
            "request_path": observation.request_path,
            "body_size": observation.body_size,
        },
    )

    try:
        payload = _serialize_observation(
            observation,
            correlation,
        )

        evidence_path, evidence_sha256, evidence_size = (
            _write_evidence_atomically(
                payload,
                evidence_root=evidence_root,
            )
        )

        evidence = database.add_evidence(
            observation.execution_id,
            EvidenceCreate(
                evidence_type=EvidenceType.OAST_OBSERVATION,
                source="saarthi-oast-manager",
                path=evidence_path,
                sha256=evidence_sha256,
                size_bytes=evidence_size,
                content_type="application/json",
                step_id="oast-observation-001",
                tool_name="saarthi-oast-manager",
                metadata={
                    "phase": "4C",
                    "observation_id": observation.observation_id,
                    "token_id": correlation.token_id,
                    "token_hash": correlation.token_hash,
                    "protocol": observation.protocol.value,
                    "request_method": observation.request_method,
                    "request_path": observation.request_path,
                    "source_address": observation.source_address,
                    "body_size": observation.body_size,
                    "status": correlation.status.value,
                },
            ),
            actor=actor,
        )

        database.add_audit_event(
            observation.execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message="Saarthi Phase 4C OAST observation persisted.",
            details={
                "tool": "saarthi-oast-manager",
                "observation_id": observation.observation_id,
                "token_id": correlation.token_id,
                "evidence_id": evidence.evidence_id,
                "evidence_sha256": evidence_sha256,
                "request_path": observation.request_path,
            },
        )

        return evidence

    except (OSError, ValueError, TypeError) as exc:
        database.add_audit_event(
            observation.execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message="Saarthi Phase 4C OAST observation persistence failed.",
            details={
                "tool": "saarthi-oast-manager",
                "observation_id": observation.observation_id,
                "token_id": correlation.token_id,
                "error": str(exc),
            },
        )

        raise OastObservationWorkflowError(
            f"Unable to persist OAST observation: {exc}"
        ) from exc
