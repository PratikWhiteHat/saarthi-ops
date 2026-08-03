"""Persistent Phase 4B blind-validation correlation workflow."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

from saarthi_ai.blind_validation.models import (
    BlindValidationDecision,
    BlindValidationRequest,
    BlindValidationStatus,
    CorrelationToken,
)
from saarthi_ai.blind_validation.policy import evaluate_blind_validation
from saarthi_ai.blind_validation.tokens import generate_correlation_token
from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.http_intelligence_workflow import (
    _domain_in_execution_scope,
)
from saarthi_ai.persistence.http_workflow import (
    advance_execution_to_running,
    fail_execution_safely,
)
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceCreate,
    EvidenceRecord,
    EvidenceType,
    ExecutionRecord,
    ExecutionState,
)

DEFAULT_EVIDENCE_ROOT = Path("evidence") / "blind-validation"


class BlindValidationWorkflowError(RuntimeError):
    """Raised when a tracked blind-validation workflow fails safely."""


class TrackedBlindValidationResult:
    """Combined Phase 4B execution, token, and evidence result."""

    def __init__(
        self,
        *,
        execution: ExecutionRecord,
        token: CorrelationToken,
        evidence: EvidenceRecord,
        status: BlindValidationStatus,
    ) -> None:
        self.execution = execution
        self.token = token
        self.evidence = evidence
        self.status = status


def _validate_target_scope(
    target_url: str,
    execution: ExecutionRecord,
) -> None:
    parsed = urlparse(target_url)
    hostname = parsed.hostname

    if parsed.scheme not in {"http", "https"} or not hostname:
        raise InvalidStateTransitionError(
            "A valid HTTP or HTTPS target URL is required."
        )

    if not _domain_in_execution_scope(hostname, execution):
        raise InvalidStateTransitionError(
            f"Target '{hostname}' is not associated with this execution."
        )


def _serialize_blind_validation(
    request: BlindValidationRequest,
    token: CorrelationToken,
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "phase": "4B",
        "evidence_type": EvidenceType.BLIND_VALIDATION_RESULT.value,
        "created_at": datetime.now(UTC).isoformat(),
        "request": {
            "execution_id": request.execution_id,
            "target_url": request.target_url,
            "authorized": request.authorized,
            "active_testing": request.active_testing,
            "explicitly_approved": request.explicitly_approved,
            "callback_protocol": request.callback_protocol.value,
            "requested_poll_attempts": request.requested_poll_attempts,
            "requested_poll_interval_seconds": (
                request.requested_poll_interval_seconds
            ),
        },
        "correlation": {
            "token_id": token.token_id,
            "token_hash": token.token_hash,
            "created_at": token.created_at.isoformat(),
            "expires_at": token.expires_at.isoformat(),
            "status": BlindValidationStatus.WAITING.value,
        },
    }


def _write_evidence_atomically(
    payload: dict[str, object],
    *,
    evidence_root: Path | None = None,
) -> tuple[str, str, int]:
    evidence_directory = evidence_root or DEFAULT_EVIDENCE_ROOT
    evidence_directory.mkdir(parents=True, exist_ok=True)

    evidence_id = f"blind-validation-evidence-{uuid4()}"
    evidence_path = evidence_directory / f"{evidence_id}.json"

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
            prefix=".blind-validation-",
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


def run_tracked_blind_validation(
    database: SaarthiDatabase,
    request: BlindValidationRequest,
    *,
    actor: str = "blind-validation-manager",
    evidence_root: Path | None = None,
) -> TrackedBlindValidationResult:
    """Create one bounded Phase 4B correlation record with persistence."""

    execution = database.get_execution(request.execution_id)

    if not execution.authorization_confirmed:
        raise InvalidStateTransitionError(
            "Execution does not have confirmed authorization."
        )

    if request.authorized is not True:
        raise InvalidStateTransitionError(
            "Blind-validation request does not confirm authorization."
        )

    if request.active_testing and not execution.active_testing_allowed:
        raise InvalidStateTransitionError(
            "Execution does not allow active testing."
        )

    _validate_target_scope(request.target_url, execution)

    policy = evaluate_blind_validation(request)

    if policy.decision is not BlindValidationDecision.ALLOW:
        raise BlindValidationWorkflowError(
            f"Blind validation denied by policy: {policy.reason}"
        )

    execution = advance_execution_to_running(
        database,
        execution,
        actor=actor,
    )

    database.add_audit_event(
        request.execution_id,
        event_type=AuditEventType.TOOL_STARTED,
        actor=actor,
        message="Saarthi Phase 4B blind validation started.",
        details={
            "tool": "saarthi-blind-validation",
            "target_url": request.target_url,
            "callback_protocol": request.callback_protocol.value,
            "requested_poll_attempts": request.requested_poll_attempts,
            "requested_poll_interval_seconds": (
                request.requested_poll_interval_seconds
            ),
        },
    )

    try:
        token = generate_correlation_token()

        payload = _serialize_blind_validation(
            request,
            token,
        )

        evidence_path, evidence_sha256, evidence_size = (
            _write_evidence_atomically(
                payload,
                evidence_root=evidence_root,
            )
        )

        evidence = database.add_evidence(
            request.execution_id,
            EvidenceCreate(
                evidence_type=EvidenceType.BLIND_VALIDATION_RESULT,
                source="saarthi-blind-validation",
                path=evidence_path,
                sha256=evidence_sha256,
                size_bytes=evidence_size,
                content_type="application/json",
                step_id="blind-validation-001",
                tool_name="saarthi-blind-validation",
                metadata={
                    "phase": "4B",
                    "target_url": request.target_url,
                    "callback_protocol": request.callback_protocol.value,
                    "token_id": token.token_id,
                    "token_hash": token.token_hash,
                    "status": BlindValidationStatus.WAITING.value,
                },
            ),
            actor=actor,
        )

        database.add_audit_event(
            request.execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message="Saarthi Phase 4B correlation record created.",
            details={
                "tool": "saarthi-blind-validation",
                "target_url": request.target_url,
                "token_id": token.token_id,
                "token_hash": token.token_hash,
                "evidence_id": evidence.evidence_id,
                "evidence_sha256": evidence_sha256,
                "status": BlindValidationStatus.WAITING.value,
            },
        )

        execution = database.transition_execution(
            request.execution_id,
            ExecutionState.ANALYZING,
            actor=actor,
            reason=(
                "Phase 4B blind-validation correlation evidence is ready."
            ),
        )

        execution = database.transition_execution(
            request.execution_id,
            ExecutionState.COMPLETED,
            actor=actor,
            reason=(
                "Phase 4B blind-validation correlation workflow completed."
            ),
        )

        return TrackedBlindValidationResult(
            execution=execution,
            token=token,
            evidence=evidence,
            status=BlindValidationStatus.WAITING,
        )

    except (
        BlindValidationWorkflowError,
        InvalidStateTransitionError,
        OSError,
        ValueError,
    ) as exc:
        database.add_audit_event(
            request.execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message="Saarthi Phase 4B blind validation failed.",
            details={
                "tool": "saarthi-blind-validation",
                "target_url": request.target_url,
                "error": str(exc),
            },
        )

        fail_execution_safely(
            database,
            request.execution_id,
            actor=actor,
            reason=str(exc),
        )

        raise
