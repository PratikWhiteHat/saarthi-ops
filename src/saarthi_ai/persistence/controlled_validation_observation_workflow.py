"""Tracked Phase 6F controlled-validation observation workflow."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

import httpx

from saarthi_ai.controlled_validation.executor import (
    ControlledValidationExecutionDecision,
    ControlledValidationExecutionRequest,
    evaluate_controlled_validation_execution,
)
from saarthi_ai.controlled_validation.observation import (
    ControlledValidationObservationResult,
    execute_bounded_observation,
)
from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.http_intelligence_workflow import (
    _domain_in_execution_scope,
)
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceCreate,
    EvidenceRecord,
    EvidenceType,
    ExecutionRecord,
    ExecutionState,
)

DEFAULT_EVIDENCE_ROOT = (
    Path("evidence") / "controlled-validation-observations"
)


class ControlledValidationObservationWorkflowError(RuntimeError):
    """Raised when a tracked Phase 6F observation cannot complete."""


@dataclass(frozen=True)
class TrackedControlledValidationObservation:
    """Persistent result for one bounded controlled observation."""

    execution: ExecutionRecord
    observation: ControlledValidationObservationResult
    evidence: EvidenceRecord


def _validate_target_scope(
    target_url: str,
    execution: ExecutionRecord,
) -> None:
    parsed = urlparse(target_url)
    hostname = parsed.hostname

    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise InvalidStateTransitionError(
            "A valid HTTP or HTTPS target URL without credentials is required."
        )

    if not _domain_in_execution_scope(hostname, execution):
        raise InvalidStateTransitionError(
            f"Target '{hostname}' is not associated with this execution."
        )


def _find_matching_plan(
    database: SaarthiDatabase,
    request: ControlledValidationExecutionRequest,
) -> EvidenceRecord | None:
    validation = request.validation

    plans = database.list_evidence(
        validation.execution_id,
        evidence_type=EvidenceType.CONTROLLED_VALIDATION_PLAN,
    )

    for evidence in plans:
        metadata = evidence.metadata

        if (
            metadata.get("target_url") == validation.target_url
            and metadata.get("action") == validation.action.value
            and metadata.get("requested_requests")
            == validation.requested_requests
            and metadata.get("reversible") is validation.reversible
            and metadata.get("executed") is False
            and metadata.get("network_activity") is False
        ):
            return evidence

    return None


def _serialize_observation(
    request: ControlledValidationExecutionRequest,
    observation: ControlledValidationObservationResult,
    *,
    plan_evidence: EvidenceRecord,
) -> dict[str, object]:
    validation = request.validation

    return {
        "schema_version": "1.0",
        "phase": "6F3B",
        "evidence_type": (
            EvidenceType.CONTROLLED_VALIDATION_OBSERVATION.value
        ),
        "collected_at": datetime.now(UTC).isoformat(),
        "plan": {
            "evidence_id": plan_evidence.evidence_id,
            "sha256": plan_evidence.sha256,
        },
        "request": {
            "execution_id": validation.execution_id,
            "target_url": validation.target_url,
            "action": validation.action.value,
            "method": observation.method,
            "requested_requests": validation.requested_requests,
            "explicitly_approved": validation.explicitly_approved,
            "reversible": validation.reversible,
            "timeout_seconds": observation.policy.timeout_seconds,
            "max_response_bytes": (
                observation.policy.max_response_bytes
            ),
            "follow_redirects": observation.policy.follow_redirects,
        },
        "policy": {
            "decision": observation.policy.decision.value,
            "reason": observation.policy.reason,
        },
        "execution": {
            "request_attempted": observation.request_attempted,
            "response_received": observation.response_received,
            "network_activity": observation.request_attempted,
            "subprocess_started": False,
            "payload_sent": False,
        },
        "response": {
            "final_url": observation.final_url,
            "status_code": observation.status_code,
            "http_version": observation.http_version,
            "content_type": observation.content_type,
            "headers": observation.response_headers,
            "body_bytes_captured": observation.body_bytes_captured,
            "body_truncated": observation.body_truncated,
            "body_sha256": observation.body_sha256,
        },
    }


def _write_evidence_atomically(
    payload: dict[str, object],
    *,
    evidence_root: Path | None = None,
) -> tuple[str, str, int]:
    evidence_directory = evidence_root or DEFAULT_EVIDENCE_ROOT
    evidence_directory.mkdir(parents=True, exist_ok=True)

    evidence_id = f"controlled-validation-observation-{uuid4()}"
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
            prefix=".controlled-validation-observation-",
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


async def run_tracked_controlled_validation_observation(
    database: SaarthiDatabase,
    request: ControlledValidationExecutionRequest,
    *,
    transport: httpx.AsyncBaseTransport,
    actor: str = "controlled-validation-observer",
    evidence_root: Path | None = None,
) -> TrackedControlledValidationObservation:
    """Run and persist exactly one preplanned bounded observation."""

    validation = request.validation
    execution = database.get_execution(validation.execution_id)

    if not execution.authorization_confirmed:
        raise InvalidStateTransitionError(
            "Execution does not have confirmed authorization."
        )

    if validation.authorized is not True:
        raise InvalidStateTransitionError(
            "Controlled-validation request does not confirm authorization."
        )

    if (
        validation.active_testing
        and not execution.active_testing_allowed
    ):
        raise InvalidStateTransitionError(
            "Execution does not allow active testing."
        )

    if (
        validation.intrusive_testing
        and not execution.intrusive_testing_allowed
    ):
        raise InvalidStateTransitionError(
            "Execution does not allow intrusive testing."
        )

    if execution.state is not ExecutionState.PLANNED:
        raise InvalidStateTransitionError(
            "Controlled-validation observation requires an execution in "
            f"'planned' state; current state is '{execution.state.value}'."
        )

    _validate_target_scope(validation.target_url, execution)

    policy = evaluate_controlled_validation_execution(request)

    if (
        policy.decision
        is not ControlledValidationExecutionDecision.ALLOW
    ):
        raise ControlledValidationObservationWorkflowError(
            "Controlled-validation observation denied by policy: "
            f"{policy.reason}"
        )

    plan_evidence = _find_matching_plan(database, request)

    if plan_evidence is None:
        raise ControlledValidationObservationWorkflowError(
            "A matching approved Phase 6B controlled-validation plan "
            "is required before observation."
        )

    execution = database.transition_execution(
        validation.execution_id,
        ExecutionState.RUNNING,
        actor=actor,
        reason="Approved bounded controlled-validation observation started.",
    )

    database.add_audit_event(
        validation.execution_id,
        event_type=AuditEventType.TOOL_STARTED,
        actor=actor,
        message=(
            "[6F3B][controlled-validation] "
            "Bounded HTTP observation started."
        ),
        details={
            "phase_code": "6F3B",
            "tool": "saarthi-controlled-validation-observer",
            "target_url": validation.target_url,
            "action": validation.action.value,
            "method": policy.method,
            "plan_evidence_id": plan_evidence.evidence_id,
            "requested_requests": validation.requested_requests,
        },
    )

    observation = await execute_bounded_observation(
        request,
        transport=transport,
    )

    if not observation.succeeded:
        raise ControlledValidationObservationWorkflowError(
            observation.error
            or "Controlled-validation observation did not succeed."
        )

    database.add_audit_event(
        validation.execution_id,
        event_type=AuditEventType.TOOL_OUTPUT,
        actor=actor,
        message=(
            "[6F3B][controlled-validation] "
            f"HTTP {observation.status_code}; "
            f"captured={observation.body_bytes_captured}; "
            f"truncated={str(observation.body_truncated).lower()}."
        ),
        details={
            "phase_code": "6F3B",
            "status_code": observation.status_code,
            "final_url": observation.final_url,
            "http_version": observation.http_version,
            "content_type": observation.content_type,
            "body_bytes_captured": observation.body_bytes_captured,
            "body_truncated": observation.body_truncated,
            "body_sha256": observation.body_sha256,
        },
    )

    payload = _serialize_observation(
        request,
        observation,
        plan_evidence=plan_evidence,
    )

    evidence_path, evidence_sha256, evidence_size = (
        _write_evidence_atomically(
            payload,
            evidence_root=evidence_root,
        )
    )

    evidence = database.add_evidence(
        validation.execution_id,
        EvidenceCreate(
            evidence_type=(
                EvidenceType.CONTROLLED_VALIDATION_OBSERVATION
            ),
            source="saarthi-controlled-validation-observer",
            path=evidence_path,
            sha256=evidence_sha256,
            size_bytes=evidence_size,
            content_type="application/json",
            step_id="controlled-validation-observation-001",
            tool_name="saarthi-controlled-validation-observer",
            metadata={
                "phase": "6F3B",
                "target_url": validation.target_url,
                "action": validation.action.value,
                "method": observation.method,
                "status_code": observation.status_code,
                "body_bytes_captured": (
                    observation.body_bytes_captured
                ),
                "body_truncated": observation.body_truncated,
                "body_sha256": observation.body_sha256,
                "plan_evidence_id": plan_evidence.evidence_id,
                "request_attempted": True,
                "network_activity": True,
            },
        ),
        actor=actor,
    )

    database.add_audit_event(
        validation.execution_id,
        event_type=AuditEventType.TOOL_COMPLETED,
        actor=actor,
        message=(
            "[6F3B][controlled-validation] "
            "Bounded HTTP observation persisted."
        ),
        details={
            "phase_code": "6F3B",
            "evidence_id": evidence.evidence_id,
            "evidence_sha256": evidence.sha256,
            "plan_evidence_id": plan_evidence.evidence_id,
            "status_code": observation.status_code,
        },
    )

    execution = database.transition_execution(
        validation.execution_id,
        ExecutionState.ANALYZING,
        actor=actor,
        reason=(
            "Controlled-validation observation evidence is ready "
            "for analysis."
        ),
    )

    execution = database.transition_execution(
        validation.execution_id,
        ExecutionState.COMPLETED,
        actor=actor,
        reason=(
            "Phase 6F tracked controlled-validation observation completed."
        ),
    )

    return TrackedControlledValidationObservation(
        execution=execution,
        observation=observation,
        evidence=evidence,
    )
