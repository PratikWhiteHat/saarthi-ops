"""Persistent Phase 6B controlled-validation planning workflow."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

from saarthi_ai.controlled_validation.models import (
    ControlledValidationDecision,
    ControlledValidationPolicyResult,
    ControlledValidationRequest,
)
from saarthi_ai.controlled_validation.policy import (
    evaluate_controlled_validation,
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
    Path("evidence") / "controlled-validation-plans"
)


class ControlledValidationWorkflowError(RuntimeError):
    """Raised when a Phase 6 validation plan cannot be persisted safely."""


class TrackedControlledValidationPlan:
    """Persistent result for one non-executed validation plan."""

    def __init__(
        self,
        *,
        execution: ExecutionRecord,
        policy: ControlledValidationPolicyResult,
        evidence: EvidenceRecord,
    ) -> None:
        self.execution = execution
        self.policy = policy
        self.evidence = evidence


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


def _advance_execution_to_planned(
    database: SaarthiDatabase,
    execution: ExecutionRecord,
    *,
    actor: str,
) -> ExecutionRecord:
    current = execution

    if current.state is ExecutionState.CREATED:
        current = database.transition_execution(
            current.execution_id,
            ExecutionState.VALIDATED,
            actor=actor,
            reason=(
                "Authorized Phase 6 controlled-validation request accepted."
            ),
        )

    if current.state is ExecutionState.VALIDATED:
        current = database.transition_execution(
            current.execution_id,
            ExecutionState.PLANNED,
            actor=actor,
            reason=(
                "Bounded Phase 6 controlled-validation plan prepared."
            ),
        )

    if current.state is not ExecutionState.PLANNED:
        raise InvalidStateTransitionError(
            "Controlled-validation planning requires an execution in "
            f"'planned' state; current state is '{current.state.value}'."
        )

    return current


def _serialize_plan(
    request: ControlledValidationRequest,
    policy: ControlledValidationPolicyResult,
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "phase": "6B",
        "evidence_type": (
            EvidenceType.CONTROLLED_VALIDATION_PLAN.value
        ),
        "created_at": datetime.now(UTC).isoformat(),
        "request": {
            "execution_id": request.execution_id,
            "target_url": request.target_url,
            "action": request.action.value,
            "authorized": request.authorized,
            "active_testing": request.active_testing,
            "intrusive_testing": request.intrusive_testing,
            "explicitly_approved": request.explicitly_approved,
            "reversible": request.reversible,
            "requested_requests": request.requested_requests,
        },
        "policy": {
            "decision": policy.decision.value,
            "risk": policy.risk.value,
            "reason": policy.reason,
        },
        "execution": {
            "executed": False,
            "network_activity": False,
            "payload_sent": False,
            "subprocess_started": False,
        },
    }


def _find_matching_plan_evidence(
    database: SaarthiDatabase,
    request: ControlledValidationRequest,
) -> EvidenceRecord | None:
    """Return an existing equivalent Phase 6B plan, if one exists."""

    evidence_items = database.list_evidence(
        request.execution_id,
        evidence_type=EvidenceType.CONTROLLED_VALIDATION_PLAN,
    )

    for evidence in evidence_items:
        metadata = evidence.metadata

        if (
            metadata.get("target_url") == request.target_url
            and metadata.get("action") == request.action.value
            and metadata.get("requested_requests")
            == request.requested_requests
            and metadata.get("reversible") is request.reversible
            and metadata.get("executed") is False
            and metadata.get("network_activity") is False
        ):
            return evidence

    return None


def _write_evidence_atomically(
    payload: dict[str, object],
    *,
    evidence_root: Path | None = None,
) -> tuple[str, str, int]:
    evidence_directory = evidence_root or DEFAULT_EVIDENCE_ROOT
    evidence_directory.mkdir(parents=True, exist_ok=True)

    evidence_id = f"controlled-validation-plan-{uuid4()}"
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
            prefix=".controlled-validation-",
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


def create_tracked_controlled_validation_plan(
    database: SaarthiDatabase,
    request: ControlledValidationRequest,
    *,
    actor: str = "controlled-validation-planner",
    evidence_root: Path | None = None,
) -> TrackedControlledValidationPlan:
    """Persist one approved Phase 6 plan without executing an action."""

    execution = database.get_execution(request.execution_id)

    if not execution.authorization_confirmed:
        raise InvalidStateTransitionError(
            "Execution does not have confirmed authorization."
        )

    if request.authorized is not True:
        raise InvalidStateTransitionError(
            "Controlled-validation request does not confirm authorization."
        )

    if request.active_testing and not execution.active_testing_allowed:
        raise InvalidStateTransitionError(
            "Execution does not allow active testing."
        )

    if (
        request.intrusive_testing
        and not execution.intrusive_testing_allowed
    ):
        raise InvalidStateTransitionError(
            "Execution does not allow intrusive testing."
        )

    _validate_target_scope(request.target_url, execution)

    policy = evaluate_controlled_validation(request)

    if policy.decision is not ControlledValidationDecision.ALLOW:
        raise ControlledValidationWorkflowError(
            "Controlled validation denied by policy: "
            f"{policy.reason}"
        )

    execution = _advance_execution_to_planned(
        database,
        execution,
        actor=actor,
    )

    existing_evidence = _find_matching_plan_evidence(
        database,
        request,
    )

    if existing_evidence is not None:
        database.add_audit_event(
            request.execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message=(
                "[6B][controlled-validation] "
                "Existing non-executed validation plan reused."
            ),
            details={
                "phase_code": "6B",
                "action": request.action.value,
                "risk": policy.risk.value,
                "evidence_id": existing_evidence.evidence_id,
                "evidence_sha256": existing_evidence.sha256,
                "executed": False,
                "network_activity": False,
                "idempotent_reuse": True,
            },
        )

        return TrackedControlledValidationPlan(
            execution=execution,
            policy=policy,
            evidence=existing_evidence,
        )

    database.add_audit_event(
        request.execution_id,
        event_type=AuditEventType.APPROVAL_RECORDED,
        actor=actor,
        message=(
            "[6B][controlled-validation] Explicit operator approval recorded."
        ),
        details={
            "phase_code": "6B",
            "action": request.action.value,
            "risk": policy.risk.value,
            "target_url": request.target_url,
            "requested_requests": request.requested_requests,
            "reversible": request.reversible,
        },
    )

    database.add_audit_event(
        request.execution_id,
        event_type=AuditEventType.TOOL_PREPARED,
        actor=actor,
        message=(
            "[6B][controlled-validation] "
            "Non-executed validation plan prepared."
        ),
        details={
            "phase_code": "6B",
            "tool": "saarthi-controlled-validation-planner",
            "action": request.action.value,
            "policy_decision": policy.decision.value,
            "risk": policy.risk.value,
            "executed": False,
            "network_activity": False,
        },
    )

    payload = _serialize_plan(request, policy)

    evidence_path: str | None = None
    evidence_registered = False

    try:
        evidence_path, evidence_sha256, evidence_size = (
            _write_evidence_atomically(
                payload,
                evidence_root=evidence_root,
            )
        )

        evidence = database.add_evidence(
            request.execution_id,
            EvidenceCreate(
                evidence_type=(
                    EvidenceType.CONTROLLED_VALIDATION_PLAN
                ),
                source="saarthi-controlled-validation-planner",
                path=evidence_path,
                sha256=evidence_sha256,
                size_bytes=evidence_size,
                content_type="application/json",
                step_id="controlled-validation-plan-001",
                tool_name=(
                    "saarthi-controlled-validation-planner"
                ),
                metadata={
                    "phase": "6B",
                    "target_url": request.target_url,
                    "action": request.action.value,
                    "risk": policy.risk.value,
                    "policy_decision": policy.decision.value,
                    "requested_requests": (
                        request.requested_requests
                    ),
                    "reversible": request.reversible,
                    "executed": False,
                    "network_activity": False,
                },
            ),
            actor=actor,
        )
        evidence_registered = True
    except (OSError, RuntimeError, ValueError) as exc:
        if (
            evidence_path is not None
            and not evidence_registered
        ):
            try:
                Path(evidence_path).unlink(missing_ok=True)
            except OSError:
                pass

        database.add_audit_event(
            request.execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message=(
                "[6B][controlled-validation] "
                "Validation-plan persistence failed."
            ),
            details={
                "phase_code": "6B",
                "action": request.action.value,
                "error_type": type(exc).__name__,
                "execution_state": ExecutionState.PLANNED.value,
                "retry_allowed": True,
                "evidence_registered": False,
                "orphan_file_removed": (
                    evidence_path is not None
                    and not Path(evidence_path).exists()
                ),
            },
        )
        raise ControlledValidationWorkflowError(
            "Controlled-validation plan could not be persisted safely."
        ) from exc

    database.add_audit_event(
        request.execution_id,
        event_type=AuditEventType.TOOL_COMPLETED,
        actor=actor,
        message=(
            "[6B][controlled-validation] "
            "Non-executed validation plan persisted."
        ),
        details={
            "phase_code": "6B",
            "action": request.action.value,
            "risk": policy.risk.value,
            "evidence_id": evidence.evidence_id,
            "evidence_sha256": evidence.sha256,
            "executed": False,
            "network_activity": False,
        },
    )

    return TrackedControlledValidationPlan(
        execution=execution,
        policy=policy,
        evidence=evidence,
    )
