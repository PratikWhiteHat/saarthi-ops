"""Integrity-checked Phase 6A to Phase 6B hypothesis routing."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from saarthi_ai.attack_hypothesis import (
    AttackHypothesisRisk,
    AttackHypothesisValidationMethod,
)
from saarthi_ai.controlled_validation.models import (
    ControlledValidationAction,
    ControlledValidationRequest,
)
from saarthi_ai.persistence.controlled_validation_workflow import (
    TrackedControlledValidationPlan,
    create_tracked_controlled_validation_plan,
)
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceRecord,
    EvidenceType,
    ExecutionCreate,
    ExecutionRecord,
    ExecutionState,
)


class HypothesisRoutingWorkflowError(RuntimeError):
    """Raised when a Phase 6A hypothesis cannot be routed safely."""


@dataclass(frozen=True)
class HypothesisRoutingRequest:
    """Freshly approved request to route one persisted hypothesis."""

    source_execution_id: str
    hypothesis_evidence_id: str
    hypothesis_id: str
    explicitly_approved: bool
    requested_requests: int = 1


@dataclass(frozen=True)
class RoutedHypothesisPlan:
    """Linked Phase 6B execution and its non-executed plan."""

    source_execution: ExecutionRecord
    validation_execution: ExecutionRecord
    source_evidence: EvidenceRecord
    hypothesis_id: str
    plan: TrackedControlledValidationPlan
    reused_validation_execution: bool


_METHOD_ACTIONS = {
    AttackHypothesisValidationMethod.RESPONSE_DIFFERENTIAL.value: (
        ControlledValidationAction.RESPONSE_DIFFERENTIAL
    ),
    AttackHypothesisValidationMethod.INPUT_HANDLING_OBSERVATION.value: (
        ControlledValidationAction.INPUT_HANDLING_OBSERVATION
    ),
}


def _load_source_evidence(
    database: SaarthiDatabase,
    request: HypothesisRoutingRequest,
) -> EvidenceRecord:
    matches = [
        evidence
        for evidence in database.list_evidence(
            request.source_execution_id,
            evidence_type=EvidenceType.ATTACK_HYPOTHESIS_SET,
        )
        if evidence.evidence_id == request.hypothesis_evidence_id
    ]

    if len(matches) != 1:
        raise HypothesisRoutingWorkflowError(
            "The selected Phase 6A hypothesis evidence was not found "
            "on the source execution."
        )

    return matches[0]


def _read_verified_payload(evidence: EvidenceRecord) -> dict[str, Any]:
    path = Path(evidence.path)

    try:
        serialized = path.read_bytes()
    except OSError as exc:
        raise HypothesisRoutingWorkflowError(
            "The selected hypothesis evidence file is unavailable."
        ) from exc

    if evidence.size_bytes is None or len(serialized) != evidence.size_bytes:
        raise HypothesisRoutingWorkflowError(
            "Hypothesis evidence size verification failed."
        )

    digest = hashlib.sha256(serialized).hexdigest()
    if evidence.sha256 is None or digest != evidence.sha256:
        raise HypothesisRoutingWorkflowError(
            "Hypothesis evidence SHA-256 verification failed."
        )

    try:
        payload = json.loads(serialized)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HypothesisRoutingWorkflowError(
            "Hypothesis evidence is not valid JSON."
        ) from exc

    if not isinstance(payload, dict):
        raise HypothesisRoutingWorkflowError(
            "Hypothesis evidence must contain a JSON object."
        )

    return payload


def _selected_hypothesis(
    payload: dict[str, Any],
    request: HypothesisRoutingRequest,
) -> dict[str, Any]:
    payload_request = payload.get("request")
    summary = payload.get("summary")
    hypotheses = payload.get("hypotheses")
    execution = payload.get("execution")

    if (
        payload.get("schema_version") != "1.0"
        or payload.get("phase") != "6A"
        or payload.get("evidence_type")
        != EvidenceType.ATTACK_HYPOTHESIS_SET.value
        or not isinstance(payload_request, dict)
        or payload_request.get("execution_id")
        != request.source_execution_id
        or not isinstance(summary, dict)
        or not isinstance(hypotheses, list)
        or not isinstance(execution, dict)
        or any(
            execution.get(flag) is not False
            for flag in (
                "executed",
                "network_activity",
                "payload_generated",
                "subprocess_started",
            )
        )
    ):
        raise HypothesisRoutingWorkflowError(
            "Hypothesis evidence does not satisfy the Phase 6A "
            "non-execution contract."
        )

    matches = [
        item
        for item in hypotheses
        if isinstance(item, dict)
        and item.get("hypothesis_id") == request.hypothesis_id
    ]
    if len(matches) != 1:
        raise HypothesisRoutingWorkflowError(
            "The selected hypothesis ID is missing or ambiguous."
        )

    hypothesis = matches[0]
    supporting_ids = hypothesis.get("supporting_evidence_ids")
    considered_ids = summary.get("considered_evidence_ids")
    if any(
        hypothesis.get(flag) is not False
        for flag in (
            "executed",
            "network_activity",
            "payload_generated",
            "subprocess_started",
        )
    ):
        raise HypothesisRoutingWorkflowError(
            "The selected hypothesis violates the non-execution contract."
        )
    if (
        not isinstance(supporting_ids, list)
        or not isinstance(considered_ids, list)
        or not set(supporting_ids).issubset(considered_ids)
    ):
        raise HypothesisRoutingWorkflowError(
            "The selected hypothesis is not linked to the evidence "
            "considered by its Phase 6A set."
        )

    return hypothesis


def _validate_routable_hypothesis(
    database: SaarthiDatabase,
    source: ExecutionRecord,
    evidence: EvidenceRecord,
    hypothesis: dict[str, Any],
) -> tuple[str, ControlledValidationAction]:
    target_url = hypothesis.get("target_url")
    method = hypothesis.get("validation_method")
    supporting_ids = hypothesis.get("supporting_evidence_ids")
    required_permissions = hypothesis.get("required_permissions")

    if (
        not isinstance(target_url, str)
        or target_url != evidence.metadata.get("target_url")
    ):
        raise HypothesisRoutingWorkflowError(
            "Hypothesis target does not match its evidence catalog entry."
        )

    if hypothesis.get("validation_risk") != AttackHypothesisRisk.LOW.value:
        raise HypothesisRoutingWorkflowError(
            "Only low-risk Phase 6A hypotheses can be routed "
            "automatically; this hypothesis requires manual review."
        )

    action = _METHOD_ACTIONS.get(method)
    if action is None:
        raise HypothesisRoutingWorkflowError(
            "The proposed validation method is manual-only or unsupported "
            "by the automated Phase 6B gate."
        )

    required = {
        "authorization_confirmed",
        "active_testing_allowed",
        "explicit_approval",
    }
    if (
        not isinstance(required_permissions, list)
        or not required.issubset(required_permissions)
    ):
        raise HypothesisRoutingWorkflowError(
            "The selected hypothesis does not declare all required "
            "Phase 6B permissions."
        )

    known_evidence_ids = {
        item.evidence_id
        for item in database.list_evidence(source.execution_id)
    }
    if (
        not isinstance(supporting_ids, list)
        or not supporting_ids
        or any(
            not isinstance(item, str)
            or item not in known_evidence_ids
            for item in supporting_ids
        )
    ):
        raise HypothesisRoutingWorkflowError(
            "Hypothesis supporting-evidence linkage is incomplete."
        )

    return target_url, action


def _matching_validation_execution(
    database: SaarthiDatabase,
    request: HypothesisRoutingRequest,
) -> ExecutionRecord | None:
    for execution in database.list_executions(limit=1_000):
        metadata = execution.metadata
        if (
            execution.state is ExecutionState.PLANNED
            and metadata.get("execution_role")
            == "orchestration_child"
            and metadata.get("workflow_role")
            == "phase_6b_hypothesis_validation"
            and metadata.get("source_execution_id")
            == request.source_execution_id
            and metadata.get("source_hypothesis_evidence_id")
            == request.hypothesis_evidence_id
            and metadata.get("source_hypothesis_id")
            == request.hypothesis_id
            and metadata.get("requested_requests")
            == request.requested_requests
        ):
            return execution

    return None


def _create_validation_execution(
    database: SaarthiDatabase,
    source: ExecutionRecord,
    evidence: EvidenceRecord,
    request: HypothesisRoutingRequest,
    target_url: str,
    action: ControlledValidationAction,
) -> ExecutionRecord:
    source_metadata = source.metadata
    metadata: dict[str, object] = {
        "execution_role": "orchestration_child",
        "workflow_role": "phase_6b_hypothesis_validation",
        "phase_code": "6B",
        "phase_name": "Policy & Approval Gate",
        "source_execution_id": source.execution_id,
        "source_hypothesis_evidence_id": evidence.evidence_id,
        "source_hypothesis_evidence_sha256": evidence.sha256,
        "source_hypothesis_id": request.hypothesis_id,
        "validation_action": action.value,
        "requested_requests": request.requested_requests,
        "target_url": target_url,
        "project_id": source_metadata.get("project_id"),
        "project_slug": source_metadata.get("project_slug"),
        "orchestration_id": source_metadata.get("orchestration_id"),
        "parent_execution_id": (
            source_metadata.get("parent_execution_id")
            or (
                source.execution_id
                if source_metadata.get("execution_role")
                == "orchestration_parent"
                else None
            )
        ),
        "previous_execution_id": source.execution_id,
        "executed": False,
        "network_activity": False,
    }

    return database.create_execution(
        ExecutionCreate(
            assessment_name=(
                f"{source.assessment_name} — 6B hypothesis approval"
            ),
            plan_version=source.plan_version,
            asset_types=source.asset_types,
            targets=source.targets,
            authorization_confirmed=source.authorization_confirmed,
            active_testing_allowed=source.active_testing_allowed,
            intrusive_testing_allowed=False,
            metadata=metadata,
        )
    )


def route_hypothesis_to_controlled_validation(
    database: SaarthiDatabase,
    request: HypothesisRoutingRequest,
    *,
    actor: str = "hypothesis-routing-workflow",
    evidence_root: Path | None = None,
) -> RoutedHypothesisPlan:
    """Route one intact low-risk 6A hypothesis into a linked 6B plan."""

    if request.explicitly_approved is not True:
        raise HypothesisRoutingWorkflowError(
            "Fresh explicit approval is required for the 6A to 6B handoff."
        )
    if not 1 <= request.requested_requests <= 5:
        raise HypothesisRoutingWorkflowError(
            "The routed validation must be bounded to 1–5 requests."
        )

    source = database.get_execution(request.source_execution_id)
    if not source.authorization_confirmed:
        raise HypothesisRoutingWorkflowError(
            "The source execution does not have confirmed authorization."
        )
    if not source.active_testing_allowed:
        raise HypothesisRoutingWorkflowError(
            "The source execution does not permit active testing."
        )

    evidence = _load_source_evidence(database, request)
    catalog_hypothesis_ids = evidence.metadata.get("hypothesis_ids")
    if (
        evidence.metadata.get("phase") != "6A"
        or not isinstance(catalog_hypothesis_ids, list)
        or request.hypothesis_id not in catalog_hypothesis_ids
        or any(
            evidence.metadata.get(flag) is not False
            for flag in (
                "executed",
                "network_activity",
                "payload_generated",
                "subprocess_started",
            )
        )
    ):
        raise HypothesisRoutingWorkflowError(
            "The evidence catalog entry does not satisfy the Phase 6A "
            "traceability contract."
        )
    payload = _read_verified_payload(evidence)
    hypothesis = _selected_hypothesis(payload, request)
    target_url, action = _validate_routable_hypothesis(
        database,
        source,
        evidence,
        hypothesis,
    )

    validation_execution = _matching_validation_execution(
        database,
        request,
    )
    reused = validation_execution is not None
    if validation_execution is None:
        validation_execution = _create_validation_execution(
            database,
            source,
            evidence,
            request,
            target_url,
            action,
        )

    plan_request = ControlledValidationRequest(
        execution_id=validation_execution.execution_id,
        target_url=target_url,
        action=action,
        authorized=True,
        active_testing=True,
        explicitly_approved=True,
        reversible=True,
        requested_requests=request.requested_requests,
        source_execution_id=source.execution_id,
        source_hypothesis_evidence_id=evidence.evidence_id,
        source_hypothesis_id=request.hypothesis_id,
    )

    try:
        plan = create_tracked_controlled_validation_plan(
            database,
            plan_request,
            actor=actor,
            evidence_root=evidence_root,
        )
    except Exception:
        current = database.get_execution(
            validation_execution.execution_id
        )
        if current.state not in {
            ExecutionState.FAILED,
            ExecutionState.CANCELLED,
            ExecutionState.COMPLETED,
        }:
            database.transition_execution(
                current.execution_id,
                ExecutionState.FAILED,
                actor=actor,
                reason="Phase 6B hypothesis routing failed safely.",
            )
        raise

    database.add_audit_event(
        source.execution_id,
        event_type=AuditEventType.APPROVAL_RECORDED,
        actor=actor,
        message=(
            "[6A→6B][hypothesis-routing] Low-risk hypothesis routed "
            "to a separate non-executing validation plan."
        ),
        details={
            "phase_code": "6B",
            "source_hypothesis_id": request.hypothesis_id,
            "source_hypothesis_evidence_id": evidence.evidence_id,
            "validation_execution_id": plan.execution.execution_id,
            "validation_plan_evidence_id": plan.evidence.evidence_id,
            "reused_validation_execution": reused,
            "executed": False,
            "network_activity": False,
        },
    )

    return RoutedHypothesisPlan(
        source_execution=source,
        validation_execution=plan.execution,
        source_evidence=evidence,
        hypothesis_id=request.hypothesis_id,
        plan=plan,
        reused_validation_execution=reused,
    )
