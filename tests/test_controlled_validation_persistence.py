"""Persistence tests for Phase 6B validation planning."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from saarthi_ai.controlled_validation.models import (
    ControlledValidationAction,
    ControlledValidationDecision,
    ControlledValidationRequest,
)
from saarthi_ai.persistence.controlled_validation_workflow import (
    ControlledValidationWorkflowError,
    create_tracked_controlled_validation_plan,
)
from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceType,
    ExecutionCreate,
    ExecutionState,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(
        tmp_path / "controlled-validation.db"
    )
    repository.initialize()
    return repository


def create_execution(
    database: SaarthiDatabase,
    *,
    target: str = "example.com",
    authorized: bool = True,
    active_testing_allowed: bool = True,
    intrusive_testing_allowed: bool = False,
) -> str:
    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Phase 6 Controlled Validation",
            asset_types=["web"],
            targets=[target],
            authorization_confirmed=authorized,
            active_testing_allowed=active_testing_allowed,
            intrusive_testing_allowed=intrusive_testing_allowed,
        )
    )
    return execution.execution_id


def make_request(
    execution_id: str,
    **overrides: object,
) -> ControlledValidationRequest:
    values: dict[str, object] = {
        "execution_id": execution_id,
        "target_url": "https://example.com/account",
        "action": ControlledValidationAction.RESPONSE_DIFFERENTIAL,
        "authorized": True,
        "active_testing": True,
        "intrusive_testing": False,
        "explicitly_approved": True,
        "reversible": True,
        "requested_requests": 2,
    }
    values.update(overrides)
    return ControlledValidationRequest(**values)  # type: ignore[arg-type]


def test_approved_plan_is_persisted_without_execution(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    request = make_request(execution_id)

    result = create_tracked_controlled_validation_plan(
        database,
        request,
        evidence_root=tmp_path / "evidence",
    )

    assert result.execution.state is ExecutionState.PLANNED
    assert (
        result.policy.decision
        is ControlledValidationDecision.ALLOW
    )
    assert (
        result.evidence.evidence_type
        is EvidenceType.CONTROLLED_VALIDATION_PLAN
    )

    evidence_path = Path(result.evidence.path)
    evidence_bytes = evidence_path.read_bytes()
    payload = json.loads(evidence_bytes)

    assert (
        hashlib.sha256(evidence_bytes).hexdigest()
        == result.evidence.sha256
    )
    assert payload["phase"] == "6B"
    assert payload["execution"]["executed"] is False
    assert payload["execution"]["network_activity"] is False
    assert payload["execution"]["payload_sent"] is False
    assert payload["execution"]["subprocess_started"] is False

    events = database.list_audit_events(execution_id)

    assert any(
        event.event_type is AuditEventType.APPROVAL_RECORDED
        for event in events
    )
    assert any(
        event.event_type is AuditEventType.TOOL_PREPARED
        for event in events
    )
    assert any(
        event.event_type is AuditEventType.TOOL_COMPLETED
        for event in events
    )


def test_out_of_scope_target_creates_no_evidence(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    request = make_request(
        execution_id,
        target_url="https://outside.test/",
    )

    with pytest.raises(
        InvalidStateTransitionError,
        match="not associated with this execution",
    ):
        create_tracked_controlled_validation_plan(
            database,
            request,
            evidence_root=tmp_path,
        )

    assert database.list_evidence(execution_id) == []
    assert (
        database.get_execution(execution_id).state
        is ExecutionState.CREATED
    )


def test_active_permission_is_enforced_before_persistence(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(
        database,
        active_testing_allowed=False,
    )

    with pytest.raises(
        InvalidStateTransitionError,
        match="does not allow active testing",
    ):
        create_tracked_controlled_validation_plan(
            database,
            make_request(execution_id),
            evidence_root=tmp_path,
        )

    assert database.list_evidence(execution_id) == []


def test_intrusive_permission_is_enforced(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(
        database,
        intrusive_testing_allowed=False,
    )

    request = make_request(
        execution_id,
        action=ControlledValidationAction.AUTHORIZATION_BOUNDARY,
        intrusive_testing=True,
    )

    with pytest.raises(
        InvalidStateTransitionError,
        match="does not allow intrusive testing",
    ):
        create_tracked_controlled_validation_plan(
            database,
            request,
            evidence_root=tmp_path,
        )

    assert database.list_evidence(execution_id) == []


def test_policy_rejection_creates_no_evidence_or_state_change(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    request = make_request(
        execution_id,
        explicitly_approved=False,
    )

    with pytest.raises(
        ControlledValidationWorkflowError,
        match="requires explicit operator approval",
    ):
        create_tracked_controlled_validation_plan(
            database,
            request,
            evidence_root=tmp_path,
        )

    assert database.list_evidence(execution_id) == []
    assert (
        database.get_execution(execution_id).state
        is ExecutionState.CREATED
    )


def test_high_impact_action_is_not_persisted_as_automated_plan(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(
        database,
        intrusive_testing_allowed=True,
    )
    request = make_request(
        execution_id,
        action=ControlledValidationAction.STATE_CHANGE_VALIDATION,
        intrusive_testing=True,
    )

    with pytest.raises(
        ControlledValidationWorkflowError,
        match="manual procedure",
    ):
        create_tracked_controlled_validation_plan(
            database,
            request,
            evidence_root=tmp_path,
        )

    assert database.list_evidence(execution_id) == []
    assert (
        database.get_execution(execution_id).state
        is ExecutionState.CREATED
    )


def test_unauthorized_execution_is_rejected(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)

    with database.connect() as connection:
        connection.execute(
            """
            UPDATE executions
            SET authorization_confirmed = 0
            WHERE execution_id = ?
            """,
            (execution_id,),
        )

    with pytest.raises(
        InvalidStateTransitionError,
        match="confirmed authorization",
    ):
        create_tracked_controlled_validation_plan(
            database,
            make_request(execution_id),
            evidence_root=tmp_path,
        )

    assert database.list_evidence(execution_id) == []
    assert (
        database.get_execution(execution_id).state
        is ExecutionState.CREATED
    )
