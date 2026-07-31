from __future__ import annotations

from pathlib import Path

import pytest

from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.models import (
    EvidenceCreate,
    EvidenceType,
    ExecutionCreate,
    ExecutionState,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    """Create an isolated initialized database."""

    repository = SaarthiDatabase(tmp_path / "saarthi-test.db")
    repository.initialize()
    return repository


def build_execution() -> ExecutionCreate:
    """Create a reusable authorized execution request."""

    return ExecutionCreate(
        assessment_name="Authorized Web VAPT",
        plan_version="0.1.0",
        asset_types=["web"],
        targets=["https://example.com/"],
        authorization_confirmed=True,
        active_testing_allowed=True,
        intrusive_testing_allowed=False,
    )


def test_create_and_retrieve_execution(
    database: SaarthiDatabase,
) -> None:
    """An execution should be persisted and retrievable."""

    created = database.create_execution(build_execution())
    retrieved = database.get_execution(created.execution_id)

    assert retrieved.execution_id == created.execution_id
    assert retrieved.state is ExecutionState.CREATED
    assert retrieved.targets == ["https://example.com/"]


def test_execution_state_lifecycle(
    database: SaarthiDatabase,
) -> None:
    """Valid execution transitions should be persisted."""

    execution = database.create_execution(build_execution())

    for state in [
        ExecutionState.VALIDATED,
        ExecutionState.PLANNED,
        ExecutionState.AWAITING_APPROVAL,
        ExecutionState.RUNNING,
        ExecutionState.ANALYZING,
        ExecutionState.COMPLETED,
    ]:
        execution = database.transition_execution(
            execution.execution_id,
            state,
            actor="tester",
        )

    assert execution.state is ExecutionState.COMPLETED
    assert execution.completed_at is not None


def test_invalid_state_transition_is_rejected(
    database: SaarthiDatabase,
) -> None:
    """The state machine must reject skipped lifecycle states."""

    execution = database.create_execution(build_execution())

    with pytest.raises(
        InvalidStateTransitionError,
        match="created -> completed",
    ):
        database.transition_execution(
            execution.execution_id,
            ExecutionState.COMPLETED,
            actor="tester",
        )


def test_audit_events_are_created(
    database: SaarthiDatabase,
) -> None:
    """Execution creation and transitions should create audit events."""

    execution = database.create_execution(build_execution())

    database.transition_execution(
        execution.execution_id,
        ExecutionState.VALIDATED,
        actor="tester",
        reason="Scope validation passed.",
    )

    events = database.list_audit_events(execution.execution_id)

    assert len(events) == 2
    assert events[0].event_type.value == "execution_created"
    assert events[1].event_type.value == "state_changed"


def test_add_and_list_evidence(
    database: SaarthiDatabase,
) -> None:
    """Evidence records should be linked to an execution."""

    execution = database.create_execution(build_execution())

    evidence = database.add_evidence(
        execution.execution_id,
        EvidenceCreate(
            evidence_type=EvidenceType.HTTP_METADATA,
            source="internal-http-collector",
            path="evidence/http/example.json",
            sha256="a" * 64,
            size_bytes=1_024,
            content_type="application/json",
            step_id="recon-001",
            tool_name="internal-http-collector",
        ),
        actor="collector",
    )

    evidence_items = database.list_evidence(execution.execution_id)

    assert len(evidence_items) == 1
    assert evidence_items[0].evidence_id == evidence.evidence_id
    assert evidence_items[0].step_id == "recon-001"

    events = database.list_audit_events(execution.execution_id)

    assert events[-1].event_type.value == "evidence_added"


def test_list_executions_by_state(
    database: SaarthiDatabase,
) -> None:
    """Execution history should support state filtering."""

    first = database.create_execution(build_execution())
    database.create_execution(
        build_execution().model_copy(update={"assessment_name": "Second Web VAPT"})
    )

    database.transition_execution(
        first.execution_id,
        ExecutionState.VALIDATED,
        actor="tester",
    )

    validated = database.list_executions(state=ExecutionState.VALIDATED)

    assert len(validated) == 1
    assert validated[0].execution_id == first.execution_id
