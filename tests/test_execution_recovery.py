"""Startup recovery for interrupted execution records."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.execution_recovery import recover_stale_executions
from saarthi_ai.persistence.models import ExecutionCreate, ExecutionState


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "recovery.db")
    repository.initialize()
    return repository


def _execution(
    database: SaarthiDatabase,
    *,
    role: str,
    state: ExecutionState,
) -> str:
    record = database.create_execution(
        ExecutionCreate(
            assessment_name=f"Recovery {role}",
            asset_types=["web"],
            targets=["https://app.example.test/"],
            authorization_confirmed=True,
            metadata={"execution_role": role},
        )
    )
    path = {
        ExecutionState.CREATED: (),
        ExecutionState.VALIDATED: (ExecutionState.VALIDATED,),
        ExecutionState.PLANNED: (
            ExecutionState.VALIDATED,
            ExecutionState.PLANNED,
        ),
        ExecutionState.RUNNING: (
            ExecutionState.VALIDATED,
            ExecutionState.PLANNED,
            ExecutionState.RUNNING,
        ),
        ExecutionState.ANALYZING: (
            ExecutionState.VALIDATED,
            ExecutionState.PLANNED,
            ExecutionState.RUNNING,
            ExecutionState.ANALYZING,
        ),
    }[state]
    for next_state in path:
        record = database.transition_execution(
            record.execution_id,
            next_state,
            actor="test",
        )
    return record.execution_id


def _set_updated_at(
    database: SaarthiDatabase,
    execution_id: str,
    updated_at: datetime,
) -> None:
    with database.connect() as connection:
        connection.execute(
            "UPDATE executions SET updated_at = ? WHERE execution_id = ?",
            (updated_at.isoformat(), execution_id),
        )


def test_recovers_only_stale_active_records(database: SaarthiDatabase) -> None:
    now = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
    stale_running = _execution(
        database,
        role="orchestration_child",
        state=ExecutionState.RUNNING,
    )
    stale_analyzing = _execution(
        database,
        role="orchestration_parent",
        state=ExecutionState.ANALYZING,
    )
    recent_running = _execution(
        database,
        role="orchestration_child",
        state=ExecutionState.RUNNING,
    )
    planned = _execution(
        database,
        role="orchestration_child",
        state=ExecutionState.PLANNED,
    )
    _set_updated_at(database, stale_running, now - timedelta(hours=8))
    _set_updated_at(database, stale_analyzing, now - timedelta(hours=7))
    _set_updated_at(database, recent_running, now - timedelta(hours=1))
    _set_updated_at(database, planned, now - timedelta(days=2))

    result = recover_stale_executions(database, now=now)

    assert result.recovered_execution_ids == (
        stale_running,
        stale_analyzing,
    )
    assert database.get_execution(stale_running).state is ExecutionState.FAILED
    assert database.get_execution(stale_analyzing).state is ExecutionState.FAILED
    assert database.get_execution(recent_running).state is ExecutionState.RUNNING
    assert database.get_execution(planned).state is ExecutionState.PLANNED

    events = database.list_audit_events(stale_running)
    assert events[-1].message.startswith("[RECOVERY]")
    assert events[-1].details["automatic"] is True
    assert events[-1].details["stale_threshold_seconds"] == 21_600


def test_recovery_is_idempotent(database: SaarthiDatabase) -> None:
    now = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
    execution_id = _execution(
        database,
        role="orchestration_child",
        state=ExecutionState.RUNNING,
    )
    _set_updated_at(database, execution_id, now - timedelta(days=1))

    first = recover_stale_executions(database, now=now)
    second = recover_stale_executions(database, now=now)

    assert first.recovered_count == 1
    assert second.recovered_count == 0


def test_recovery_rejects_invalid_time_configuration(
    database: SaarthiDatabase,
) -> None:
    with pytest.raises(ValueError, match="greater than zero"):
        recover_stale_executions(database, max_age=timedelta(0))
    with pytest.raises(ValueError, match="timezone-aware"):
        recover_stale_executions(database, now=datetime(2026, 9, 22, 12, 0))
