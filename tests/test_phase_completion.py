"""Phase-child completion: children must reach COMPLETED to render DONE.

complete_phase_execution walks a freshly-created phase child through the state
machine to COMPLETED so the orchestration/TUI recognize the phase as done.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from saarthi_ai.orchestration.models import OrchestrationPhase
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import ExecutionCreate, ExecutionState
from saarthi_ai.persistence.orchestration_workflow import (
    complete_phase_execution,
    create_orchestration,
    create_phase_execution,
)
from saarthi_ai.tui.app import phase_rows


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "complete.db")
    repository.initialize()
    return repository


def test_walks_created_to_completed(database: SaarthiDatabase) -> None:
    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="c",
            asset_types=["web"],
            targets=["http://t/"],
            authorization_confirmed=True,
            active_testing_allowed=False,
            intrusive_testing_allowed=False,
        )
    )
    assert execution.state is ExecutionState.CREATED
    done = complete_phase_execution(
        database, execution.execution_id, actor="t", reason="done"
    )
    assert done.state is ExecutionState.COMPLETED


def test_idempotent_on_terminal_state(database: SaarthiDatabase) -> None:
    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="c",
            asset_types=["web"],
            targets=["http://t/"],
            authorization_confirmed=True,
            active_testing_allowed=False,
            intrusive_testing_allowed=False,
        )
    )
    complete_phase_execution(database, execution.execution_id, actor="t")
    # Second call is a no-op, not an error.
    again = complete_phase_execution(database, execution.execution_id, actor="t")
    assert again.state is ExecutionState.COMPLETED


def test_completed_phase_children_render_done(database: SaarthiDatabase) -> None:
    context = create_orchestration(
        database,
        assessment_name="run",
        target_url="http://t.example/",
        active_testing_allowed=True,
        intrusive_testing_allowed=True,
        rate_limit_per_second=2,
        actor="t",
    )
    phases = [
        OrchestrationPhase.BLIND_VALIDATION,
        OrchestrationPhase.OAST_MANAGER,
        OrchestrationPhase.CONFIRMATION,
        OrchestrationPhase.EXPLOIT_CONFIRMATION,
        OrchestrationPhase.POST_EXPLOITATION,
        OrchestrationPhase.CLEANUP,
    ]
    for phase in phases:
        child = create_phase_execution(
            database,
            context,
            phase=phase,
            phase_name=phase.value,
            active_testing_allowed=False,
        )
        done = complete_phase_execution(
            database, child.execution_id, actor="t", reason="done"
        )
        assert done.state is ExecutionState.COMPLETED

    completed = {
        (e.metadata or {}).get("phase_code")
        for e in database.list_executions(limit=1_000)
        if (e.metadata or {}).get("execution_role") == "orchestration_child"
        and e.state is ExecutionState.COMPLETED
    }
    completed.discard(None)
    status = {
        code: state
        for _m, code, _n, state, _d in phase_rows(
            "6G — CLEANUP & ROLLBACK", list(completed)
        )
    }
    for code in ("4B", "4C", "4D", "6E", "6F", "6G"):
        assert status[code] == "DONE", (code, status[code])
