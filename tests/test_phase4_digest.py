"""Phase 4B/4C/4D surfacing in the AI-analyze digest.

The blind/OAST/confirmation validators run as prerequisite gates in the auto
chain; their outcomes live in audit events (not evidence). The digest must lift
them so the analyst model reasons about them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from saarthi_ai.analysis.engine import build_analysis_prompt, gather_run_digest
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import AuditEventType, ExecutionCreate

OID = "orchestration-phase4"

_GATES = [
    ("4B", "No approved blind-validation candidate was selected."),
    ("4C", "No active OAST correlation exists for this target."),
    ("4D", "No confirmation candidate with supporting evidence was available."),
]


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "p4.db")
    repository.initialize()
    return repository


def _parent_with_gates(database: SaarthiDatabase) -> None:
    parent = database.create_execution(
        ExecutionCreate(
            assessment_name="full",
            asset_types=["web"],
            targets=["http://t/"],
            authorization_confirmed=True,
            active_testing_allowed=True,
            intrusive_testing_allowed=False,
            metadata={
                "orchestration_id": OID,
                "execution_role": "orchestration_parent",
            },
        )
    )
    for code, reason in _GATES:
        database.add_audit_event(
            parent.execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor="orchestrator",
            message=f"[{code}][orchestrator] gate",
            details={
                "phase_code": code,
                "outcome": "not_applicable",
                "reason": reason,
                "gate_evaluated": True,
                "executed": False,
                "network_activity": False,
            },
        )


def test_phase4_gates_surface_in_digest(database: SaarthiDatabase) -> None:
    _parent_with_gates(database)
    digest = gather_run_digest(database, orchestration_id=OID)
    summary = digest.phase4_validation_summary
    assert summary is not None
    for code, reason in _GATES:
        assert code in summary
        assert reason in summary


def test_phase4_block_in_analysis_prompt(database: SaarthiDatabase) -> None:
    _parent_with_gates(database)
    digest = gather_run_digest(database, orchestration_id=OID)
    prompt = build_analysis_prompt(digest)
    assert "Blind / OAST / confirmation validators (4B/4C/4D" in prompt
    # The loopback caveat must be visible to the analyst.
    assert "loopback-only collaborator" in prompt


def test_no_phase4_block_when_no_gates(database: SaarthiDatabase) -> None:
    database.create_execution(
        ExecutionCreate(
            assessment_name="bare",
            asset_types=["web"],
            targets=["http://t/"],
            authorization_confirmed=True,
            active_testing_allowed=False,
            intrusive_testing_allowed=False,
            metadata={"orchestration_id": OID, "execution_role": "orchestration_parent"},
        )
    )
    digest = gather_run_digest(database, orchestration_id=OID)
    assert digest.phase4_validation_summary is None
    assert "4B/4C/4D" not in build_analysis_prompt(digest)
