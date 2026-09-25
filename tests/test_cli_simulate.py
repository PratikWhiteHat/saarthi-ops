"""Phase 6F — `saarthi simulate` CLI tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import saarthi_ai.cli as cli
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import (
    EvidenceCreate,
    EvidenceType,
    ExecutionCreate,
)
from saarthi_ai.persistence.post_exploitation_workflow import (
    run_tracked_post_exploitation,
)

ORCHESTRATION_ID = "orchestration-cli-6f"


@pytest.fixture
def database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "cli6f.db")
    repository.initialize()
    monkeypatch.setattr(cli, "get_database", lambda: repository)
    return repository


def _seed_6e(database: SaarthiDatabase, tmp_path: Path) -> str:
    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Phase 6F CLI",
            asset_types=["web"],
            targets=["http://t/"],
            authorization_confirmed=True,
            active_testing_allowed=False,
            intrusive_testing_allowed=False,
            metadata={
                "orchestration_id": ORCHESTRATION_ID,
                "execution_role": "orchestration_parent",
            },
        )
    )
    payload = {
        "target": "http://t/",
        "confirmed_count": 1,
        "highest_severity": "critical",
        "findings": [
            {
                "finding_id": "f1",
                "source_tool": "sqlmap",
                "kind": "sql_injection",
                "severity": "critical",
                "target": "http://t/p?id=1",
                "parameter": "id",
                "verdict": "confirmed_impact",
                "proof": ["back-end DBMS: MySQL", "current user is DBA: True"],
            }
        ],
    }
    path = tmp_path / "6e.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    database.add_evidence(
        execution.execution_id,
        EvidenceCreate(
            evidence_type=EvidenceType.EXPLOIT_CONFIRMATION_RESULT,
            source="exploit-confirmation",
            path=str(path),
            sha256="0" * 64,
            size_bytes=path.stat().st_size,
            content_type="application/json",
            step_id="phase6e-001",
            tool_name="exploit-confirmation",
        ),
    )
    return execution.execution_id


def test_simulate_regenerates_from_6e(
    database: SaarthiDatabase, tmp_path: Path
) -> None:
    _seed_6e(database, tmp_path)
    result = CliRunner().invoke(cli.app, ["simulate", "--orchestration", ORCHESTRATION_ID])
    assert result.exit_code == 0
    # Normalize whitespace: Rich wraps console lines at the terminal width.
    normalized = " ".join(result.output.split())
    assert "post-exploitation simulation" in normalized
    assert "sql_injection" in normalized
    assert "regenerated on the fly" in normalized
    # The safety invariant must be surfaced to the operator.
    assert "nothing was executed against the target" in normalized


def test_simulate_reads_persisted_result(
    database: SaarthiDatabase, tmp_path: Path
) -> None:
    execution_id = _seed_6e(database, tmp_path)
    run_tracked_post_exploitation(
        database,
        execution_id,
        orchestration_id=ORCHESTRATION_ID,
        evidence_root=tmp_path / "6f",
    )
    result = CliRunner().invoke(cli.app, ["simulate", "--orchestration", ORCHESTRATION_ID])
    assert result.exit_code == 0
    assert "sql_injection" in result.output
    # A persisted result is used verbatim, not regenerated.
    assert "regenerated on the fly" not in result.output


def test_simulate_without_evidence_errors(database: SaarthiDatabase) -> None:
    result = CliRunner().invoke(
        cli.app, ["simulate", "--orchestration", "does-not-exist"]
    )
    assert result.exit_code == 1
