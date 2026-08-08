"""Phase 6G — `saarthi cleanup` show + rollback CLI tests (guard paths)."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

import saarthi_ai.cli as cli
from saarthi_ai.cleanup.planner import build_cleanup_manifest
from saarthi_ai.persistence.cleanup_workflow import _gather_run_evidence
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import (
    EvidenceCreate,
    EvidenceType,
    ExecutionCreate,
)

OID = "orchestration-cli-6g"


@pytest.fixture
def database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "cli6g.db")
    repository.initialize()
    monkeypatch.setattr(cli, "get_database", lambda: repository)
    return repository


def _seed(database: SaarthiDatabase) -> None:
    parent = database.create_execution(
        ExecutionCreate(
            assessment_name="6G CLI",
            asset_types=["web"],
            targets=["http://t.example/"],
            authorization_confirmed=True,
            active_testing_allowed=False,
            intrusive_testing_allowed=False,
            metadata={
                "orchestration_id": OID,
                "execution_role": "orchestration_parent",
            },
        )
    )
    for et, path, meta in [
        (EvidenceType.SQLMAP_EXTERNAL_RESULT, "/e/s.txt", {}),
        (
            EvidenceType.UPLOAD_EXTERNAL_RESULT,
            "/e/up.json",
            {"uploaded_url": "http://t.example/uploads/x.txt"},
        ),
        (
            EvidenceType.UPLOAD_EXTERNAL_RESULT,
            "/e/up2.json",
            {"uploaded_url": "http://evil.com/x.txt"},
        ),
    ]:
        database.add_evidence(
            parent.execution_id,
            EvidenceCreate(
                evidence_type=et,
                source="x",
                path=path,
                sha256="0" * 64,
                size_bytes=1,
                content_type="application/json",
                step_id="s",
                tool_name="t",
                metadata=meta,
            ),
        )


def _items(database: SaarthiDatabase) -> dict:
    target, records = _gather_run_evidence(database, OID)
    manifest = build_cleanup_manifest(target=target, evidence_records=records)
    return {i.location: i for i in manifest.items}


def test_show_lists_items_and_footprint(database: SaarthiDatabase) -> None:
    _seed(database)
    result = CliRunner().invoke(cli.app, ["cleanup", "show", "--orchestration", OID])
    assert result.exit_code == 0
    text = " ".join(result.output.split())
    assert "target_footprint_present" in text
    assert "no target-side action taken" in text


def test_show_clean_run_reports_no_footprint(database: SaarthiDatabase) -> None:
    database.create_execution(
        ExecutionCreate(
            assessment_name="clean",
            asset_types=["web"],
            targets=["http://t.example/"],
            authorization_confirmed=True,
            active_testing_allowed=False,
            intrusive_testing_allowed=False,
            metadata={"orchestration_id": OID, "execution_role": "orchestration_parent"},
        )
    )
    result = CliRunner().invoke(cli.app, ["cleanup", "show", "--orchestration", OID])
    assert result.exit_code == 0
    assert "left no footprint" in " ".join(result.output.split())


def test_rollback_operator_action_is_guidance_only(database: SaarthiDatabase) -> None:
    _seed(database)
    sqlmap = _items(database)["/e/s.txt"]
    result = CliRunner().invoke(
        cli.app, ["cleanup", "rollback", "--orchestration", OID, "--item", sqlmap.item_id]
    )
    assert result.exit_code == 0
    assert "handle manually" in " ".join(result.output.split())


def test_rollback_offhost_refused_even_with_approved(database: SaarthiDatabase) -> None:
    _seed(database)
    offhost = _items(database)["http://evil.com/x.txt"]
    result = CliRunner().invoke(
        cli.app,
        [
            "cleanup",
            "rollback",
            "--orchestration",
            OID,
            "--item",
            offhost.item_id,
            "--approved",
        ],
    )
    assert result.exit_code == 1
    assert "outside the run target" in " ".join(result.output.split())


def test_rollback_onhost_requires_approval(database: SaarthiDatabase) -> None:
    _seed(database)
    onhost = _items(database)["http://t.example/uploads/x.txt"]
    result = CliRunner().invoke(
        cli.app,
        ["cleanup", "rollback", "--orchestration", OID, "--item", onhost.item_id],
    )
    # Blocked at the approval gate before any network call.
    assert result.exit_code == 1
    assert "Approval required" in " ".join(result.output.split())


def test_rollback_unknown_item_errors(database: SaarthiDatabase) -> None:
    _seed(database)
    result = CliRunner().invoke(
        cli.app, ["cleanup", "rollback", "--orchestration", OID, "--item", "nope"]
    )
    assert result.exit_code == 1
