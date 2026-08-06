"""Tests for asynchronous SQLmap handoff and local result import."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from saarthi_ai.execution.sqlmap_adapter import (
    SqlmapMethod,
    SqlmapPreviewRequest,
)
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import (
    EvidenceType,
    ExecutionCreate,
    ExecutionState,
)
from saarthi_ai.persistence.sqlmap_handoff_workflow import (
    NORMALIZED_RESULT_SCHEMA,
    SqlmapHandoffWorkflowError,
    analyze_imported_sqlmap_result,
    create_sqlmap_handoff,
    finalize_sqlmap_external_result,
    import_sqlmap_external_result,
    select_sqlmap_result_file,
)
from saarthi_ai.persistence.sqlmap_preview_workflow import (
    create_tracked_sqlmap_preview,
)
from saarthi_ai.tui.app import (
    build_phase6_chain_status,
    current_phase_for_dashboard,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "sqlmap-handoff.db")
    repository.initialize()
    return repository


def create_preview(
    database: SaarthiDatabase,
    tmp_path: Path,
):
    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="SQLmap External Handoff",
            asset_types=["web"],
            targets=["example.com"],
            authorization_confirmed=True,
            active_testing_allowed=True,
            intrusive_testing_allowed=True,
            metadata={
                "phase_code": "6C-sqlmap-preview",
                "phase_name": "SQLmap Non-Executed Preview",
            },
        )
    )
    preview = create_tracked_sqlmap_preview(
        database,
        execution.execution_id,
        SqlmapPreviewRequest(
            target_url="https://example.com/search?id=secret",
            parameter_name="id",
            method=SqlmapMethod.GET,
            authorized=True,
            active_testing=True,
            intrusive_testing=True,
            approval_granted=True,
        ),
        evidence_root=tmp_path / "preview",
    )
    return preview


def test_creates_non_executable_handoff_manifest(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    preview = create_preview(database, tmp_path)
    handoff = create_sqlmap_handoff(
        database,
        preview,
        evidence_root=tmp_path / "handoff",
    )

    payload = json.loads(Path(handoff.manifest_evidence.path).read_text())
    assert handoff.execution.state is ExecutionState.PLANNED
    assert (
        handoff.manifest_evidence.evidence_type
        is EvidenceType.SQLMAP_HANDOFF_MANIFEST
    )
    assert payload["mode"] == "external-manual-result-import"
    assert payload["executable_command_included"] is False
    assert payload["network_activity_performed"] is False
    assert payload["candidate"]["parameter_name"] == "id"
    assert "secret" not in json.dumps(payload)
    assert "arguments" not in payload


def test_imports_hashes_and_completes_external_result(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    preview = create_preview(database, tmp_path)
    handoff = create_sqlmap_handoff(
        database,
        preview,
        evidence_root=tmp_path / "handoff",
    )
    result_file = tmp_path / "operator-result.json"
    result_file.write_text(
        json.dumps(
            {
                "summary": "operator supplied result",
                "findings": [],
            }
        )
    )

    imported = import_sqlmap_external_result(
        database,
        preview.execution.execution_id,
        result_file,
        evidence_root=tmp_path / "imports",
    )

    assert imported.execution.state is ExecutionState.COMPLETED
    assert (
        imported.result_evidence.evidence_type
        is EvidenceType.SQLMAP_EXTERNAL_RESULT
    )
    assert imported.result_evidence.sha256
    assert Path(imported.result_evidence.path).read_bytes() == (
        result_file.read_bytes()
    )
    assert (
        imported.result_evidence.metadata["manifest_evidence_id"]
        == handoff.manifest_evidence.evidence_id
    )
    assert imported.result_evidence.metadata["tool_launched_by_saarthi"] is False
    assert imported.result_evidence.metadata["network_activity_by_saarthi"] is False

    events = database.list_audit_events(preview.execution.execution_id)
    assert any("no SQLmap subprocess" in event.message for event in events)


def test_import_is_idempotent_for_same_result(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    preview = create_preview(database, tmp_path)
    create_sqlmap_handoff(
        database,
        preview,
        evidence_root=tmp_path / "handoff",
    )
    result_file = tmp_path / "operator-result.log"
    result_file.write_text("operator supplied result\n")

    first = import_sqlmap_external_result(
        database,
        preview.execution.execution_id,
        result_file,
        evidence_root=tmp_path / "imports",
    )
    second = import_sqlmap_external_result(
        database,
        preview.execution.execution_id,
        result_file,
        evidence_root=tmp_path / "imports",
    )

    assert second.reused_existing_evidence is True
    assert (
        second.result_evidence.evidence_id
        == first.result_evidence.evidence_id
    )


def test_registers_strict_normalized_findings_for_review(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    preview = create_preview(database, tmp_path)
    handoff = create_sqlmap_handoff(
        database,
        preview,
        evidence_root=tmp_path / "handoff",
    )
    result_file = tmp_path / "normalized-result.json"
    result_file.write_text(
        json.dumps(
            {
                "schema": NORMALIZED_RESULT_SCHEMA,
                "execution_id": preview.execution.execution_id,
                "manifest_sha256": handoff.manifest_evidence.sha256,
                "findings": [
                    {
                        "parameter": "id",
                        "technique": "operator-reported boolean behavior",
                        "dbms": "unknown",
                        "confidence": "medium",
                    }
                ],
            }
        )
    )

    imported = import_sqlmap_external_result(
        database,
        preview.execution.execution_id,
        result_file,
        evidence_root=tmp_path / "imports",
    )

    assert (
        imported.result_evidence.metadata["normalized_finding_count"]
        == 1
    )
    findings = [
        event
        for event in database.list_audit_events(
            preview.execution.execution_id
        )
        if event.event_type.value == "finding_created"
    ]
    assert len(findings) == 1
    assert findings[0].details["parameter"] == "id"
    assert findings[0].details["confirmed_by_saarthi"] is False


def test_sanitizes_raw_log_findings_and_is_idempotent(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    preview = create_preview(database, tmp_path)
    create_sqlmap_handoff(
        database,
        preview,
        evidence_root=tmp_path / "handoff",
    )
    result_file = tmp_path / "operator-result.log"
    result_file.write_text(
        "\n".join(
            (
                "Parameter: id (GET)",
                "    Type: boolean-based blind",
                "    Title: ignored external title",
                "    Payload: ignored and never parsed",
                "back-end DBMS: MySQL",
                "",
            )
        )
    )

    imported = import_sqlmap_external_result(
        database,
        preview.execution.execution_id,
        result_file,
        evidence_root=tmp_path / "imports",
    )
    analyzed = analyze_imported_sqlmap_result(
        database,
        preview.execution.execution_id,
    )

    assert (
        imported.result_evidence.metadata["normalized_finding_count"]
        == 1
    )
    assert analyzed.finding_count == 1
    assert analyzed.reused_existing_findings is True
    findings = [
        event
        for event in database.list_audit_events(
            preview.execution.execution_id
        )
        if event.event_type.value == "finding_created"
    ]
    assert len(findings) == 1
    assert findings[0].details == {
        "phase_code": "6C.1",
        "tool": "sqlmap",
        "result_evidence_id": imported.result_evidence.evidence_id,
        "parameter": "id",
        "method": "GET",
        "technique": "boolean-based blind",
        "dbms": "MySQL",
        "confidence": "medium",
        "source": "operator_supplied_external_result",
        "confirmed_by_saarthi": False,
        "payload_stored_in_finding": False,
    }


def test_finalizes_standard_sqlmap_output_directory(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    preview = create_preview(database, tmp_path)
    create_sqlmap_handoff(
        database,
        preview,
        evidence_root=tmp_path / "handoff",
    )
    output = tmp_path / "sqlmap-output" / "example.com"
    output.mkdir(parents=True)
    (output / "session.sqlite").write_bytes(b"not imported")
    raw_log = output / "log"
    raw_log.write_text(
        "\n".join(
            (
                "Parameter: id (GET)",
                "    Type: boolean-based blind",
                "    Payload: ignored",
                "back-end DBMS: MySQL",
                "",
            )
        )
    )

    result = finalize_sqlmap_external_result(
        database,
        preview.execution.execution_id,
        output,
        evidence_root=tmp_path / "imports",
    )

    assert result.selected_result_path == str(raw_log)
    assert result.imported.execution.state is ExecutionState.COMPLETED
    assert result.imported.result_evidence.path.endswith(".log")
    assert result.analyzed.finding_count == 1


def test_rejects_ambiguous_result_directory(tmp_path: Path) -> None:
    output = tmp_path / "sqlmap-output"
    output.mkdir()
    (output / "first.log").write_text("first\n")
    (output / "second.json").write_text("{}\n")

    with pytest.raises(
        SqlmapHandoffWorkflowError,
        match="ambiguous",
    ):
        select_sqlmap_result_file(output)


def test_rejects_tampered_handoff_manifest(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    preview = create_preview(database, tmp_path)
    handoff = create_sqlmap_handoff(
        database,
        preview,
        evidence_root=tmp_path / "handoff",
    )
    Path(handoff.manifest_evidence.path).write_text("{}\n")
    result_file = tmp_path / "operator-result.txt"
    result_file.write_text("result\n")

    with pytest.raises(
        SqlmapHandoffWorkflowError,
        match="hash does not match",
    ):
        import_sqlmap_external_result(
            database,
            preview.execution.execution_id,
            result_file,
            evidence_root=tmp_path / "imports",
        )


def test_tui_tracks_waiting_and_imported_states(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    preview = create_preview(database, tmp_path)
    create_sqlmap_handoff(
        database,
        preview,
        evidence_root=tmp_path / "handoff",
    )

    with database.connect() as connection:
        rows = connection.execute(
            "SELECT state, metadata_json FROM executions"
        ).fetchall()
    waiting = build_phase6_chain_status(
        rows,
        "metadata_json",
        "state",
    )
    assert waiting["sqlmap"] == "AWAITING RESULT"
    assert current_phase_for_dashboard(
        "completed",
        (),
        {"6A"},
        waiting,
    ) == "6C — LOW-RISK ATTACK VALIDATORS"

    result_file = tmp_path / "operator-result.jsonl"
    result_file.write_text('{"type":"operator-result"}\n')
    import_sqlmap_external_result(
        database,
        preview.execution.execution_id,
        result_file,
        evidence_root=tmp_path / "imports",
    )
    with database.connect() as connection:
        rows = connection.execute(
            "SELECT state, metadata_json FROM executions"
        ).fetchall()
    imported = build_phase6_chain_status(
        rows,
        "metadata_json",
        "state",
    )
    assert imported["sqlmap"] == "IMPORTED"
