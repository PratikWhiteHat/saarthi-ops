"""Tests for manual-only upload validation planning and result import."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceType,
    ExecutionCreate,
    ExecutionState,
)
from saarthi_ai.persistence.upload_validation_workflow import (
    RESULT_SCHEMA,
    UploadCleanupStatus,
    UploadValidationKind,
    UploadValidationOutcome,
    UploadValidationWorkflowError,
    create_upload_validation_plan,
    import_upload_validation_result,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "upload-validation.db")
    repository.initialize()
    return repository


def create_execution(database: SaarthiDatabase) -> str:
    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Manual Upload Validation",
            asset_types=["web"],
            targets=["https://example.com/upload"],
            authorization_confirmed=True,
            active_testing_allowed=True,
            intrusive_testing_allowed=True,
        )
    )
    return execution.execution_id


def test_creates_non_executing_approved_plan(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    plan = create_upload_validation_plan(
        database,
        execution_id,
        target_url="https://example.com/upload",
        kind=UploadValidationKind.EXTENSION_BYPASS,
        explicitly_approved=True,
        evidence_root=tmp_path / "plans",
    )

    payload = json.loads(Path(plan.evidence.path).read_text())
    assert plan.execution.state is ExecutionState.PLANNED
    assert plan.evidence.evidence_type is EvidenceType.UPLOAD_VALIDATION_PLAN
    assert payload["execution"]["manual_only"] is True
    assert payload["execution"]["file_uploaded_by_saarthi"] is False
    assert payload["execution"]["executable_instructions_included"] is False


def test_imports_matching_result_and_tracks_cleanup(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    plan = create_upload_validation_plan(
        database,
        execution_id,
        target_url="https://example.com/upload",
        kind=UploadValidationKind.MIME_CONTENT_CONSISTENCY,
        explicitly_approved=True,
        evidence_root=tmp_path / "plans",
    )
    result_file = tmp_path / "external-result.json"
    result_file.write_text(
        json.dumps(
            {
                "schema": RESULT_SCHEMA,
                "execution_id": execution_id,
                "plan_sha256": plan.evidence.sha256,
                "validation_kind": (
                    UploadValidationKind.MIME_CONTENT_CONSISTENCY.value
                ),
                "outcome": UploadValidationOutcome.ACCEPTED.value,
                "cleanup_status": UploadCleanupStatus.VERIFIED.value,
            }
        )
    )

    imported = import_upload_validation_result(
        database,
        execution_id,
        result_file,
        evidence_root=tmp_path / "results",
    )

    assert imported.execution.state is ExecutionState.COMPLETED
    assert imported.outcome is UploadValidationOutcome.ACCEPTED
    assert imported.cleanup_status is UploadCleanupStatus.VERIFIED
    assert (
        imported.result_evidence.evidence_type
        is EvidenceType.UPLOAD_EXTERNAL_RESULT
    )
    findings = [
        event
        for event in database.list_audit_events(execution_id)
        if event.event_type is AuditEventType.FINDING_CREATED
    ]
    assert len(findings) == 1
    assert findings[0].details["confirmed_by_saarthi"] is False


def test_rejects_result_with_submitted_file_content(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    plan = create_upload_validation_plan(
        database,
        execution_id,
        target_url="https://example.com/upload",
        kind=UploadValidationKind.EXTENSION_BYPASS,
        explicitly_approved=True,
        evidence_root=tmp_path / "plans",
    )
    result_file = tmp_path / "unsafe-result.json"
    result_file.write_text(
        json.dumps(
            {
                "schema": RESULT_SCHEMA,
                "execution_id": execution_id,
                "plan_sha256": plan.evidence.sha256,
                "validation_kind": UploadValidationKind.EXTENSION_BYPASS.value,
                "outcome": UploadValidationOutcome.REJECTED.value,
                "cleanup_status": UploadCleanupStatus.NOT_REQUIRED.value,
                "file_content": "must not be imported",
            }
        )
    )

    with pytest.raises(
        UploadValidationWorkflowError,
        match="prohibited",
    ):
        import_upload_validation_result(
            database,
            execution_id,
            result_file,
            evidence_root=tmp_path / "results",
        )


def test_accepted_result_requires_cleanup_tracking(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    plan = create_upload_validation_plan(
        database,
        execution_id,
        target_url="https://example.com/upload",
        kind=UploadValidationKind.EXTENSION_BYPASS,
        explicitly_approved=True,
        evidence_root=tmp_path / "plans",
    )
    result_file = tmp_path / "result.json"
    result_file.write_text(
        json.dumps(
            {
                "schema": RESULT_SCHEMA,
                "execution_id": execution_id,
                "plan_sha256": plan.evidence.sha256,
                "validation_kind": UploadValidationKind.EXTENSION_BYPASS.value,
                "outcome": UploadValidationOutcome.ACCEPTED.value,
                "cleanup_status": UploadCleanupStatus.NOT_REQUIRED.value,
            }
        )
    )

    with pytest.raises(
        UploadValidationWorkflowError,
        match="cleanup",
    ):
        import_upload_validation_result(
            database,
            execution_id,
            result_file,
            evidence_root=tmp_path / "results",
        )
