from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from saarthi_ai.execution.nuclei_adapter import (
    NucleiDryRunRequest,
    NucleiExecutionRequest,
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
from saarthi_ai.persistence.nuclei_preparation_workflow import (
    NucleiPreparationWorkflowError,
    create_tracked_nuclei_preparation,
)
from saarthi_ai.persistence.nuclei_preview_workflow import (
    create_tracked_nuclei_preview,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(
        tmp_path / "nuclei-preparation.db"
    )
    repository.initialize()
    return repository


def create_execution(
    database: SaarthiDatabase,
    *,
    target: str = "example.com",
    authorized: bool = True,
    active_testing_allowed: bool = True,
) -> str:
    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Controlled Nuclei Preparation",
            asset_types=["web"],
            targets=[target],
            authorization_confirmed=authorized,
            active_testing_allowed=active_testing_allowed,
        )
    )
    return execution.execution_id


def create_preview(
    database: SaarthiDatabase,
    execution_id: str,
    evidence_root: Path,
):
    return create_tracked_nuclei_preview(
        database,
        execution_id,
        NucleiDryRunRequest(
            target_url="https://example.com/",
            authorized=True,
            active_testing=True,
            approval_granted=True,
            rate_limit_per_second=1,
            concurrency=1,
            timeout_seconds=7,
            dry_run=True,
        ),
        evidence_root=evidence_root,
    )


def make_request(preview, **overrides: object):
    values: dict[str, object] = {
        "preview": preview,
        "authorization_confirmed": True,
        "active_testing_allowed": True,
        "explicitly_approved": True,
    }
    values.update(overrides)
    return NucleiExecutionRequest(**values)  # type: ignore[arg-type]


def test_persists_non_executed_nuclei_preparation(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    preview = create_preview(
        database,
        execution_id,
        tmp_path / "preview",
    )

    result = create_tracked_nuclei_preparation(
        database,
        execution_id,
        make_request(preview.preview),
        evidence_root=tmp_path / "preparation",
    )

    assert result.execution.state is ExecutionState.PLANNED
    assert (
        result.evidence.evidence_type
        is EvidenceType.CONTROLLED_NUCLEI_PREPARATION
    )
    assert (
        result.preview_evidence.evidence_id
        == preview.evidence.evidence_id
    )
    assert result.plan.executed is False
    assert result.binding.executed is False
    assert result.reused_existing_evidence is False

    evidence_path = Path(result.evidence.path)
    evidence_bytes = evidence_path.read_bytes()
    payload = json.loads(evidence_bytes)

    assert (
        hashlib.sha256(evidence_bytes).hexdigest()
        == result.evidence.sha256
    )
    assert payload["phase"] == "6C"
    assert payload["tool"]["name"] == "nuclei"
    assert payload["tool"]["request_timeout_seconds"] == 7
    assert payload["tool"]["process_timeout_seconds"] == 120
    assert payload["tool"]["max_output_bytes_per_stream"] == 1_000_000

    assert payload["execution"] == {
        "executed": False,
        "network_activity": False,
        "subprocess_started": False,
        "runner_invoked": False,
        "executable_resolved": False,
        "automatic_retry": False,
    }

    events = database.list_audit_events(execution_id)

    assert any(
        event.event_type is AuditEventType.APPROVAL_RECORDED
        and event.details.get("phase_code") == "6C"
        for event in events
    )
    assert any(
        event.event_type is AuditEventType.TOOL_PREPARED
        and event.details.get("phase_code") == "6C"
        for event in events
    )
    assert any(
        event.event_type is AuditEventType.TOOL_COMPLETED
        and event.details.get("phase_code") == "6C"
        for event in events
    )


def test_requires_matching_persisted_preview(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)

    preview_result = create_preview(
        database,
        execution_id,
        tmp_path / "preview",
    )

    database_path = Path(preview_result.evidence.path)
    database_path.unlink()

    with database.connect() as connection:
        connection.execute(
            "DELETE FROM evidence WHERE evidence_id = ?",
            (preview_result.evidence.evidence_id,),
        )

    with pytest.raises(
        NucleiPreparationWorkflowError,
        match="matching persisted Nuclei preview",
    ):
        create_tracked_nuclei_preparation(
            database,
            execution_id,
            make_request(preview_result.preview),
            evidence_root=tmp_path / "preparation",
        )


def test_rejects_out_of_scope_preparation(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    preview = create_preview(
        database,
        execution_id,
        tmp_path / "preview",
    )

    from dataclasses import replace

    modified_preview = replace(
        preview.preview,
        target_url="https://outside.test/",
    )

    with pytest.raises(
        InvalidStateTransitionError,
        match="not associated with this execution",
    ):
        create_tracked_nuclei_preparation(
            database,
            execution_id,
            make_request(modified_preview),
            evidence_root=tmp_path / "preparation",
        )


def test_requires_explicit_preparation_approval(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    preview = create_preview(
        database,
        execution_id,
        tmp_path / "preview",
    )

    with pytest.raises(
        InvalidStateTransitionError,
        match="Explicit operator approval",
    ):
        create_tracked_nuclei_preparation(
            database,
            execution_id,
            make_request(
                preview.preview,
                explicitly_approved=False,
            ),
            evidence_root=tmp_path / "preparation",
        )


def test_repeated_preparation_is_idempotent(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    preview = create_preview(
        database,
        execution_id,
        tmp_path / "preview",
    )
    request = make_request(preview.preview)

    first = create_tracked_nuclei_preparation(
        database,
        execution_id,
        request,
        evidence_root=tmp_path / "preparation",
    )
    second = create_tracked_nuclei_preparation(
        database,
        execution_id,
        request,
        evidence_root=tmp_path / "preparation",
    )

    evidence_items = database.list_evidence(
        execution_id,
        evidence_type=(
            EvidenceType.CONTROLLED_NUCLEI_PREPARATION
        ),
    )

    assert len(evidence_items) == 1
    assert first.evidence.evidence_id == second.evidence.evidence_id
    assert second.reused_existing_evidence is True

    reuse_events = [
        event
        for event in database.list_audit_events(execution_id)
        if (
            event.details.get("phase_code") == "6C"
            and event.details.get("idempotent_reuse") is True
        )
    ]

    assert len(reuse_events) == 1


def test_registration_failure_removes_orphan_file(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_id = create_execution(database)
    preview = create_preview(
        database,
        execution_id,
        tmp_path / "preview",
    )
    evidence_root = tmp_path / "preparation"

    original_add_evidence = database.add_evidence

    def fail_preparation_registration(
        execution_id_value,
        request,
        *,
        actor="system",
    ):
        if (
            request.evidence_type
            is EvidenceType.CONTROLLED_NUCLEI_PREPARATION
        ):
            raise RuntimeError("simulated registration failure")

        return original_add_evidence(
            execution_id_value,
            request,
            actor=actor,
        )

    monkeypatch.setattr(
        database,
        "add_evidence",
        fail_preparation_registration,
    )

    with pytest.raises(
        NucleiPreparationWorkflowError,
        match="could not be persisted safely",
    ):
        create_tracked_nuclei_preparation(
            database,
            execution_id,
            make_request(preview.preview),
            evidence_root=evidence_root,
        )

    assert list(evidence_root.glob("*.json")) == []

    failures = [
        event
        for event in database.list_audit_events(execution_id)
        if (
            event.event_type is AuditEventType.TOOL_FAILED
            and event.details.get("phase_code") == "6C"
        )
    ]

    assert len(failures) == 1
    assert failures[0].details["orphan_file_removed"] is True
    assert failures[0].details["executed"] is False
    assert failures[0].details["network_activity"] is False
    assert failures[0].details["subprocess_started"] is False
    assert failures[0].details["runner_invoked"] is False
