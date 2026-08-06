from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from saarthi_ai.execution.nuclei_adapter import (
    NucleiDryRunRequest,
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
from saarthi_ai.persistence.nuclei_preview_workflow import (
    NucleiPreviewWorkflowError,
    create_tracked_nuclei_preview,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(
        tmp_path / "nuclei-preview.db"
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
            assessment_name="Controlled Nuclei Preview",
            asset_types=["web"],
            targets=[target],
            authorization_confirmed=authorized,
            active_testing_allowed=active_testing_allowed,
        )
    )
    return execution.execution_id


def make_request(
    **overrides: object,
) -> NucleiDryRunRequest:
    values: dict[str, object] = {
        "target_url": "https://example.com/",
        "authorized": True,
        "active_testing": True,
        "approval_granted": True,
        "rate_limit_per_second": 2,
        "concurrency": 2,
        "timeout_seconds": 10,
        "dry_run": True,
    }
    values.update(overrides)
    return NucleiDryRunRequest(**values)  # type: ignore[arg-type]


def test_persists_non_executed_nuclei_preview(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)

    result = create_tracked_nuclei_preview(
        database,
        execution_id,
        make_request(),
        evidence_root=tmp_path / "evidence",
    )

    assert result.execution.state is ExecutionState.PLANNED
    assert (
        result.evidence.evidence_type
        is EvidenceType.CONTROLLED_NUCLEI_PREVIEW
    )
    assert result.preview.executed is False
    assert result.preview.subprocess_started is False
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
    assert payload["execution"]["executed"] is False
    assert payload["execution"]["network_activity"] is False
    assert payload["execution"]["subprocess_started"] is False
    assert payload["execution"]["automatic_retry"] is False

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


def test_rejects_out_of_scope_target_without_evidence(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)

    with pytest.raises(
        InvalidStateTransitionError,
        match="not associated with this execution",
    ):
        create_tracked_nuclei_preview(
            database,
            execution_id,
            make_request(
                target_url="https://outside.test/"
            ),
            evidence_root=tmp_path,
        )

    assert database.list_evidence(execution_id) == []
    assert (
        database.get_execution(execution_id).state
        is ExecutionState.CREATED
    )


def test_requires_stored_active_testing_permission(
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
        create_tracked_nuclei_preview(
            database,
            execution_id,
            make_request(),
            evidence_root=tmp_path,
        )

    assert database.list_evidence(execution_id) == []


def test_repeated_preview_is_idempotent(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    request = make_request()

    first = create_tracked_nuclei_preview(
        database,
        execution_id,
        request,
        evidence_root=tmp_path / "evidence",
    )
    second = create_tracked_nuclei_preview(
        database,
        execution_id,
        request,
        evidence_root=tmp_path / "evidence",
    )

    evidence_items = database.list_evidence(
        execution_id,
        evidence_type=EvidenceType.CONTROLLED_NUCLEI_PREVIEW,
    )

    assert len(evidence_items) == 1
    assert first.evidence.evidence_id == second.evidence.evidence_id
    assert second.reused_existing_evidence is True

    reuse_events = [
        event
        for event in database.list_audit_events(execution_id)
        if event.details.get("idempotent_reuse") is True
    ]

    assert len(reuse_events) == 1


def test_registration_failure_removes_orphan_file(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_id = create_execution(database)
    evidence_root = tmp_path / "evidence"

    def fail_registration(*args: object, **kwargs: object) -> object:
        raise RuntimeError("simulated registration failure")

    monkeypatch.setattr(
        database,
        "add_evidence",
        fail_registration,
    )

    with pytest.raises(
        NucleiPreviewWorkflowError,
        match="could not be persisted safely",
    ):
        create_tracked_nuclei_preview(
            database,
            execution_id,
            make_request(),
            evidence_root=evidence_root,
        )

    assert database.list_evidence(execution_id) == []
    assert list(evidence_root.glob("*.json")) == []

    failures = [
        event
        for event in database.list_audit_events(execution_id)
        if event.event_type is AuditEventType.TOOL_FAILED
    ]

    assert len(failures) == 1
    assert failures[0].details["orphan_file_removed"] is True
    assert failures[0].details["subprocess_started"] is False
