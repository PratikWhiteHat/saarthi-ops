"""Persistence tests for redacted SQLmap previews."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from saarthi_ai.execution.sqlmap_adapter import (
    SqlmapMethod,
    SqlmapPostContentType,
    SqlmapPreviewRequest,
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
from saarthi_ai.persistence.sqlmap_preview_workflow import (
    create_tracked_sqlmap_preview,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "sqlmap-preview.db")
    repository.initialize()
    return repository


def create_execution(
    database: SaarthiDatabase,
    *,
    intrusive_testing_allowed: bool = True,
) -> str:
    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Controlled SQLmap Preview",
            asset_types=["web"],
            targets=["example.com"],
            authorization_confirmed=True,
            active_testing_allowed=True,
            intrusive_testing_allowed=intrusive_testing_allowed,
        )
    )
    return execution.execution_id


def make_request(
    **overrides: object,
) -> SqlmapPreviewRequest:
    values: dict[str, object] = {
        "target_url": (
            "https://example.com/search?id=secret-query-value"
        ),
        "parameter_name": "id",
        "method": SqlmapMethod.GET,
        "authorized": True,
        "active_testing": True,
        "intrusive_testing": True,
        "approval_granted": True,
    }
    values.update(overrides)
    return SqlmapPreviewRequest(**values)  # type: ignore[arg-type]


def test_persists_verbose_redacted_preview(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    result = create_tracked_sqlmap_preview(
        database,
        execution_id,
        make_request(),
        evidence_root=tmp_path / "evidence",
    )

    assert result.execution.state is ExecutionState.PLANNED
    assert (
        result.evidence.evidence_type
        is EvidenceType.CONTROLLED_SQLMAP_PREVIEW
    )
    evidence_text = Path(result.evidence.path).read_text()
    metadata_text = json.dumps(result.evidence.metadata)
    audit_text = json.dumps(
        [
            event.details
            for event in database.list_audit_events(execution_id)
        ]
    )
    for persisted in (evidence_text, metadata_text, audit_text):
        assert "secret-query-value" not in persisted

    payload = json.loads(evidence_text)
    assert payload["phase"] == "6C.1"
    assert payload["tool"]["name"] == "sqlmap"
    assert payload["safety"] == {
        "executable_arguments_built": False,
        "executed": False,
        "network_activity": False,
        "request_values_stored": False,
        "subprocess_started": False,
    }
    events = database.list_audit_events(execution_id)
    assert any(
        event.event_type is AuditEventType.TOOL_OUTPUT
        and event.details.get("techniques") == "BE"
        and event.details.get("executed") is False
        for event in events
    )


def test_post_preview_persists_names_but_no_values(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    result = create_tracked_sqlmap_preview(
        database,
        execution_id,
        make_request(
            target_url="https://example.com/login",
            parameter_name="username",
            method=SqlmapMethod.POST,
            post_parameter_names=("username", "password"),
            post_content_type=SqlmapPostContentType.JSON,
        ),
        evidence_root=tmp_path / "evidence",
    )

    payload = json.loads(Path(result.evidence.path).read_text())
    assert payload["tool"]["method"] == "POST"
    assert payload["tool"]["post_parameter_names"] == [
        "username",
        "password",
    ]
    assert payload["tool"]["post_content_type"] == "application/json"
    assert payload["safety"]["request_values_stored"] is False


def test_preview_reuse_creates_no_second_evidence(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    request = make_request()
    first = create_tracked_sqlmap_preview(
        database,
        execution_id,
        request,
        evidence_root=tmp_path / "evidence",
    )
    second = create_tracked_sqlmap_preview(
        database,
        execution_id,
        request,
        evidence_root=tmp_path / "evidence",
    )

    assert first.evidence.evidence_id == second.evidence.evidence_id
    assert second.reused_existing_evidence is True
    assert len(
        database.list_evidence(
            execution_id,
            evidence_type=EvidenceType.CONTROLLED_SQLMAP_PREVIEW,
        )
    ) == 1


def test_requires_stored_intrusive_permission(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(
        database,
        intrusive_testing_allowed=False,
    )

    with pytest.raises(
        InvalidStateTransitionError,
        match="does not allow intrusive testing",
    ):
        create_tracked_sqlmap_preview(
            database,
            execution_id,
            make_request(),
            evidence_root=tmp_path / "evidence",
        )

    assert database.list_evidence(execution_id) == []
