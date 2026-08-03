from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from saarthi_ai.blind_validation.models import (
    BlindValidationRequest,
    BlindValidationStatus,
    CallbackProtocol,
)
from saarthi_ai.persistence.blind_validation_workflow import (
    BlindValidationWorkflowError,
    run_tracked_blind_validation,
)
from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.models import (
    EvidenceType,
    ExecutionCreate,
    ExecutionState,
)
from saarthi_ai.persistence.oast_registry import (
    PersistentOastCorrelationRegistry,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "blind-validation.db")
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
            assessment_name="Phase 4B Blind Validation",
            asset_types=["web"],
            targets=[target],
            authorization_confirmed=authorized,
            active_testing_allowed=active_testing_allowed,
            intrusive_testing_allowed=False,
        )
    )
    return execution.execution_id


def make_request(
    execution_id: str,
    *,
    target_url: str = "https://example.com/",
    authorized: bool = True,
    active_testing: bool = True,
    explicitly_approved: bool = True,
) -> BlindValidationRequest:
    return BlindValidationRequest(
        execution_id=execution_id,
        target_url=target_url,
        authorized=authorized,
        active_testing=active_testing,
        explicitly_approved=explicitly_approved,
        callback_protocol=CallbackProtocol.HTTPS,
        requested_poll_attempts=6,
        requested_poll_interval_seconds=10,
    )


def test_workflow_persists_hash_only_correlation_evidence(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    request = make_request(execution_id)

    result = run_tracked_blind_validation(
        database,
        request,
        evidence_root=tmp_path / "evidence",
    )

    assert result.execution.state is ExecutionState.COMPLETED
    assert result.status is BlindValidationStatus.WAITING
    assert (
        result.evidence.evidence_type
        is EvidenceType.BLIND_VALIDATION_RESULT
    )

    evidence_path = Path(result.evidence.path)
    evidence_bytes = evidence_path.read_bytes()
    evidence_text = evidence_bytes.decode("utf-8")
    payload = json.loads(evidence_bytes)

    assert (
        hashlib.sha256(evidence_bytes).hexdigest()
        == result.evidence.sha256
    )
    assert payload["phase"] == "4B"
    assert payload["correlation"]["token_id"] == result.token.token_id
    assert payload["correlation"]["token_hash"] == result.token.token_hash
    assert "token_value" not in payload["correlation"]

    assert result.token.token_value not in evidence_text
    assert result.token.token_value not in json.dumps(
        result.evidence.metadata
    )

    registry = PersistentOastCorrelationRegistry(database)
    registry.initialize()

    stored_correlation = registry.get_by_token_id(
        result.token.token_id
    )

    assert stored_correlation is not None
    assert stored_correlation.token_hash == result.token.token_hash
    assert stored_correlation.execution_id == execution_id

    with database.connect() as connection:
        registry_row = connection.execute(
            """
            SELECT *
            FROM oast_correlations
            WHERE token_id = ?
            """,
            (result.token.token_id,),
        ).fetchone()

    assert registry_row is not None
    assert result.token.token_value not in repr(dict(registry_row))

    events = database.list_audit_events(execution_id)
    serialized_events = json.dumps(
        [
            {
                "message": event.message,
                "details": event.details,
            }
            for event in events
        ]
    )

    assert result.token.token_value not in serialized_events
    assert any(
        event.event_type.value == "tool_completed"
        for event in events
    )
    assert any(
        event.event_type.value == "evidence_added"
        for event in events
    )


def test_target_must_match_execution_scope(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    request = make_request(
        execution_id,
        target_url="https://outside.test/",
    )

    with pytest.raises(
        InvalidStateTransitionError,
        match="not associated with this execution",
    ):
        run_tracked_blind_validation(
            database,
            request,
            evidence_root=tmp_path,
        )

    assert (
        database.get_execution(execution_id).state
        is ExecutionState.CREATED
    )


def test_active_testing_permission_is_enforced(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(
        database,
        active_testing_allowed=False,
    )
    request = make_request(execution_id)

    with pytest.raises(
        InvalidStateTransitionError,
        match="does not allow active testing",
    ):
        run_tracked_blind_validation(
            database,
            request,
            evidence_root=tmp_path,
        )


def test_policy_denial_does_not_create_evidence(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    request = make_request(
        execution_id,
        explicitly_approved=False,
    )

    with pytest.raises(
        BlindValidationWorkflowError,
        match="requires explicit operator approval",
    ):
        run_tracked_blind_validation(
            database,
            request,
            evidence_root=tmp_path,
        )

    assert database.list_evidence(execution_id) == []
    assert (
        database.get_execution(execution_id).state
        is ExecutionState.CREATED
    )
