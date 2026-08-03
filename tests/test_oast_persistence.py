from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from saarthi_ai.blind_validation.tokens import generate_correlation_token
from saarthi_ai.oast.models import (
    OastCorrelation,
    OastCorrelationStatus,
    OastObservation,
    OastProtocol,
)
from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.models import (
    EvidenceType,
    ExecutionCreate,
)
from saarthi_ai.persistence.oast_workflow import (
    OastObservationWorkflowError,
    persist_oast_observation,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "oast.db")
    repository.initialize()
    return repository


def create_execution(
    database: SaarthiDatabase,
    *,
    authorized: bool = True,
    active_testing_allowed: bool = True,
) -> str:
    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Phase 4C OAST Observation",
            asset_types=["web"],
            targets=["example.com"],
            authorization_confirmed=authorized,
            active_testing_allowed=active_testing_allowed,
            intrusive_testing_allowed=False,
        )
    )

    return execution.execution_id


def build_observation(
    execution_id: str,
) -> tuple[OastObservation, OastCorrelation, str]:
    now = datetime.now(UTC)
    token = generate_correlation_token(
        ttl_seconds=300,
        now=now,
    )

    correlation = OastCorrelation(
        token_id=token.token_id,
        token_hash=token.token_hash,
        execution_id=execution_id,
        protocol=OastProtocol.HTTP,
        created_at=token.created_at,
        expires_at=token.expires_at,
        status=OastCorrelationStatus.OBSERVED,
    )

    observation = OastObservation(
        observation_id="oast-observation-test",
        token_id=token.token_id,
        execution_id=execution_id,
        protocol=OastProtocol.HTTP,
        observed_at=now + timedelta(seconds=5),
        request_method="POST",
        request_path="/v1/oast/callback/[REDACTED]",
        source_address="127.0.0.1",
        selected_headers={
            "user-agent": "Saarthi persistence test",
        },
        body_size=14,
    )

    return observation, correlation, token.token_value


def test_observation_is_persisted_without_raw_token(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    observation, correlation, raw_token = build_observation(
        execution_id
    )

    evidence = persist_oast_observation(
        database,
        observation,
        correlation,
        evidence_root=tmp_path / "evidence",
    )

    assert evidence.evidence_type is EvidenceType.OAST_OBSERVATION

    evidence_path = Path(evidence.path)
    evidence_bytes = evidence_path.read_bytes()
    evidence_text = evidence_bytes.decode("utf-8")
    payload = json.loads(evidence_bytes)

    assert (
        hashlib.sha256(evidence_bytes).hexdigest()
        == evidence.sha256
    )
    assert payload["phase"] == "4C"
    assert payload["correlation"]["token_id"] == correlation.token_id
    assert payload["correlation"]["token_hash"] == correlation.token_hash
    assert payload["observation"]["request_path"] == (
        "/v1/oast/callback/[REDACTED]"
    )

    assert raw_token not in evidence_text
    assert raw_token not in json.dumps(evidence.metadata)

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

    assert raw_token not in serialized_events
    assert any(
        event.event_type.value == "tool_completed"
        for event in events
    )
    assert any(
        event.event_type.value == "evidence_added"
        for event in events
    )


def test_unredacted_callback_path_is_rejected(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    observation, correlation, raw_token = build_observation(
        execution_id
    )

    unsafe_observation = OastObservation(
        observation_id=observation.observation_id,
        token_id=observation.token_id,
        execution_id=observation.execution_id,
        protocol=observation.protocol,
        observed_at=observation.observed_at,
        request_method=observation.request_method,
        request_path=f"/v1/oast/callback/{raw_token}",
        source_address=observation.source_address,
        selected_headers=observation.selected_headers,
        body_size=observation.body_size,
    )

    with pytest.raises(
        OastObservationWorkflowError,
        match="redacted callback token",
    ):
        persist_oast_observation(
            database,
            unsafe_observation,
            correlation,
            evidence_root=tmp_path,
        )

    assert database.list_evidence(execution_id) == []


def test_active_testing_permission_is_required(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(
        database,
        active_testing_allowed=False,
    )
    observation, correlation, _ = build_observation(execution_id)

    with pytest.raises(
        InvalidStateTransitionError,
        match="does not allow active testing",
    ):
        persist_oast_observation(
            database,
            observation,
            correlation,
            evidence_root=tmp_path,
        )


def test_observation_and_correlation_must_match(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    observation, correlation, _ = build_observation(execution_id)

    mismatched = OastCorrelation(
        token_id="blind-token-different",
        token_hash=correlation.token_hash,
        execution_id=correlation.execution_id,
        protocol=correlation.protocol,
        created_at=correlation.created_at,
        expires_at=correlation.expires_at,
        status=correlation.status,
    )

    with pytest.raises(
        OastObservationWorkflowError,
        match="token ID does not match",
    ):
        persist_oast_observation(
            database,
            observation,
            mismatched,
            evidence_root=tmp_path,
        )
