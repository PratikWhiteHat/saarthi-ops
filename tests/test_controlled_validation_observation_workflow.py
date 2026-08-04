"""Tracked Phase 6F controlled-validation observation tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx
import pytest

from saarthi_ai.controlled_validation.executor import (
    ControlledValidationExecutionRequest,
)
from saarthi_ai.controlled_validation.models import (
    ControlledValidationAction,
    ControlledValidationRequest,
)
from saarthi_ai.persistence.controlled_validation_observation_workflow import (
    run_tracked_controlled_validation_observation,
)
from saarthi_ai.persistence.controlled_validation_workflow import (
    create_tracked_controlled_validation_plan,
)
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceType,
    ExecutionCreate,
    ExecutionState,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(
        tmp_path / "controlled-observation.db"
    )
    repository.initialize()
    return repository


def create_execution(database: SaarthiDatabase) -> str:
    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Phase 6F Controlled Observation",
            asset_types=["web"],
            targets=["example.com"],
            authorization_confirmed=True,
            active_testing_allowed=True,
            intrusive_testing_allowed=False,
        )
    )
    return execution.execution_id


def make_request(
    execution_id: str,
) -> ControlledValidationExecutionRequest:
    validation = ControlledValidationRequest(
        execution_id=execution_id,
        target_url="https://example.com/account",
        action=ControlledValidationAction.RESPONSE_DIFFERENTIAL,
        authorized=True,
        active_testing=True,
        intrusive_testing=False,
        explicitly_approved=True,
        reversible=True,
        requested_requests=1,
    )

    return ControlledValidationExecutionRequest(
        validation=validation,
        method="GET",
        max_response_bytes=1_024,
        follow_redirects=False,
    )


@pytest.mark.asyncio
async def test_tracked_observation_persists_one_mocked_result(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    request = make_request(execution_id)

    plan = create_tracked_controlled_validation_plan(
        database,
        request.validation,
        evidence_root=tmp_path / "plans",
    )

    captured_requests: list[httpx.Request] = []

    def handler(request_object: httpx.Request) -> httpx.Response:
        captured_requests.append(request_object)
        return httpx.Response(
            200,
            headers={
                "Content-Type": "text/plain",
                "Set-Cookie": "session=secret",
            },
            content=b"controlled observation",
            request=request_object,
        )

    result = await run_tracked_controlled_validation_observation(
        database,
        request,
        transport=httpx.MockTransport(handler),
        evidence_root=tmp_path / "observations",
    )

    assert len(captured_requests) == 1
    assert result.execution.state is ExecutionState.COMPLETED
    assert result.observation.succeeded is True
    assert result.observation.status_code == 200
    assert (
        result.evidence.evidence_type
        is EvidenceType.CONTROLLED_VALIDATION_OBSERVATION
    )

    evidence_path = Path(result.evidence.path)
    evidence_bytes = evidence_path.read_bytes()
    payload = json.loads(evidence_bytes)

    assert (
        hashlib.sha256(evidence_bytes).hexdigest()
        == result.evidence.sha256
    )
    assert payload["phase"] == "6F3B"
    assert payload["plan"]["evidence_id"] == plan.evidence.evidence_id
    assert payload["response"]["status_code"] == 200
    assert (
        payload["response"]["headers"]["set-cookie"]
        == "<redacted>"
    )
    assert "body" not in payload["response"]
    assert payload["response"]["body_bytes_captured"] == len(
        b"controlled observation"
    )
    assert len(payload["response"]["body_sha256"]) == 64
    assert payload["execution"]["subprocess_started"] is False
    assert payload["execution"]["payload_sent"] is False

    observation_items = database.list_evidence(
        execution_id,
        evidence_type=(
            EvidenceType.CONTROLLED_VALIDATION_OBSERVATION
        ),
    )

    assert len(observation_items) == 1

    events = database.list_audit_events(execution_id)
    event_types = [event.event_type for event in events]

    assert AuditEventType.TOOL_STARTED in event_types
    assert AuditEventType.TOOL_OUTPUT in event_types
    assert AuditEventType.TOOL_COMPLETED in event_types

    state_changes = [
        event.details.get("new_state")
        for event in events
        if event.event_type is AuditEventType.STATE_CHANGED
    ]

    assert ExecutionState.RUNNING.value in state_changes
    assert ExecutionState.ANALYZING.value in state_changes
    assert ExecutionState.COMPLETED.value in state_changes
