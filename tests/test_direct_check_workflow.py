from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from saarthi_ai.checks.executor import DirectCheckExecutionResult
from saarthi_ai.checks.models import (
    CheckDecision,
    DirectCheckRequest,
    PolicyResult,
)
from saarthi_ai.checks.security_headers import SecurityHeadersResult
from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.direct_check_workflow import (
    DirectCheckWorkflowError,
    run_tracked_direct_check,
)
from saarthi_ai.persistence.models import (
    EvidenceType,
    ExecutionCreate,
    ExecutionState,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "direct-check.db")
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
            assessment_name="Phase 4A Direct Check",
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
    active_testing: bool = False,
) -> DirectCheckRequest:
    return DirectCheckRequest(
        execution_id=execution_id,
        target_url=target_url,
        check_id="security-headers",
        authorized=authorized,
        active_testing=active_testing,
        requested_method="GET",
        requested_requests=1,
    )


def successful_check(
    request: DirectCheckRequest,
) -> DirectCheckExecutionResult:
    return DirectCheckExecutionResult(
        check_id=request.check_id,
        target_url=request.target_url,
        policy=PolicyResult(
            decision=CheckDecision.ALLOW,
            reason="Allowed by test policy.",
        ),
        executed=True,
        result=SecurityHeadersResult(
            target_url=request.target_url,
            status_code=200,
            present_headers=("content-security-policy",),
            missing_headers=("strict-transport-security",),
            response_headers={
                "content-security-policy": "default-src 'self'",
            },
        ),
    )


def test_direct_check_completes_and_registers_evidence(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from saarthi_ai.persistence import direct_check_workflow

    execution_id = create_execution(database)
    request = make_request(execution_id)

    async def fake_execute(
        supplied_request: DirectCheckRequest,
    ) -> DirectCheckExecutionResult:
        return successful_check(supplied_request)

    monkeypatch.setattr(
        direct_check_workflow,
        "execute_direct_check",
        fake_execute,
    )

    result = run_tracked_direct_check(
        database,
        request,
        evidence_root=tmp_path / "evidence",
    )

    assert result.execution.state is ExecutionState.COMPLETED
    assert result.check.executed is True
    assert result.evidence.evidence_type is EvidenceType.DIRECT_CHECK_RESULT
    assert result.evidence.tool_name == "saarthi-direct-check"

    evidence_path = Path(result.evidence.path)
    assert evidence_path.exists()

    evidence_bytes = evidence_path.read_bytes()
    assert hashlib.sha256(evidence_bytes).hexdigest() == result.evidence.sha256

    payload = json.loads(evidence_bytes)
    assert payload["phase"] == "4A"
    assert payload["request"]["check_id"] == "security-headers"
    assert payload["policy"]["decision"] == "allow"
    assert payload["result"]["status_code"] == 200

    evidence = database.list_evidence(execution_id)
    assert len(evidence) == 1

    events = database.list_audit_events(execution_id)
    event_types = [event.event_type.value for event in events]

    assert "tool_started" in event_types
    assert "tool_completed" in event_types
    assert "evidence_added" in event_types


def test_direct_check_target_must_match_execution_scope(
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
        run_tracked_direct_check(
            database,
            request,
            evidence_root=tmp_path,
        )

    execution = database.get_execution(execution_id)
    assert execution.state is ExecutionState.CREATED


def test_direct_check_request_must_confirm_authorization(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)

    request = make_request(
        execution_id,
        authorized=False,
    )

    with pytest.raises(
        InvalidStateTransitionError,
        match="does not confirm authorization",
    ):
        run_tracked_direct_check(
            database,
            request,
            evidence_root=tmp_path,
        )

    execution = database.get_execution(execution_id)
    assert execution.state is ExecutionState.CREATED


def test_direct_check_requires_active_permission_when_requested(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(
        database,
        active_testing_allowed=False,
    )

    request = make_request(
        execution_id,
        active_testing=True,
    )

    with pytest.raises(
        InvalidStateTransitionError,
        match="does not allow active testing",
    ):
        run_tracked_direct_check(
            database,
            request,
            evidence_root=tmp_path,
        )


def test_policy_denial_fails_execution(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from saarthi_ai.persistence import direct_check_workflow

    execution_id = create_execution(database)
    request = make_request(execution_id)

    async def fake_execute(
        supplied_request: DirectCheckRequest,
    ) -> DirectCheckExecutionResult:
        return DirectCheckExecutionResult(
            check_id=supplied_request.check_id,
            target_url=supplied_request.target_url,
            policy=PolicyResult(
                decision=CheckDecision.DENY,
                reason="Denied by test policy.",
            ),
            executed=False,
        )

    monkeypatch.setattr(
        direct_check_workflow,
        "execute_direct_check",
        fake_execute,
    )

    with pytest.raises(
        DirectCheckWorkflowError,
        match="Denied by test policy",
    ):
        run_tracked_direct_check(
            database,
            request,
            evidence_root=tmp_path,
        )

    execution = database.get_execution(execution_id)
    assert execution.state is ExecutionState.FAILED

    events = database.list_audit_events(execution_id)
    assert any(
        event.event_type.value == "tool_failed"
        for event in events
    )


def test_failed_check_does_not_register_evidence(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from saarthi_ai.persistence import direct_check_workflow

    execution_id = create_execution(database)
    request = make_request(execution_id)

    async def fake_execute(
        supplied_request: DirectCheckRequest,
    ) -> DirectCheckExecutionResult:
        return DirectCheckExecutionResult(
            check_id=supplied_request.check_id,
            target_url=supplied_request.target_url,
            policy=PolicyResult(
                decision=CheckDecision.ALLOW,
                reason="Allowed by test policy.",
            ),
            executed=False,
            error="Adapter failure.",
        )

    monkeypatch.setattr(
        direct_check_workflow,
        "execute_direct_check",
        fake_execute,
    )

    with pytest.raises(
        DirectCheckWorkflowError,
        match="Adapter failure",
    ):
        run_tracked_direct_check(
            database,
            request,
            evidence_root=tmp_path,
        )

    assert database.list_evidence(execution_id) == []
