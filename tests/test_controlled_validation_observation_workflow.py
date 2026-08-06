"""Tracked Phase 6C low-risk validation observation tests."""

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
    ControlledValidationObservationWorkflowError,
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
            assessment_name="Phase 6C Controlled Observation",
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
    *,
    action: ControlledValidationAction = (
        ControlledValidationAction.RESPONSE_DIFFERENTIAL
    ),
    target_url: str = "https://example.com/account",
) -> ControlledValidationExecutionRequest:
    validation = ControlledValidationRequest(
        execution_id=execution_id,
        target_url=target_url,
        action=action,
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
async def test_parameter_surface_validator_preserves_approved_target(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    target_url = "https://example.com/search?id=1&id=2"
    request = make_request(
        execution_id,
        action=(
            ControlledValidationAction
            .HTTP_PARAMETER_SURFACE_VALIDATION
        ),
        target_url=target_url,
    )
    create_tracked_controlled_validation_plan(
        database,
        request.validation,
        evidence_root=tmp_path / "plans",
    )
    requested_urls: list[str] = []

    def handler(request_object: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request_object.url))
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            request=request_object,
        )

    result = await run_tracked_controlled_validation_observation(
        database,
        request,
        transport=httpx.MockTransport(handler),
        evidence_root=tmp_path / "observations",
    )

    assert requested_urls == [target_url]
    assert result.validator_analysis is not None
    assert (
        result.validator_analysis.validator_id
        == "6C.3-http-parameter-surface-validation"
    )
    assert (
        result.validator_analysis.classification.value
        == "ambiguous_surface_observed"
    )
    assert result.validator_analysis.duplicate_parameter_names == (
        "id",
    )
    assert result.validator_analysis.target_unchanged is True
    assert result.validator_analysis.parameters_mutated is False
    assert result.validator_analysis.parser_attack_sent is False
    assert result.validator_analysis.payload_generated is False

    payload = json.loads(Path(result.evidence.path).read_text())
    analysis = payload["validator_analysis"]
    assert analysis["target_unchanged"] is True
    assert analysis["parameters_mutated"] is False
    assert analysis["parser_attack_sent"] is False
    assert analysis["payload_generated"] is False
    assert analysis["duplicate_parameter_names"] == ["id"]

    metadata = result.evidence.metadata
    assert metadata["target_url"] == target_url
    assert metadata["target_unchanged"] is True
    assert metadata["parameters_mutated"] is False
    assert metadata["parser_attack_sent"] is False


@pytest.mark.asyncio
async def test_parameter_surface_reuse_sends_no_second_request(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    request = make_request(
        execution_id,
        action=(
            ControlledValidationAction
            .HTTP_PARAMETER_SURFACE_VALIDATION
        ),
        target_url="https://example.com/search?q=saarthi",
    )
    create_tracked_controlled_validation_plan(
        database,
        request.validation,
        evidence_root=tmp_path / "plans",
    )
    request_count = 0

    def handler(request_object: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(200, request=request_object)

    transport = httpx.MockTransport(handler)
    first = await run_tracked_controlled_validation_observation(
        database,
        request,
        transport=transport,
        evidence_root=tmp_path / "observations",
    )
    second = await run_tracked_controlled_validation_observation(
        database,
        request,
        transport=transport,
        evidence_root=tmp_path / "observations",
    )

    assert request_count == 1
    assert first.validator_analysis is not None
    assert second.validator_analysis is not None
    assert (
        second.validator_analysis.classification.value
        == "no_ambiguity_observed"
    )
    assert second.reused_existing_evidence is True


@pytest.mark.asyncio
async def test_session_cookie_validator_persists_no_cookie_secrets(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    request = make_request(
        execution_id,
        action=(
            ControlledValidationAction
            .SESSION_COOKIE_ATTRIBUTE_VALIDATION
        ),
    )
    create_tracked_controlled_validation_plan(
        database,
        request.validation,
        evidence_root=tmp_path / "plans",
    )
    secret = "sensitive-cookie-value-never-store"
    captured_requests: list[httpx.Request] = []

    def handler(request_object: httpx.Request) -> httpx.Response:
        captured_requests.append(request_object)
        return httpx.Response(
            200,
            headers=[
                (
                    "Set-Cookie",
                    "session="
                    f"{secret}; Secure; HttpOnly; "
                    "SameSite=Lax; Path=/",
                ),
                (
                    "Set-Cookie",
                    "preferences=also-secret; SameSite=Lax",
                ),
            ],
            request=request_object,
        )

    result = await run_tracked_controlled_validation_observation(
        database,
        request,
        transport=httpx.MockTransport(handler),
        evidence_root=tmp_path / "observations",
    )

    assert len(captured_requests) == 1
    assert "cookie" not in captured_requests[0].headers
    assert result.validator_analysis is not None
    assert (
        result.validator_analysis.validator_id
        == "6C.4-session-cookie-attribute-validation"
    )
    assert result.validator_analysis.cookie_count == 2
    assert result.validator_analysis.cookies_with_issues == 1
    assert result.validator_analysis.cookie_values_discarded is True
    assert result.validator_analysis.raw_set_cookie_stored is False
    assert result.validator_analysis.cookie_replayed is False
    assert result.validator_analysis.credential_header_sent is False

    evidence_text = Path(result.evidence.path).read_text()
    assert secret not in evidence_text
    assert "also-secret" not in evidence_text
    assert '"session"' not in evidence_text
    assert '"preferences"' not in evidence_text

    payload = json.loads(evidence_text)
    analysis = payload["validator_analysis"]
    assert analysis["cookie_values_discarded"] is True
    assert analysis["raw_set_cookie_stored"] is False
    assert analysis["cookie_replayed"] is False
    assert analysis["credential_header_sent"] is False
    assert len(
        analysis["cookie_observations"][0][
            "cookie_name_sha256"
        ]
    ) == 64

    metadata_text = json.dumps(result.evidence.metadata)
    assert secret not in metadata_text
    assert "also-secret" not in metadata_text
    assert result.evidence.metadata["cookie_values_discarded"] is True
    assert result.evidence.metadata["raw_set_cookie_stored"] is False


@pytest.mark.asyncio
async def test_session_cookie_reuse_sends_no_second_request(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    request = make_request(
        execution_id,
        action=(
            ControlledValidationAction
            .SESSION_COOKIE_ATTRIBUTE_VALIDATION
        ),
    )
    create_tracked_controlled_validation_plan(
        database,
        request.validation,
        evidence_root=tmp_path / "plans",
    )
    request_count = 0

    def handler(request_object: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(200, request=request_object)

    transport = httpx.MockTransport(handler)
    first = await run_tracked_controlled_validation_observation(
        database,
        request,
        transport=transport,
        evidence_root=tmp_path / "observations",
    )
    second = await run_tracked_controlled_validation_observation(
        database,
        request,
        transport=transport,
        evidence_root=tmp_path / "observations",
    )

    assert request_count == 1
    assert first.validator_analysis is not None
    assert second.validator_analysis is not None
    assert (
        second.validator_analysis.classification.value
        == "no_cookies_observed"
    )
    assert second.reused_existing_evidence is True


@pytest.mark.asyncio
async def test_csrf_surface_persists_no_form_or_token_values(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    request = make_request(
        execution_id,
        action=(
            ControlledValidationAction
            .CSRF_PROTECTION_SURFACE_VALIDATION
        ),
    )
    create_tracked_controlled_validation_plan(
        database,
        request.validation,
        evidence_root=tmp_path / "plans",
    )
    secret = "csrf-token-value-never-persist"
    captured: list[httpx.Request] = []

    def handler(request_object: httpx.Request) -> httpx.Response:
        captured.append(request_object)
        return httpx.Response(
            200,
            headers={
                "Content-Type": "text/html",
                "Set-Cookie": (
                    "session=cookie-secret; Secure; HttpOnly; "
                    "SameSite=Lax"
                ),
            },
            content=(
                "<form method='post' action='/save'>"
                "<input type='hidden' name='csrf_token' "
                f"value='{secret}'>"
                "<input name='email' value='private@example.com'>"
                "</form>"
            ),
            request=request_object,
        )

    result = await run_tracked_controlled_validation_observation(
        database,
        request,
        transport=httpx.MockTransport(handler),
        evidence_root=tmp_path / "observations",
    )

    assert len(captured) == 1
    assert captured[0].method == "GET"
    assert captured[0].content == b""
    assert "cookie" not in captured[0].headers
    assert result.validator_analysis is not None
    assert (
        result.validator_analysis.validator_id
        == "6C.2-csrf-protection-surface-validation"
    )
    assert result.validator_analysis.post_form_count == 1
    assert result.validator_analysis.forms_with_token_signal == 1
    assert result.validator_analysis.form_submitted is False
    assert result.validator_analysis.browser_launched is False
    assert result.validator_analysis.request_body_sent is False

    evidence_text = Path(result.evidence.path).read_text()
    assert secret not in evidence_text
    assert "cookie-secret" not in evidence_text
    assert "private@example.com" not in evidence_text
    payload = json.loads(evidence_text)
    analysis = payload["validator_analysis"]
    assert analysis["token_values_discarded"] is True
    assert analysis["form_submitted"] is False
    assert analysis["browser_launched"] is False
    assert analysis["request_body_sent"] is False
    assert analysis["payload_generated"] is False
    assert "body" not in payload["response"]


@pytest.mark.asyncio
async def test_csrf_surface_reuse_sends_no_second_request(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    request = make_request(
        execution_id,
        action=(
            ControlledValidationAction
            .CSRF_PROTECTION_SURFACE_VALIDATION
        ),
    )
    create_tracked_controlled_validation_plan(
        database,
        request.validation,
        evidence_root=tmp_path / "plans",
    )
    request_count = 0

    def handler(request_object: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            content=b"<p>No forms</p>",
            request=request_object,
        )

    transport = httpx.MockTransport(handler)
    first = await run_tracked_controlled_validation_observation(
        database,
        request,
        transport=transport,
        evidence_root=tmp_path / "observations",
    )
    second = await run_tracked_controlled_validation_observation(
        database,
        request,
        transport=transport,
        evidence_root=tmp_path / "observations",
    )

    assert request_count == 1
    assert first.validator_analysis is not None
    assert second.validator_analysis is not None
    assert (
        second.validator_analysis.classification.value
        == "not_applicable"
    )
    assert second.reused_existing_evidence is True


@pytest.mark.asyncio
async def test_clickjacking_validator_persists_header_only_analysis(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    request = make_request(
        execution_id,
        action=(
            ControlledValidationAction
            .CLICKJACKING_HEADER_VALIDATION
        ),
    )
    create_tracked_controlled_validation_plan(
        database,
        request.validation,
        evidence_root=tmp_path / "plans",
    )
    request_count = 0

    def handler(request_object: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(
            200,
            headers={
                "Content-Type": "text/html",
                "Content-Security-Policy": (
                    "default-src 'self'; frame-ancestors 'none'"
                ),
            },
            content=b"<html>not persisted</html>",
            request=request_object,
        )

    result = await run_tracked_controlled_validation_observation(
        database,
        request,
        transport=httpx.MockTransport(handler),
        evidence_root=tmp_path / "observations",
    )

    assert request_count == 1
    assert result.validator_analysis is not None
    assert (
        result.validator_analysis.classification.value
        == "protected"
    )
    assert result.validator_analysis.header_only is True
    assert result.validator_analysis.exploit_page_generated is False
    assert result.validator_analysis.browser_launched is False
    assert result.validator_analysis.payload_generated is False

    payload = json.loads(Path(result.evidence.path).read_text())
    analysis = payload["validator_analysis"]
    assert (
        analysis["validator_id"]
        == "6C.2-clickjacking-header-validation"
    )
    assert analysis["classification"] == "protected"
    assert analysis["header_only"] is True
    assert analysis["exploit_page_generated"] is False
    assert analysis["browser_launched"] is False
    assert analysis["payload_generated"] is False
    assert "body" not in payload["response"]

    metadata = result.evidence.metadata
    assert (
        metadata["validator_id"]
        == "6C.2-clickjacking-header-validation"
    )
    assert metadata["validator_classification"] == "protected"
    assert metadata["header_only"] is True
    assert metadata["exploit_page_generated"] is False
    assert metadata["browser_launched"] is False
    assert metadata["payload_generated"] is False


@pytest.mark.asyncio
async def test_clickjacking_reuse_sends_no_second_request(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    request = make_request(
        execution_id,
        action=(
            ControlledValidationAction
            .CLICKJACKING_HEADER_VALIDATION
        ),
    )
    create_tracked_controlled_validation_plan(
        database,
        request.validation,
        evidence_root=tmp_path / "plans",
    )
    request_count = 0

    def handler(request_object: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            request=request_object,
        )

    transport = httpx.MockTransport(handler)
    first = await run_tracked_controlled_validation_observation(
        database,
        request,
        transport=transport,
        evidence_root=tmp_path / "observations",
    )
    second = await run_tracked_controlled_validation_observation(
        database,
        request,
        transport=transport,
        evidence_root=tmp_path / "observations",
    )

    assert request_count == 1
    assert first.validator_analysis is not None
    assert second.validator_analysis is not None
    assert (
        second.validator_analysis.classification.value
        == "potentially_exposed"
    )
    assert second.reused_existing_evidence is True


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
    assert result.reused_existing_evidence is False
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
    assert payload["phase"] == "6C"
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


@pytest.mark.asyncio
async def test_network_failure_moves_execution_to_failed(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    request = make_request(execution_id)

    create_tracked_controlled_validation_plan(
        database,
        request.validation,
        evidence_root=tmp_path / "plans",
    )

    request_count = 0

    def handler(request_object: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        raise httpx.ConnectError(
            "simulated connection failure",
            request=request_object,
        )

    with pytest.raises(
        Exception,
        match="simulated connection failure",
    ):
        await run_tracked_controlled_validation_observation(
            database,
            request,
            transport=httpx.MockTransport(handler),
            evidence_root=tmp_path / "observations",
        )

    assert request_count == 1
    assert (
        database.get_execution(execution_id).state
        is ExecutionState.FAILED
    )
    assert database.list_evidence(
        execution_id,
        evidence_type=(
            EvidenceType.CONTROLLED_VALIDATION_OBSERVATION
        ),
    ) == []

    failure_events = [
        event
        for event in database.list_audit_events(execution_id)
        if event.event_type is AuditEventType.TOOL_FAILED
    ]

    assert len(failure_events) == 1
    assert failure_events[0].details["request_attempted"] is True
    assert failure_events[0].details["retry_allowed"] is False
    assert (
        failure_events[0].details["requires_new_execution"]
        is True
    )


@pytest.mark.asyncio
async def test_evidence_write_failure_is_fail_closed(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import saarthi_ai.persistence.controlled_validation_observation_workflow as workflow

    execution_id = create_execution(database)
    request = make_request(execution_id)

    create_tracked_controlled_validation_plan(
        database,
        request.validation,
        evidence_root=tmp_path / "plans",
    )

    def fail_write(*args: object, **kwargs: object) -> object:
        raise OSError("simulated observation evidence write failure")

    monkeypatch.setattr(
        workflow,
        "_write_evidence_atomically",
        fail_write,
    )

    def handler(request_object: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"bounded result",
            request=request_object,
        )

    with pytest.raises(
        workflow.ControlledValidationObservationWorkflowError,
        match="failed safely",
    ):
        await workflow.run_tracked_controlled_validation_observation(
            database,
            request,
            transport=httpx.MockTransport(handler),
            evidence_root=tmp_path / "observations",
        )

    assert (
        database.get_execution(execution_id).state
        is ExecutionState.FAILED
    )
    assert database.list_evidence(
        execution_id,
        evidence_type=(
            EvidenceType.CONTROLLED_VALIDATION_OBSERVATION
        ),
    ) == []


@pytest.mark.asyncio
async def test_registration_failure_removes_orphan_json(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_id = create_execution(database)
    request = make_request(execution_id)
    evidence_root = tmp_path / "observations"

    create_tracked_controlled_validation_plan(
        database,
        request.validation,
        evidence_root=tmp_path / "plans",
    )

    original_add_evidence = database.add_evidence

    def fail_observation_registration(
        execution_id_value: str,
        evidence_request: object,
        *,
        actor: str = "system",
    ) -> object:
        if (
            getattr(evidence_request, "evidence_type", None)
            is EvidenceType.CONTROLLED_VALIDATION_OBSERVATION
        ):
            raise RuntimeError(
                "simulated observation registration failure"
            )

        return original_add_evidence(
            execution_id_value,
            evidence_request,  # type: ignore[arg-type]
            actor=actor,
        )

    monkeypatch.setattr(
        database,
        "add_evidence",
        fail_observation_registration,
    )

    def handler(request_object: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"bounded result",
            request=request_object,
        )

    with pytest.raises(
        ControlledValidationObservationWorkflowError,
        match="failed safely",
    ):
        await run_tracked_controlled_validation_observation(
            database,
            request,
            transport=httpx.MockTransport(handler),
            evidence_root=evidence_root,
        )

    assert list(evidence_root.glob("*.json")) == []
    assert (
        database.get_execution(execution_id).state
        is ExecutionState.FAILED
    )

    failure_events = [
        event
        for event in database.list_audit_events(execution_id)
        if event.event_type is AuditEventType.TOOL_FAILED
    ]

    assert len(failure_events) == 1
    assert (
        failure_events[0].details["orphan_file_removed"]
        is True
    )
    assert (
        failure_events[0].details["evidence_registered"]
        is False
    )


@pytest.mark.asyncio
async def test_completed_observation_is_reused_without_second_request(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    request = make_request(execution_id)

    create_tracked_controlled_validation_plan(
        database,
        request.validation,
        evidence_root=tmp_path / "plans",
    )

    request_count = 0

    def handler(request_object: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(
            200,
            content=b"idempotent result",
            request=request_object,
        )

    transport = httpx.MockTransport(handler)

    first = await run_tracked_controlled_validation_observation(
        database,
        request,
        transport=transport,
        evidence_root=tmp_path / "observations",
    )

    second = await run_tracked_controlled_validation_observation(
        database,
        request,
        transport=transport,
        evidence_root=tmp_path / "observations",
    )

    assert request_count == 1
    assert first.evidence.evidence_id == second.evidence.evidence_id
    assert second.reused_existing_evidence is True
    assert second.observation.succeeded is True

    evidence_items = database.list_evidence(
        execution_id,
        evidence_type=(
            EvidenceType.CONTROLLED_VALIDATION_OBSERVATION
        ),
    )

    assert len(evidence_items) == 1

    reuse_events = [
        event
        for event in database.list_audit_events(execution_id)
        if event.details.get("idempotent_reuse") is True
    ]

    assert len(reuse_events) == 1
    assert reuse_events[0].details["second_request_sent"] is False
