"""Tests for the non-network Phase 6C validator contract."""

from __future__ import annotations

import pytest

from saarthi_ai.controlled_validation.executor import (
    MAX_RESPONSE_BYTES,
    ControlledValidationExecutionDecision,
    ControlledValidationExecutionRequest,
    evaluate_controlled_validation_execution,
)
from saarthi_ai.controlled_validation.models import (
    ControlledValidationAction,
    ControlledValidationRequest,
)


def make_validation(
    **overrides: object,
) -> ControlledValidationRequest:
    values: dict[str, object] = {
        "execution_id": "execution-phase-6c",
        "target_url": "https://example.com/search?q=saarthi",
        "action": ControlledValidationAction.RESPONSE_DIFFERENTIAL,
        "authorized": True,
        "active_testing": True,
        "intrusive_testing": False,
        "explicitly_approved": True,
        "reversible": True,
        "requested_requests": 2,
    }
    values.update(overrides)
    return ControlledValidationRequest(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize("method", ["GET", "HEAD", "get", " head "])
def test_get_and_head_are_allowed(method: str) -> None:
    result = evaluate_controlled_validation_execution(
        ControlledValidationExecutionRequest(
            validation=make_validation(),
            method=method,
        )
    )

    assert result.decision is ControlledValidationExecutionDecision.ALLOW
    assert result.allowed is True


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_state_capable_methods_are_denied(method: str) -> None:
    result = evaluate_controlled_validation_execution(
        ControlledValidationExecutionRequest(
            validation=make_validation(),
            method=method,
        )
    )

    assert result.decision is ControlledValidationExecutionDecision.DENY
    assert "Only GET and HEAD" in result.reason


def test_only_low_risk_actions_are_executable() -> None:
    result = evaluate_controlled_validation_execution(
        ControlledValidationExecutionRequest(
            validation=make_validation(
                action=ControlledValidationAction.AUTHORIZATION_BOUNDARY,
                intrusive_testing=True,
            )
        )
    )

    assert result.decision is ControlledValidationExecutionDecision.DENY


def test_input_handling_observation_is_allowed() -> None:
    result = evaluate_controlled_validation_execution(
        ControlledValidationExecutionRequest(
            validation=make_validation(
                action=(
                    ControlledValidationAction
                    .INPUT_HANDLING_OBSERVATION
                )
            )
        )
    )

    assert result.decision is ControlledValidationExecutionDecision.ALLOW


def test_clickjacking_header_validation_is_executable() -> None:
    result = evaluate_controlled_validation_execution(
        ControlledValidationExecutionRequest(
            validation=make_validation(
                action=(
                    ControlledValidationAction
                    .CLICKJACKING_HEADER_VALIDATION
                )
            ),
            method="HEAD",
        )
    )

    assert result.decision is ControlledValidationExecutionDecision.ALLOW
    assert result.request_budget == 2


def test_parameter_surface_validation_is_executable() -> None:
    result = evaluate_controlled_validation_execution(
        ControlledValidationExecutionRequest(
            validation=make_validation(
                action=(
                    ControlledValidationAction
                    .HTTP_PARAMETER_SURFACE_VALIDATION
                )
            ),
        )
    )

    assert result.decision is ControlledValidationExecutionDecision.ALLOW


def test_session_cookie_validation_requires_get() -> None:
    get_result = evaluate_controlled_validation_execution(
        ControlledValidationExecutionRequest(
            validation=make_validation(
                action=(
                    ControlledValidationAction
                    .SESSION_COOKIE_ATTRIBUTE_VALIDATION
                )
            ),
            method="GET",
        )
    )
    head_result = evaluate_controlled_validation_execution(
        ControlledValidationExecutionRequest(
            validation=make_validation(
                action=(
                    ControlledValidationAction
                    .SESSION_COOKIE_ATTRIBUTE_VALIDATION
                )
            ),
            method="HEAD",
        )
    )

    assert (
        get_result.decision
        is ControlledValidationExecutionDecision.ALLOW
    )
    assert (
        head_result.decision
        is ControlledValidationExecutionDecision.DENY
    )
    assert "requires exactly one GET" in head_result.reason


def test_request_budget_is_limited_to_five() -> None:
    result = evaluate_controlled_validation_execution(
        ControlledValidationExecutionRequest(
            validation=make_validation(requested_requests=6)
        )
    )

    assert result.decision is ControlledValidationExecutionDecision.DENY


def test_redirect_following_is_denied() -> None:
    result = evaluate_controlled_validation_execution(
        ControlledValidationExecutionRequest(
            validation=make_validation(),
            follow_redirects=True,
        )
    )

    assert result.decision is ControlledValidationExecutionDecision.DENY
    assert "Redirect following is disabled" in result.reason


def test_request_body_is_denied() -> None:
    result = evaluate_controlled_validation_execution(
        ControlledValidationExecutionRequest(
            validation=make_validation(),
            body=b"state=changed",
        )
    )

    assert result.decision is ControlledValidationExecutionDecision.DENY


@pytest.mark.parametrize(
    "header_name",
    [
        "Authorization",
        "Cookie",
        "Proxy-Authorization",
        "X-API-Key",
        "X-Auth-Token",
    ],
)
def test_credential_headers_are_denied(header_name: str) -> None:
    result = evaluate_controlled_validation_execution(
        ControlledValidationExecutionRequest(
            validation=make_validation(),
            headers=((header_name, "redacted"),),
        )
    )

    assert result.decision is ControlledValidationExecutionDecision.DENY
    assert "Credential-bearing headers" in result.reason


def test_credential_free_observation_header_is_allowed() -> None:
    result = evaluate_controlled_validation_execution(
        ControlledValidationExecutionRequest(
            validation=make_validation(),
            headers=(("Accept", "text/html"),),
        )
    )

    assert result.decision is ControlledValidationExecutionDecision.ALLOW


@pytest.mark.parametrize("timeout", [0, -1, 10.1, 60])
def test_invalid_timeout_is_denied(timeout: float) -> None:
    result = evaluate_controlled_validation_execution(
        ControlledValidationExecutionRequest(
            validation=make_validation(),
            timeout_seconds=timeout,
        )
    )

    assert result.decision is ControlledValidationExecutionDecision.DENY


@pytest.mark.parametrize(
    "capture_limit",
    [0, -1, MAX_RESPONSE_BYTES + 1],
)
def test_invalid_response_capture_limit_is_denied(
    capture_limit: int,
) -> None:
    result = evaluate_controlled_validation_execution(
        ControlledValidationExecutionRequest(
            validation=make_validation(),
            max_response_bytes=capture_limit,
        )
    )

    assert result.decision is ControlledValidationExecutionDecision.DENY


@pytest.mark.parametrize(
    "target_url",
    [
        "ftp://example.com/",
        "https://user:secret@example.com/",
        "/relative/path",
        "not-a-url",
    ],
)
def test_invalid_or_credential_bearing_target_is_denied(
    target_url: str,
) -> None:
    result = evaluate_controlled_validation_execution(
        ControlledValidationExecutionRequest(
            validation=make_validation(target_url=target_url)
        )
    )

    assert result.decision is ControlledValidationExecutionDecision.DENY


def test_missing_fresh_approval_is_denied() -> None:
    result = evaluate_controlled_validation_execution(
        ControlledValidationExecutionRequest(
            validation=make_validation(explicitly_approved=False)
        )
    )

    assert result.decision is ControlledValidationExecutionDecision.DENY


def test_contract_does_not_report_execution() -> None:
    result = evaluate_controlled_validation_execution(
        ControlledValidationExecutionRequest(
            validation=make_validation()
        )
    )

    assert result.allowed is True
    assert "No request has been executed" in result.reason
