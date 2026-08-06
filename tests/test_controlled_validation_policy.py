"""Tests for the Phase 6B policy and approval gate."""

from __future__ import annotations

import pytest

from saarthi_ai.controlled_validation.models import (
    ControlledValidationAction,
    ControlledValidationDecision,
    ControlledValidationRequest,
    ControlledValidationRisk,
)
from saarthi_ai.controlled_validation.policy import (
    evaluate_controlled_validation,
)


def make_request(
    **overrides: object,
) -> ControlledValidationRequest:
    values: dict[str, object] = {
        "execution_id": "execution-test",
        "target_url": "https://example.com/account",
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


def test_bounded_low_risk_request_is_allowed() -> None:
    result = evaluate_controlled_validation(make_request())

    assert result.decision is ControlledValidationDecision.ALLOW
    assert result.risk is ControlledValidationRisk.LOW
    assert result.allowed is True


def test_clickjacking_header_validation_is_low_risk() -> None:
    result = evaluate_controlled_validation(
        make_request(
            action=(
                ControlledValidationAction
                .CLICKJACKING_HEADER_VALIDATION
            )
        )
    )

    assert result.decision is ControlledValidationDecision.ALLOW
    assert result.risk is ControlledValidationRisk.LOW


def test_parameter_surface_validation_is_low_risk() -> None:
    result = evaluate_controlled_validation(
        make_request(
            action=(
                ControlledValidationAction
                .HTTP_PARAMETER_SURFACE_VALIDATION
            )
        )
    )

    assert result.decision is ControlledValidationDecision.ALLOW
    assert result.risk is ControlledValidationRisk.LOW


def test_session_cookie_validation_is_low_risk() -> None:
    result = evaluate_controlled_validation(
        make_request(
            action=(
                ControlledValidationAction
                .SESSION_COOKIE_ATTRIBUTE_VALIDATION
            )
        )
    )

    assert result.decision is ControlledValidationDecision.ALLOW
    assert result.risk is ControlledValidationRisk.LOW


def test_csrf_surface_validation_is_low_risk() -> None:
    result = evaluate_controlled_validation(
        make_request(
            action=(
                ControlledValidationAction
                .CSRF_PROTECTION_SURFACE_VALIDATION
            )
        )
    )

    assert result.decision is ControlledValidationDecision.ALLOW
    assert result.risk is ControlledValidationRisk.LOW


def test_authorization_is_required() -> None:
    result = evaluate_controlled_validation(
        make_request(authorized=False)
    )

    assert result.decision is ControlledValidationDecision.DENY
    assert "authorization" in result.reason.lower()


def test_active_testing_permission_is_required() -> None:
    result = evaluate_controlled_validation(
        make_request(active_testing=False)
    )

    assert result.decision is ControlledValidationDecision.DENY
    assert "active-testing" in result.reason.lower()


def test_explicit_approval_is_required() -> None:
    result = evaluate_controlled_validation(
        make_request(explicitly_approved=False)
    )

    assert (
        result.decision
        is ControlledValidationDecision.REQUIRE_APPROVAL
    )


@pytest.mark.parametrize("requested_requests", [0, 6, 100])
def test_request_count_is_bounded(
    requested_requests: int,
) -> None:
    result = evaluate_controlled_validation(
        make_request(requested_requests=requested_requests)
    )

    assert result.decision is ControlledValidationDecision.DENY


@pytest.mark.parametrize(
    "target_url",
    [
        "",
        "example.com",
        "ftp://example.com/",
        "javascript:alert(1)",
        "https://user:password@example.com/",
    ],
)
def test_invalid_or_credentialed_targets_are_denied(
    target_url: str,
) -> None:
    result = evaluate_controlled_validation(
        make_request(target_url=target_url)
    )

    assert result.decision is ControlledValidationDecision.DENY


def test_non_reversible_request_is_denied() -> None:
    result = evaluate_controlled_validation(
        make_request(reversible=False)
    )

    assert result.decision is ControlledValidationDecision.DENY
    assert "reversible" in result.reason.lower()


def test_moderate_action_requires_intrusive_permission() -> None:
    result = evaluate_controlled_validation(
        make_request(
            action=ControlledValidationAction.AUTHORIZATION_BOUNDARY,
            intrusive_testing=False,
        )
    )

    assert result.risk is ControlledValidationRisk.MODERATE
    assert result.decision is ControlledValidationDecision.DENY
    assert "intrusive-testing" in result.reason.lower()


def test_moderate_action_is_allowed_with_all_permissions() -> None:
    result = evaluate_controlled_validation(
        make_request(
            action=ControlledValidationAction.AUTHORIZATION_BOUNDARY,
            intrusive_testing=True,
        )
    )

    assert result.risk is ControlledValidationRisk.MODERATE
    assert result.decision is ControlledValidationDecision.ALLOW


@pytest.mark.parametrize(
    "action",
    [
        ControlledValidationAction.STATE_CHANGE_VALIDATION,
        ControlledValidationAction.FILE_PROCESSING_VALIDATION,
    ],
)
def test_high_impact_actions_are_manual_only(
    action: ControlledValidationAction,
) -> None:
    result = evaluate_controlled_validation(
        make_request(
            action=action,
            intrusive_testing=True,
        )
    )

    assert result.risk is ControlledValidationRisk.HIGH
    assert result.decision is ControlledValidationDecision.MANUAL_ONLY
    assert result.allowed is False


def test_destructive_action_is_always_denied() -> None:
    result = evaluate_controlled_validation(
        make_request(
            action=ControlledValidationAction.DESTRUCTIVE_VALIDATION,
            intrusive_testing=True,
        )
    )

    assert result.risk is ControlledValidationRisk.DESTRUCTIVE
    assert result.decision is ControlledValidationDecision.DENY


def test_empty_execution_identifier_is_denied() -> None:
    result = evaluate_controlled_validation(
        make_request(execution_id=" ")
    )

    assert result.decision is ControlledValidationDecision.DENY
