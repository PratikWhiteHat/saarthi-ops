"""Fail-closed policy for Phase 6 controlled attack validation."""

from __future__ import annotations

from urllib.parse import urlparse

from saarthi_ai.controlled_validation.models import (
    ControlledValidationAction,
    ControlledValidationDecision,
    ControlledValidationPolicyResult,
    ControlledValidationRequest,
    ControlledValidationRisk,
)

MAX_CONTROLLED_REQUESTS = 5

ACTION_RISK: dict[
    ControlledValidationAction,
    ControlledValidationRisk,
] = {
    ControlledValidationAction.RESPONSE_DIFFERENTIAL: (
        ControlledValidationRisk.LOW
    ),
    ControlledValidationAction.INPUT_HANDLING_OBSERVATION: (
        ControlledValidationRisk.LOW
    ),
    ControlledValidationAction.CLICKJACKING_HEADER_VALIDATION: (
        ControlledValidationRisk.LOW
    ),
    ControlledValidationAction.AUTHORIZATION_BOUNDARY: (
        ControlledValidationRisk.MODERATE
    ),
    ControlledValidationAction.STATE_CHANGE_VALIDATION: (
        ControlledValidationRisk.HIGH
    ),
    ControlledValidationAction.FILE_PROCESSING_VALIDATION: (
        ControlledValidationRisk.HIGH
    ),
    ControlledValidationAction.DESTRUCTIVE_VALIDATION: (
        ControlledValidationRisk.DESTRUCTIVE
    ),
}


def _result(
    decision: ControlledValidationDecision,
    risk: ControlledValidationRisk,
    reason: str,
) -> ControlledValidationPolicyResult:
    return ControlledValidationPolicyResult(
        decision=decision,
        risk=risk,
        reason=reason,
    )


def _valid_http_target(target_url: str) -> bool:
    try:
        parsed = urlparse(target_url)
    except ValueError:
        return False

    return (
        parsed.scheme.lower() in {"http", "https"}
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
    )


def evaluate_controlled_validation(
    request: ControlledValidationRequest,
) -> ControlledValidationPolicyResult:
    """Evaluate one controlled validation request without executing it."""

    risk = ACTION_RISK.get(
        request.action,
        ControlledValidationRisk.DESTRUCTIVE,
    )

    if not request.execution_id.strip():
        return _result(
            ControlledValidationDecision.DENY,
            risk,
            "A persistent execution identifier is required.",
        )

    if not request.authorized:
        return _result(
            ControlledValidationDecision.DENY,
            risk,
            "Confirmed authorization is required.",
        )

    if not _valid_http_target(request.target_url):
        return _result(
            ControlledValidationDecision.DENY,
            risk,
            "Target must be an absolute HTTP or HTTPS URL without credentials.",
        )

    if not request.active_testing:
        return _result(
            ControlledValidationDecision.DENY,
            risk,
            "Active-testing authorization is required.",
        )

    if not 1 <= request.requested_requests <= MAX_CONTROLLED_REQUESTS:
        return _result(
            ControlledValidationDecision.DENY,
            risk,
            (
                "Controlled validation is limited to between 1 and "
                f"{MAX_CONTROLLED_REQUESTS} requests."
            ),
        )

    if not request.reversible:
        return _result(
            ControlledValidationDecision.DENY,
            risk,
            "Automated validation must be explicitly reversible.",
        )

    if risk is ControlledValidationRisk.DESTRUCTIVE:
        return _result(
            ControlledValidationDecision.DENY,
            risk,
            "Destructive validation is never permitted automatically.",
        )

    if risk is ControlledValidationRisk.HIGH:
        return _result(
            ControlledValidationDecision.MANUAL_ONLY,
            risk,
            (
                "High-impact validation requires a separately reviewed "
                "manual procedure."
            ),
        )

    if (
        risk is ControlledValidationRisk.MODERATE
        and not request.intrusive_testing
    ):
        return _result(
            ControlledValidationDecision.DENY,
            risk,
            "Intrusive-testing authorization is required for this action.",
        )

    if not request.explicitly_approved:
        return _result(
            ControlledValidationDecision.REQUIRE_APPROVAL,
            risk,
            "Controlled validation requires explicit operator approval.",
        )

    return _result(
        ControlledValidationDecision.ALLOW,
        risk,
        (
            "Request is authorized, bounded, reversible, and permitted by "
            "Phase 6B policy."
        ),
    )
