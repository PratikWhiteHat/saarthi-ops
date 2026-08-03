import pytest

from saarthi_ai.blind_validation.models import (
    BlindValidationDecision,
    BlindValidationRequest,
    CallbackProtocol,
)
from saarthi_ai.blind_validation.policy import evaluate_blind_validation


def make_request(
    **overrides,
) -> BlindValidationRequest:
    values = {
        "execution_id": "execution-test",
        "target_url": "https://example.com/",
        "authorized": True,
        "active_testing": True,
        "explicitly_approved": True,
        "callback_protocol": CallbackProtocol.HTTPS,
        "requested_poll_attempts": 6,
        "requested_poll_interval_seconds": 10,
    }
    values.update(overrides)
    return BlindValidationRequest(**values)


def test_valid_blind_validation_request_is_allowed() -> None:
    result = evaluate_blind_validation(make_request())

    assert result.decision is BlindValidationDecision.ALLOW


def test_authorization_is_required() -> None:
    result = evaluate_blind_validation(
        make_request(authorized=False)
    )

    assert result.decision is BlindValidationDecision.DENY


def test_active_testing_permission_is_required() -> None:
    result = evaluate_blind_validation(
        make_request(active_testing=False)
    )

    assert result.decision is BlindValidationDecision.DENY
    assert "active-testing" in result.reason.lower()


def test_explicit_approval_is_required() -> None:
    result = evaluate_blind_validation(
        make_request(explicitly_approved=False)
    )

    assert result.decision is BlindValidationDecision.REQUIRE_APPROVAL


@pytest.mark.parametrize("attempts", [0, 13, 100])
def test_poll_attempts_are_bounded(attempts: int) -> None:
    result = evaluate_blind_validation(
        make_request(requested_poll_attempts=attempts)
    )

    assert result.decision is BlindValidationDecision.DENY


@pytest.mark.parametrize("interval", [0, 4, 61, 120])
def test_poll_interval_is_bounded(interval: int) -> None:
    result = evaluate_blind_validation(
        make_request(requested_poll_interval_seconds=interval)
    )

    assert result.decision is BlindValidationDecision.DENY


@pytest.mark.parametrize(
    "target_url",
    [
        "",
        "example.com",
        "ftp://example.com/",
        "javascript:alert(1)",
    ],
)
def test_invalid_target_urls_are_denied(target_url: str) -> None:
    result = evaluate_blind_validation(
        make_request(target_url=target_url)
    )

    assert result.decision is BlindValidationDecision.DENY
