from __future__ import annotations

from urllib.parse import urlparse

from saarthi_ai.blind_validation.models import (
    BlindValidationDecision,
    BlindValidationPolicyResult,
    BlindValidationRequest,
)

MAX_POLL_ATTEMPTS = 12
MIN_POLL_INTERVAL_SECONDS = 5
MAX_POLL_INTERVAL_SECONDS = 60


def evaluate_blind_validation(
    request: BlindValidationRequest,
) -> BlindValidationPolicyResult:
    if not request.execution_id.strip():
        return BlindValidationPolicyResult(
            decision=BlindValidationDecision.DENY,
            reason="Execution ID is required.",
        )

    if not request.authorized:
        return BlindValidationPolicyResult(
            decision=BlindValidationDecision.DENY,
            reason="Target authorization is required.",
        )

    parsed_target = urlparse(request.target_url)

    if parsed_target.scheme not in {"http", "https"} or not parsed_target.netloc:
        return BlindValidationPolicyResult(
            decision=BlindValidationDecision.DENY,
            reason="A valid HTTP or HTTPS target URL is required.",
        )

    if not request.active_testing:
        return BlindValidationPolicyResult(
            decision=BlindValidationDecision.DENY,
            reason="Active-testing authorization is required.",
        )

    if request.requested_poll_attempts < 1:
        return BlindValidationPolicyResult(
            decision=BlindValidationDecision.DENY,
            reason="At least one polling attempt is required.",
        )

    if request.requested_poll_attempts > MAX_POLL_ATTEMPTS:
        return BlindValidationPolicyResult(
            decision=BlindValidationDecision.DENY,
            reason=(
                "Requested polling attempts exceed the bounded maximum of "
                f"{MAX_POLL_ATTEMPTS}."
            ),
        )

    if not (
        MIN_POLL_INTERVAL_SECONDS
        <= request.requested_poll_interval_seconds
        <= MAX_POLL_INTERVAL_SECONDS
    ):
        return BlindValidationPolicyResult(
            decision=BlindValidationDecision.DENY,
            reason=(
                "Polling interval must be between "
                f"{MIN_POLL_INTERVAL_SECONDS} and "
                f"{MAX_POLL_INTERVAL_SECONDS} seconds."
            ),
        )

    if not request.explicitly_approved:
        return BlindValidationPolicyResult(
            decision=BlindValidationDecision.REQUIRE_APPROVAL,
            reason="Blind validation requires explicit operator approval.",
        )

    return BlindValidationPolicyResult(
        decision=BlindValidationDecision.ALLOW,
        reason=(
            "Blind validation is authorized, explicitly approved, "
            "and bounded by Phase 4B policy."
        ),
    )
