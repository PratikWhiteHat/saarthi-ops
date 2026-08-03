from __future__ import annotations

from urllib.parse import urlparse

from saarthi_ai.checks.models import (
    CheckDecision,
    CheckMode,
    DirectCheckDefinition,
    DirectCheckRequest,
    PolicyResult,
)

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
BLOCKED_METHODS = {"DELETE", "TRACE", "CONNECT"}


def evaluate_direct_check(
    definition: DirectCheckDefinition,
    request: DirectCheckRequest,
) -> PolicyResult:
    method = request.requested_method.upper().strip()

    if not request.execution_id.strip():
        return PolicyResult(
            decision=CheckDecision.DENY,
            reason="Execution ID is required.",
        )

    if not request.authorized:
        return PolicyResult(
            decision=CheckDecision.DENY,
            reason="Target authorization is required.",
        )

    parsed_target = urlparse(request.target_url)
    if parsed_target.scheme not in {"http", "https"} or not parsed_target.netloc:
        return PolicyResult(
            decision=CheckDecision.DENY,
            reason="A valid HTTP or HTTPS target URL is required.",
        )

    if request.check_id != definition.check_id:
        return PolicyResult(
            decision=CheckDecision.DENY,
            reason="Requested check does not match the registered check definition.",
        )

    if request.requested_requests < 1:
        return PolicyResult(
            decision=CheckDecision.DENY,
            reason="Requested request count must be at least one.",
        )

    if request.requested_requests > definition.max_requests:
        return PolicyResult(
            decision=CheckDecision.DENY,
            reason=(
                f"Requested request count exceeds the allowed maximum of "
                f"{definition.max_requests}."
            ),
        )

    if method in BLOCKED_METHODS:
        return PolicyResult(
            decision=CheckDecision.DENY,
            reason=f"HTTP method {method} is blocked by policy.",
        )

    allowed_methods = {
        allowed_method.upper().strip()
        for allowed_method in definition.allowed_methods
    }

    if method not in allowed_methods:
        return PolicyResult(
            decision=CheckDecision.DENY,
            reason=f"HTTP method {method} is not allowed for this check.",
        )

    if definition.destructive:
        return PolicyResult(
            decision=CheckDecision.DENY,
            reason="Destructive direct checks are not permitted in Phase 4A.",
        )

    if definition.requires_active_testing and not request.active_testing:
        return PolicyResult(
            decision=CheckDecision.DENY,
            reason="Active-testing authorization is required for this check.",
        )

    if definition.mode is CheckMode.HIGH_IMPACT:
        return PolicyResult(
            decision=CheckDecision.DENY,
            reason="High-impact checks are not permitted in Phase 4A.",
        )

    if (
        definition.requires_explicit_approval
        and not request.explicitly_approved
    ):
        return PolicyResult(
            decision=CheckDecision.REQUIRE_APPROVAL,
            reason="This check requires explicit operator approval.",
        )

    if method not in SAFE_METHODS and not request.explicitly_approved:
        return PolicyResult(
            decision=CheckDecision.REQUIRE_APPROVAL,
            reason=f"HTTP method {method} requires explicit operator approval.",
        )

    return PolicyResult(
        decision=CheckDecision.ALLOW,
        reason="Direct check is authorized and permitted by Phase 4A policy.",
    )
