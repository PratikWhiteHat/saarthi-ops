from __future__ import annotations

from dataclasses import dataclass

from saarthi_ai.checks.models import (
    CheckDecision,
    DirectCheckRequest,
    PolicyResult,
)
from saarthi_ai.checks.policy import evaluate_direct_check
from saarthi_ai.checks.registry import get_direct_check
from saarthi_ai.checks.security_headers import (
    SecurityHeadersResult,
    run_security_headers_check,
)


@dataclass(frozen=True)
class DirectCheckExecutionResult:
    check_id: str
    target_url: str
    policy: PolicyResult
    executed: bool
    result: SecurityHeadersResult | None = None
    error: str | None = None


async def execute_direct_check(
    request: DirectCheckRequest,
) -> DirectCheckExecutionResult:
    definition = get_direct_check(request.check_id)

    if definition is None:
        return DirectCheckExecutionResult(
            check_id=request.check_id,
            target_url=request.target_url,
            policy=PolicyResult(
                decision=CheckDecision.DENY,
                reason="Requested check is not registered.",
            ),
            executed=False,
            error="Unknown direct check.",
        )

    policy_result = evaluate_direct_check(definition, request)

    if policy_result.decision is not CheckDecision.ALLOW:
        return DirectCheckExecutionResult(
            check_id=request.check_id,
            target_url=request.target_url,
            policy=policy_result,
            executed=False,
        )

    if request.check_id == "security-headers":
        result = await run_security_headers_check(request.target_url)

        return DirectCheckExecutionResult(
            check_id=request.check_id,
            target_url=request.target_url,
            policy=policy_result,
            executed=True,
            result=result,
            error=result.error,
        )

    return DirectCheckExecutionResult(
        check_id=request.check_id,
        target_url=request.target_url,
        policy=PolicyResult(
            decision=CheckDecision.DENY,
            reason="The registered check does not have an executable adapter yet.",
        ),
        executed=False,
        error="Direct-check adapter is unavailable.",
    )
