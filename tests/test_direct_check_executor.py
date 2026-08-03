import pytest

from saarthi_ai.checks.executor import execute_direct_check
from saarthi_ai.checks.models import (
    CheckDecision,
    DirectCheckRequest,
)


def make_request(
    *,
    check_id: str = "security-headers",
    authorized: bool = True,
    active_testing: bool = True,
) -> DirectCheckRequest:
    return DirectCheckRequest(
        execution_id="execution-test",
        target_url="https://example.com/",
        check_id=check_id,
        authorized=authorized,
        active_testing=active_testing,
    )


@pytest.mark.asyncio
async def test_executor_denies_unknown_check() -> None:
    result = await execute_direct_check(
        make_request(check_id="unknown-check"),
    )

    assert result.executed is False
    assert result.policy.decision is CheckDecision.DENY
    assert result.error == "Unknown direct check."


@pytest.mark.asyncio
async def test_executor_denies_unauthorized_check() -> None:
    result = await execute_direct_check(
        make_request(authorized=False),
    )

    assert result.executed is False
    assert result.policy.decision is CheckDecision.DENY
    assert result.result is None


@pytest.mark.asyncio
async def test_executor_does_not_run_unimplemented_adapter() -> None:
    result = await execute_direct_check(
        DirectCheckRequest(
            execution_id="execution-test",
            target_url="https://example.com/",
            check_id="information-disclosure",
            authorized=True,
            active_testing=False,
        ),
    )

    assert result.executed is False
    assert result.policy.decision is CheckDecision.DENY
    assert result.error == "Direct-check adapter is unavailable."


@pytest.mark.asyncio
async def test_executor_blocks_rce_confirmation() -> None:
    result = await execute_direct_check(
        DirectCheckRequest(
            execution_id="execution-test",
            target_url="https://example.com/",
            check_id="rce-confirmation",
            authorized=True,
            active_testing=True,
            explicitly_approved=True,
        ),
    )

    assert result.executed is False
    assert result.policy.decision is CheckDecision.DENY
    assert "high-impact" in result.policy.reason.lower()


@pytest.mark.asyncio
async def test_security_headers_http_error_is_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_run_security_headers_check(
        target_url: str,
    ) -> object:
        from saarthi_ai.checks.security_headers import SecurityHeadersResult

        return SecurityHeadersResult(
            target_url=target_url,
            status_code=0,
            present_headers=(),
            missing_headers=(),
            response_headers={},
            error="connection failed",
        )

    monkeypatch.setattr(
        "saarthi_ai.checks.executor.run_security_headers_check",
        fake_run_security_headers_check,
    )

    result = await execute_direct_check(make_request())

    assert result.executed is True
    assert result.error == "connection failed"


@pytest.mark.asyncio
async def test_security_headers_adapter_executes_when_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_run_security_headers_check(
        target_url: str,
    ) -> object:
        from saarthi_ai.checks.security_headers import SecurityHeadersResult

        return SecurityHeadersResult(
            target_url=target_url,
            status_code=200,
            present_headers=("content-security-policy",),
            missing_headers=("strict-transport-security",),
            response_headers={
                "content-security-policy": "default-src 'self'",
            },
        )

    monkeypatch.setattr(
        "saarthi_ai.checks.executor.run_security_headers_check",
        fake_run_security_headers_check,
    )

    result = await execute_direct_check(make_request())

    assert result.executed is True
    assert result.policy.decision is CheckDecision.ALLOW
    assert result.result is not None
    assert result.result.status_code == 200
    assert "strict-transport-security" in result.result.missing_headers
