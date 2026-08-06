"""Mocked-transport tests for the Phase 6C HTTP validator adapter."""

from __future__ import annotations

import httpx
import pytest

from saarthi_ai.controlled_validation.executor import (
    ControlledValidationExecutionRequest,
)
from saarthi_ai.controlled_validation.models import (
    ControlledValidationAction,
    ControlledValidationRequest,
)
from saarthi_ai.controlled_validation.observation import (
    execute_bounded_observation,
)


def make_request(
    *,
    method: str = "GET",
    max_response_bytes: int = 65_536,
    headers: tuple[tuple[str, str], ...] = (),
    action: ControlledValidationAction = (
        ControlledValidationAction.RESPONSE_DIFFERENTIAL
    ),
    explicitly_approved: bool = True,
) -> ControlledValidationExecutionRequest:
    validation = ControlledValidationRequest(
        execution_id="execution-phase-6c",
        target_url="https://example.com/search?q=saarthi",
        action=action,
        authorized=True,
        active_testing=True,
        intrusive_testing=False,
        explicitly_approved=explicitly_approved,
        reversible=True,
        requested_requests=1,
    )

    return ControlledValidationExecutionRequest(
        validation=validation,
        method=method,
        max_response_bytes=max_response_bytes,
        headers=headers,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["GET", "HEAD"])
async def test_adapter_performs_exactly_one_allowed_request(
    method: str,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            headers={"Content-Type": "text/plain"},
            content=b"observation",
            request=request,
        )

    result = await execute_bounded_observation(
        make_request(method=method),
        transport=httpx.MockTransport(handler),
    )

    assert len(requests) == 1
    assert requests[0].method == method
    assert result.request_attempted is True
    assert result.response_received is True
    assert result.status_code == 200
    assert result.succeeded is True

    if method == "HEAD":
        assert result.body_bytes_captured == 0
    else:
        assert result.body_bytes_captured == len(b"observation")


@pytest.mark.asyncio
async def test_adapter_does_not_follow_redirects() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            302,
            headers={
                "Location": "https://outside.example/",
            },
            request=request,
        )

    result = await execute_bounded_observation(
        make_request(),
        transport=httpx.MockTransport(handler),
    )

    assert len(requests) == 1
    assert result.status_code == 302
    assert result.final_url == (
        "https://example.com/search?q=saarthi"
    )


@pytest.mark.asyncio
async def test_response_body_is_limited_while_streaming() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"A" * 10_000,
            request=request,
        )

    result = await execute_bounded_observation(
        make_request(max_response_bytes=1_024),
        transport=httpx.MockTransport(handler),
    )

    assert result.body_bytes_captured == 1_024
    assert result.body_truncated is True
    assert result.body_sha256 is not None
    assert len(result.body_sha256) == 64


@pytest.mark.asyncio
async def test_sensitive_response_headers_are_redacted() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Set-Cookie": "session=secret",
                "WWW-Authenticate": "Bearer secret",
                "Content-Type": "text/plain",
            },
            request=request,
        )

    result = await execute_bounded_observation(
        make_request(),
        transport=httpx.MockTransport(handler),
    )

    assert result.response_headers is not None
    assert result.response_headers["set-cookie"] == "<redacted>"
    assert (
        result.response_headers["www-authenticate"]
        == "<redacted>"
    )
    assert result.content_type == "text/plain"


@pytest.mark.asyncio
async def test_adapter_sends_no_cookie_or_authorization_header() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            request=request,
        )

    result = await execute_bounded_observation(
        make_request(
            headers=(("Accept", "application/json"),)
        ),
        transport=httpx.MockTransport(handler),
    )

    assert result.succeeded is True
    assert len(captured) == 1
    assert "authorization" not in captured[0].headers
    assert "cookie" not in captured[0].headers
    assert captured[0].headers["accept"] == "application/json"
    assert captured[0].content == b""


@pytest.mark.asyncio
async def test_policy_denial_prevents_transport_invocation() -> None:
    invoked = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal invoked
        invoked = True
        return httpx.Response(200, request=request)

    result = await execute_bounded_observation(
        make_request(
            method="POST",
        ),
        transport=httpx.MockTransport(handler),
    )

    assert invoked is False
    assert result.request_attempted is False
    assert result.response_received is False
    assert result.error_type == "policy_denied"
    assert result.succeeded is False


@pytest.mark.asyncio
async def test_missing_approval_prevents_transport_invocation() -> None:
    invoked = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal invoked
        invoked = True
        return httpx.Response(200, request=request)

    result = await execute_bounded_observation(
        make_request(explicitly_approved=False),
        transport=httpx.MockTransport(handler),
    )

    assert invoked is False
    assert result.request_attempted is False
    assert result.error_type == "policy_denied"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exception_type", "expected_error_type"),
    [
        (httpx.ConnectError, "ConnectError"),
        (httpx.ReadTimeout, "ReadTimeout"),
        (httpx.RemoteProtocolError, "RemoteProtocolError"),
    ],
)
async def test_http_failures_are_returned_as_structured_results(
    exception_type: type[httpx.HTTPError],
    expected_error_type: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exception_type(
            "simulated HTTP failure",
            request=request,
        )

    result = await execute_bounded_observation(
        make_request(),
        transport=httpx.MockTransport(handler),
    )

    assert result.request_attempted is True
    assert result.response_received is False
    assert result.status_code == 0
    assert result.error_type == expected_error_type
    assert result.error is not None
    assert result.succeeded is False


@pytest.mark.asyncio
async def test_input_handling_observation_uses_same_bounded_adapter() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            content=b"safe response",
            request=request,
        )

    result = await execute_bounded_observation(
        make_request(
            action=(
                ControlledValidationAction
                .INPUT_HANDLING_OBSERVATION
            )
        ),
        transport=httpx.MockTransport(handler),
    )

    assert len(requests) == 1
    assert result.succeeded is True


@pytest.mark.asyncio
async def test_cookie_analysis_discards_secret_values() -> None:
    secret = "never-persist-this-cookie-value"
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            headers=[
                (
                    "Set-Cookie",
                    "session="
                    f"{secret}; Secure; HttpOnly; SameSite=Lax",
                ),
            ],
            request=request,
        )

    result = await execute_bounded_observation(
        make_request(
            action=(
                ControlledValidationAction
                .SESSION_COOKIE_ATTRIBUTE_VALIDATION
            )
        ),
        transport=httpx.MockTransport(handler),
    )

    assert len(captured) == 1
    assert "cookie" not in captured[0].headers
    assert result.session_cookie_analysis is not None
    assert secret not in repr(result.session_cookie_analysis)
    assert result.response_headers is not None
    assert result.response_headers["set-cookie"] == "<redacted>"
