import httpx
import pytest

from saarthi_ai.checks.security_headers import (
    RECOMMENDED_SECURITY_HEADERS,
    analyze_security_headers,
    run_security_headers_check,
)


def test_analyze_security_headers_detects_present_and_missing_headers() -> None:
    result = analyze_security_headers(
        target_url="https://example.com/",
        status_code=200,
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
        },
    )

    assert result.status_code == 200
    assert "content-security-policy" in result.present_headers
    assert "x-content-type-options" in result.present_headers
    assert "strict-transport-security" in result.missing_headers
    assert result.passed is False


def test_analyze_security_headers_passes_when_all_headers_exist() -> None:
    headers = {
        header: "configured"
        for header in RECOMMENDED_SECURITY_HEADERS
    }

    result = analyze_security_headers(
        target_url="https://example.com/",
        status_code=200,
        headers=headers,
    )

    assert result.missing_headers == ()
    assert result.passed is True


@pytest.mark.asyncio
async def test_run_security_headers_check_uses_single_get_request() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            headers={
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=31536000",
            },
        )

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(transport=transport) as client:
        result = await run_security_headers_check(
            "https://example.com/",
            client=client,
        )

    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert result.status_code == 200
    assert result.error is None


@pytest.mark.asyncio
async def test_run_security_headers_check_does_not_follow_redirects() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            302,
            headers={"Location": "https://outside.example/"},
        )

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(
        transport=transport,
        follow_redirects=False,
    ) as client:
        result = await run_security_headers_check(
            "https://example.com/",
            client=client,
        )

    assert len(requests) == 1
    assert result.status_code == 302


@pytest.mark.asyncio
async def test_run_security_headers_check_handles_http_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            "connection failed",
            request=request,
        )

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(transport=transport) as client:
        result = await run_security_headers_check(
            "https://example.com/",
            client=client,
        )

    assert result.status_code == 0
    assert result.error is not None
    assert result.present_headers == ()
