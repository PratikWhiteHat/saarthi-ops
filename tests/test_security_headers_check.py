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


def test_detects_sensitive_response_header_names() -> None:
    result = analyze_security_headers(
        target_url="https://example.com/",
        status_code=200,
        headers={
            "Server": "nginx/1.24.0",
            "X-Powered-By": "PHP/8.2.7",
        },
    )

    findings = {
        finding.header_name: finding
        for finding in result.sensitive_headers
    }

    assert "server" in findings
    assert "x-powered-by" in findings
    assert "software_version_disclosure" in findings["server"].reasons
    assert len(findings["server"].fingerprint_sha256) == 64


def test_redacts_token_like_header_values() -> None:
    token = "abcdefghijklmnopqrstuvwxyz1234567890"

    result = analyze_security_headers(
        target_url="https://example.com/",
        status_code=200,
        headers={
            "X-Debug-Token": token,
        },
    )

    assert len(result.sensitive_headers) == 1

    finding = result.sensitive_headers[0]

    assert token not in finding.redacted_value
    assert "[REDACTED-TOKEN]" in finding.redacted_value
    assert "token_like_value" in finding.reasons


def test_redacts_private_ip_addresses() -> None:
    result = analyze_security_headers(
        target_url="https://example.com/",
        status_code=200,
        headers={
            "X-Backend-Server": "node-01 192.168.10.20",
        },
    )

    finding = result.sensitive_headers[0]

    assert "192.168.10.20" not in finding.redacted_value
    assert "[REDACTED-PRIVATE-IP]" in finding.redacted_value
    assert "private_ip_disclosure" in finding.reasons


def test_secret_header_values_are_fully_redacted() -> None:
    result = analyze_security_headers(
        target_url="https://example.com/",
        status_code=200,
        headers={
            "Set-Cookie": "session=super-secret-session-value",
        },
    )

    finding = result.sensitive_headers[0]

    assert finding.redacted_value == "[REDACTED]"
    assert "credential_or_session_header" in finding.reasons


def test_sensitive_headers_make_result_fail() -> None:
    headers = {
        header: "configured"
        for header in RECOMMENDED_SECURITY_HEADERS
    }
    headers["Server"] = "nginx/1.24.0"

    result = analyze_security_headers(
        target_url="https://example.com/",
        status_code=200,
        headers=headers,
    )

    assert result.missing_headers == ()
    assert result.sensitive_headers
    assert result.passed is False


def test_cloudflare_report_to_url_is_not_flagged_as_token() -> None:
    result = analyze_security_headers(
        target_url="https://example.com/",
        status_code=200,
        headers={
            "Report-To": (
                '{"group":"cf-nel","max_age":604800,'
                '"endpoints":[{"url":'
                '"https://a.nel.cloudflare.com/report/v4?s='
                'abcdefghijklmnopqrstuvwxyz1234567890"}]}'
            ),
        },
    )

    assert result.sensitive_headers == ()


def test_cloudflare_nel_header_is_not_sensitive() -> None:
    result = analyze_security_headers(
        target_url="https://example.com/",
        status_code=200,
        headers={
            "NEL": (
                '{"report_to":"cf-nel","success_fraction":0.0,'
                '"max_age":604800}'
            ),
        },
    )

    assert result.sensitive_headers == ()


def test_token_named_header_still_redacts_long_value() -> None:
    token = "abcdefghijklmnopqrstuvwxyz1234567890"

    result = analyze_security_headers(
        target_url="https://example.com/",
        status_code=200,
        headers={
            "X-Access-Token": token,
        },
    )

    assert len(result.sensitive_headers) == 1
    finding = result.sensitive_headers[0]

    assert "token_like_value" in finding.reasons
    assert "credential_or_session_header" in finding.reasons
    assert token not in finding.redacted_value
    assert finding.redacted_value == "[REDACTED]"
