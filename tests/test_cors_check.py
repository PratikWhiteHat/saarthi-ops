import httpx
import pytest

from saarthi_ai.checks.cors import (
    NULL_ORIGIN,
    TEST_ORIGIN,
    analyze_cors_probe,
    analyze_cors_results,
    run_cors_check,
)


def make_probe(
    *,
    origin: str = TEST_ORIGIN,
    allow_origin: str | None = None,
    credentials: bool = False,
    methods: str | None = None,
    allowed_headers: str | None = None,
    vary: str | None = None,
):
    headers: dict[str, str] = {}

    if allow_origin is not None:
        headers["Access-Control-Allow-Origin"] = allow_origin

    if credentials:
        headers["Access-Control-Allow-Credentials"] = "true"

    if methods is not None:
        headers["Access-Control-Allow-Methods"] = methods

    if allowed_headers is not None:
        headers["Access-Control-Allow-Headers"] = allowed_headers

    if vary is not None:
        headers["Vary"] = vary

    return analyze_cors_probe(
        probe_name="test",
        request_method="GET",
        request_origin=origin,
        status_code=200,
        headers=httpx.Headers(headers),
    )


def test_detects_arbitrary_origin_reflection() -> None:
    probe = make_probe(
        allow_origin=TEST_ORIGIN,
        vary="Origin",
    )

    result = analyze_cors_results(
        target_url="https://example.com/",
        probes=(probe,),
    )

    finding_ids = {
        finding.finding_id
        for finding in result.findings
    }

    assert "arbitrary-origin-reflection" in finding_ids
    assert result.passed is False


def test_reflected_origin_with_credentials_is_high_severity() -> None:
    probe = make_probe(
        allow_origin=TEST_ORIGIN,
        credentials=True,
        vary="Origin",
    )

    result = analyze_cors_results(
        target_url="https://example.com/",
        probes=(probe,),
    )

    finding = next(
        finding
        for finding in result.findings
        if finding.finding_id == "arbitrary-origin-reflection"
    )

    assert finding.severity == "high"


def test_detects_wildcard_with_credentials() -> None:
    probe = make_probe(
        allow_origin="*",
        credentials=True,
    )

    result = analyze_cors_results(
        target_url="https://example.com/",
        probes=(probe,),
    )

    assert any(
        finding.finding_id == "wildcard-with-credentials"
        for finding in result.findings
    )


def test_detects_null_origin_trust() -> None:
    probe = make_probe(
        origin=NULL_ORIGIN,
        allow_origin=NULL_ORIGIN,
        credentials=True,
        vary="Origin",
    )

    result = analyze_cors_results(
        target_url="https://example.com/",
        probes=(probe,),
    )

    assert any(
        finding.finding_id == "null-origin-trusted"
        for finding in result.findings
    )


def test_detects_missing_vary_origin() -> None:
    probe = make_probe(
        allow_origin=TEST_ORIGIN,
    )

    result = analyze_cors_results(
        target_url="https://example.com/",
        probes=(probe,),
    )

    assert any(
        finding.finding_id == "missing-vary-origin"
        for finding in result.findings
    )


def test_detects_broad_methods_and_sensitive_headers() -> None:
    probe = make_probe(
        allow_origin=TEST_ORIGIN,
        methods="GET, POST, PUT, DELETE",
        allowed_headers="Content-Type, Authorization, X-Api-Key",
        vary="Origin",
    )

    result = analyze_cors_results(
        target_url="https://example.com/",
        probes=(probe,),
    )

    finding_ids = {
        finding.finding_id
        for finding in result.findings
    }

    assert "broad-cors-methods" in finding_ids
    assert "sensitive-cors-headers" in finding_ids


def test_safe_cors_response_passes() -> None:
    probe = make_probe(
        allow_origin="https://trusted.example",
        methods="GET, POST",
        allowed_headers="Content-Type",
        vary="Origin",
    )

    result = analyze_cors_results(
        target_url="https://example.com/",
        probes=(probe,),
    )

    assert result.findings == ()
    assert result.passed is True


@pytest.mark.asyncio
async def test_run_cors_check_uses_three_bounded_requests() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            headers={
                "Access-Control-Allow-Origin": (
                    request.headers.get("Origin", "")
                ),
                "Vary": "Origin",
            },
        )

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(
        transport=transport,
        follow_redirects=False,
    ) as client:
        result = await run_cors_check(
            "https://example.com/",
            client=client,
        )

    assert len(requests) == 3
    assert [request.method for request in requests] == [
        "GET",
        "GET",
        "OPTIONS",
    ]
    assert len(result.probes) == 3


@pytest.mark.asyncio
async def test_run_cors_check_does_not_follow_redirects() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            302,
            headers={
                "Location": "https://outside.example/",
            },
        )

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(
        transport=transport,
        follow_redirects=False,
    ) as client:
        result = await run_cors_check(
            "https://example.com/",
            client=client,
        )

    assert len(requests) == 3
    assert all(probe.status_code == 302 for probe in result.probes)


@pytest.mark.asyncio
async def test_run_cors_check_handles_http_errors() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            "connection failed",
            request=request,
        )

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(transport=transport) as client:
        result = await run_cors_check(
            "https://example.com/",
            client=client,
        )

    assert len(result.probes) == 3
    assert result.error is not None
    assert all(probe.error for probe in result.probes)
