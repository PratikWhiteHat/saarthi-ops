from __future__ import annotations

from dataclasses import dataclass

import httpx

from saarthi_ai.config import tls_verify

TEST_ORIGIN = "https://saarthi.invalid"
NULL_ORIGIN = "null"
PREFLIGHT_METHOD = "POST"
PREFLIGHT_HEADERS = "authorization, content-type"

SENSITIVE_ALLOWED_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
}

OVERLY_BROAD_METHODS = {
    "delete",
    "patch",
    "put",
    "trace",
}


@dataclass(frozen=True)
class CorsProbeResult:
    probe_name: str
    request_method: str
    request_origin: str
    status_code: int
    allow_origin: str | None
    allow_credentials: bool
    allow_methods: tuple[str, ...]
    allow_headers: tuple[str, ...]
    vary_origin: bool
    error: str | None = None


@dataclass(frozen=True)
class CorsFinding:
    finding_id: str
    title: str
    severity: str
    evidence: str


@dataclass(frozen=True)
class CorsCheckResult:
    target_url: str
    probes: tuple[CorsProbeResult, ...]
    findings: tuple[CorsFinding, ...]
    error: str | None = None

    @property
    def passed(self) -> bool:
        return not self.error and not self.findings


def _split_header_values(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()

    return tuple(
        sorted(
            {
                item.strip().lower()
                for item in value.split(",")
                if item.strip()
            }
        )
    )


def _header_is_true(value: str | None) -> bool:
    return value is not None and value.strip().lower() == "true"


def _vary_contains_origin(value: str | None) -> bool:
    return "origin" in _split_header_values(value)


def analyze_cors_probe(
    *,
    probe_name: str,
    request_method: str,
    request_origin: str,
    status_code: int,
    headers: httpx.Headers,
    error: str | None = None,
) -> CorsProbeResult:
    return CorsProbeResult(
        probe_name=probe_name,
        request_method=request_method,
        request_origin=request_origin,
        status_code=status_code,
        allow_origin=headers.get("access-control-allow-origin"),
        allow_credentials=_header_is_true(
            headers.get("access-control-allow-credentials")
        ),
        allow_methods=_split_header_values(
            headers.get("access-control-allow-methods")
        ),
        allow_headers=_split_header_values(
            headers.get("access-control-allow-headers")
        ),
        vary_origin=_vary_contains_origin(headers.get("vary")),
        error=error,
    )


def analyze_cors_results(
    *,
    target_url: str,
    probes: tuple[CorsProbeResult, ...],
) -> CorsCheckResult:
    findings: list[CorsFinding] = []

    for probe in probes:
        if probe.error:
            continue

        allow_origin = (
            probe.allow_origin.strip()
            if probe.allow_origin is not None
            else None
        )

        if (
            probe.request_origin == TEST_ORIGIN
            and allow_origin == TEST_ORIGIN
        ):
            findings.append(
                CorsFinding(
                    finding_id="arbitrary-origin-reflection",
                    title="Arbitrary Origin Reflected",
                    severity="high" if probe.allow_credentials else "medium",
                    evidence=(
                        f"Origin {TEST_ORIGIN} was reflected in "
                        "Access-Control-Allow-Origin."
                    ),
                )
            )

        if allow_origin == "*" and probe.allow_credentials:
            findings.append(
                CorsFinding(
                    finding_id="wildcard-with-credentials",
                    title="Wildcard Origin Combined with Credentials",
                    severity="high",
                    evidence=(
                        "Access-Control-Allow-Origin is '*' while "
                        "Access-Control-Allow-Credentials is true."
                    ),
                )
            )

        if (
            probe.request_origin == NULL_ORIGIN
            and allow_origin == NULL_ORIGIN
        ):
            findings.append(
                CorsFinding(
                    finding_id="null-origin-trusted",
                    title="Null Origin Trusted",
                    severity="high" if probe.allow_credentials else "medium",
                    evidence="The null Origin value was accepted by the server.",
                )
            )

        if allow_origin not in {None, "*"} and not probe.vary_origin:
            findings.append(
                CorsFinding(
                    finding_id="missing-vary-origin",
                    title="Missing Vary: Origin",
                    severity="low",
                    evidence=(
                        "A specific origin was allowed without "
                        "Vary: Origin."
                    ),
                )
            )

        broad_methods = tuple(
            sorted(
                set(probe.allow_methods).intersection(
                    OVERLY_BROAD_METHODS
                )
            )
        )

        if broad_methods:
            findings.append(
                CorsFinding(
                    finding_id="broad-cors-methods",
                    title="Broad CORS Methods Allowed",
                    severity="medium",
                    evidence=(
                        "Potentially sensitive methods allowed: "
                        f"{', '.join(broad_methods)}."
                    ),
                )
            )

        sensitive_headers = tuple(
            sorted(
                set(probe.allow_headers).intersection(
                    SENSITIVE_ALLOWED_HEADERS
                )
            )
        )

        if sensitive_headers:
            findings.append(
                CorsFinding(
                    finding_id="sensitive-cors-headers",
                    title="Sensitive CORS Headers Allowed",
                    severity="medium",
                    evidence=(
                        "Sensitive request headers allowed: "
                        f"{', '.join(sensitive_headers)}."
                    ),
                )
            )

    unique_findings = {
        finding.finding_id: finding
        for finding in findings
    }

    errors = [
        probe.error
        for probe in probes
        if probe.error
    ]

    return CorsCheckResult(
        target_url=target_url,
        probes=probes,
        findings=tuple(
            sorted(
                unique_findings.values(),
                key=lambda finding: finding.finding_id,
            )
        ),
        error="; ".join(errors) if len(errors) == len(probes) else None,
    )


async def run_cors_check(
    target_url: str,
    *,
    timeout_seconds: float = 10.0,
    client: httpx.AsyncClient | None = None,
) -> CorsCheckResult:
    owns_client = client is None

    if client is None:
        client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            verify=tls_verify(),
        )

    probes: list[CorsProbeResult] = []

    probe_definitions = (
        (
            "arbitrary-origin",
            "GET",
            TEST_ORIGIN,
            {"Origin": TEST_ORIGIN},
        ),
        (
            "null-origin",
            "GET",
            NULL_ORIGIN,
            {"Origin": NULL_ORIGIN},
        ),
        (
            "preflight",
            "OPTIONS",
            TEST_ORIGIN,
            {
                "Origin": TEST_ORIGIN,
                "Access-Control-Request-Method": PREFLIGHT_METHOD,
                "Access-Control-Request-Headers": PREFLIGHT_HEADERS,
            },
        ),
    )

    try:
        for probe_name, method, origin, headers in probe_definitions:
            try:
                response = await client.request(
                    method,
                    target_url,
                    headers=headers,
                )

                probes.append(
                    analyze_cors_probe(
                        probe_name=probe_name,
                        request_method=method,
                        request_origin=origin,
                        status_code=response.status_code,
                        headers=response.headers,
                    )
                )
            except httpx.HTTPError as exc:
                probes.append(
                    analyze_cors_probe(
                        probe_name=probe_name,
                        request_method=method,
                        request_origin=origin,
                        status_code=0,
                        headers=httpx.Headers(),
                        error=str(exc),
                    )
                )

        return analyze_cors_results(
            target_url=target_url,
            probes=tuple(probes),
        )
    finally:
        if owns_client:
            await client.aclose()
