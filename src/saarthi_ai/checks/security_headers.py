from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import httpx

RECOMMENDED_SECURITY_HEADERS = {
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
}


@dataclass(frozen=True)
class SecurityHeadersResult:
    target_url: str
    status_code: int
    present_headers: tuple[str, ...]
    missing_headers: tuple[str, ...]
    response_headers: dict[str, str]
    error: str | None = None

    @property
    def passed(self) -> bool:
        return not self.error and not self.missing_headers


def analyze_security_headers(
    *,
    target_url: str,
    status_code: int,
    headers: Mapping[str, str],
) -> SecurityHeadersResult:
    normalized_headers = {
        name.lower().strip(): value.strip()
        for name, value in headers.items()
    }

    present_headers = tuple(
        sorted(
            header
            for header in RECOMMENDED_SECURITY_HEADERS
            if header in normalized_headers
        )
    )

    missing_headers = tuple(
        sorted(RECOMMENDED_SECURITY_HEADERS.difference(present_headers))
    )

    return SecurityHeadersResult(
        target_url=target_url,
        status_code=status_code,
        present_headers=present_headers,
        missing_headers=missing_headers,
        response_headers={
            header: normalized_headers[header]
            for header in present_headers
        },
    )


async def run_security_headers_check(
    target_url: str,
    *,
    timeout_seconds: float = 10.0,
    client: httpx.AsyncClient | None = None,
) -> SecurityHeadersResult:
    owns_client = client is None

    if client is None:
        client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
        )

    try:
        response = await client.get(target_url)
        return analyze_security_headers(
            target_url=target_url,
            status_code=response.status_code,
            headers=response.headers,
        )
    except httpx.HTTPError as exc:
        return SecurityHeadersResult(
            target_url=target_url,
            status_code=0,
            present_headers=(),
            missing_headers=tuple(sorted(RECOMMENDED_SECURITY_HEADERS)),
            response_headers={},
            error=str(exc),
        )
    finally:
        if owns_client:
            await client.aclose()
