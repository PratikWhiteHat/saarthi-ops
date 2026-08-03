from __future__ import annotations

import hashlib
import re
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

SENSITIVE_RESPONSE_HEADERS = {
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-runtime",
    "x-generator",
    "x-backend-server",
    "x-debug-token",
    "x-debug-token-link",
    "x-environment",
    "x-host",
    "x-node",
}

SECRET_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
}

TOKEN_PATTERN = re.compile(
    r"(?i)\b(?:bearer\s+)?[a-z0-9_-]{24,}\b"
)

TOKEN_CONTEXT_PATTERN = re.compile(
    r"(?i)(?:token|secret|api[_-]?key|access[_-]?key|session|credential)"
)

PRIVATE_IP_PATTERN = re.compile(
    r"\b(?:"
    r"10(?:\.\d{1,3}){3}|"
    r"192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"
    r")\b"
)

VERSION_PATTERN = re.compile(
    r"(?i)\b[a-z][a-z0-9._-]*/\d+(?:\.\d+){1,3}\b"
)


@dataclass(frozen=True)
class SensitiveHeaderFinding:
    """A credential-bearing response header requiring redaction."""

    header_name: str
    redacted_value: str
    fingerprint_sha256: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class HeaderObservation:
    """A non-credential response-header security observation."""

    header_name: str
    category: str
    severity: str
    redacted_value: str
    fingerprint_sha256: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class SecurityHeadersResult:
    target_url: str
    status_code: int
    present_headers: tuple[str, ...]
    missing_headers: tuple[str, ...]
    response_headers: dict[str, str]
    sensitive_headers: tuple[SensitiveHeaderFinding, ...] = ()
    header_observations: tuple[HeaderObservation, ...] = ()
    error: str | None = None

    @property
    def passed(self) -> bool:
        """Pass only when required headers exist and no credential risk exists."""

        return (
            not self.error
            and not self.missing_headers
            and not self.sensitive_headers
        )


def _fingerprint_header_value(value: str) -> str:
    """Create a stable fingerprint without preserving the original value."""

    return hashlib.sha256(
        value.encode(
            "utf-8",
            errors="ignore",
        )
    ).hexdigest()


def _redact_header_value(
    header_name: str,
    value: str,
) -> str:
    """Return a bounded value safe for evidence and terminal output."""

    normalized_name = header_name.lower().strip()

    if normalized_name in SECRET_HEADER_NAMES:
        return "[REDACTED]"

    token_context = (
        TOKEN_CONTEXT_PATTERN.search(normalized_name)
        is not None
    )

    redacted = value

    if token_context:
        redacted = TOKEN_PATTERN.sub(
            "[REDACTED-TOKEN]",
            redacted,
        )

    redacted = PRIVATE_IP_PATTERN.sub(
        "[REDACTED-PRIVATE-IP]",
        redacted,
    )

    if len(redacted) > 200:
        redacted = (
            f"{redacted[:200]}...[TRUNCATED]"
        )

    return redacted


def _detect_credential_reasons(
    header_name: str,
    value: str,
) -> tuple[str, ...]:
    """Detect credential-bearing headers without generic entropy guessing."""

    normalized_name = header_name.lower().strip()
    reasons: set[str] = set()

    if normalized_name in SECRET_HEADER_NAMES:
        reasons.add("credential_or_session_header")

    token_context = (
        TOKEN_CONTEXT_PATTERN.search(normalized_name)
        is not None
    )

    if token_context and TOKEN_PATTERN.search(value):
        reasons.add("token_like_value")

    return tuple(sorted(reasons))


def _find_sensitive_headers(
    headers: Mapping[str, str],
) -> tuple[SensitiveHeaderFinding, ...]:
    """Return only credential-bearing response-header findings."""

    findings: list[SensitiveHeaderFinding] = []

    for name, value in headers.items():
        normalized_name = name.lower().strip()
        normalized_value = value.strip()

        reasons = _detect_credential_reasons(
            normalized_name,
            normalized_value,
        )

        if not reasons:
            continue

        findings.append(
            SensitiveHeaderFinding(
                header_name=normalized_name,
                redacted_value=_redact_header_value(
                    normalized_name,
                    normalized_value,
                ),
                fingerprint_sha256=(
                    _fingerprint_header_value(
                        normalized_value,
                    )
                ),
                reasons=reasons,
            )
        )

    return tuple(
        sorted(
            findings,
            key=lambda finding: finding.header_name,
        )
    )


def _find_header_observations(
    headers: Mapping[str, str],
) -> tuple[HeaderObservation, ...]:
    """Classify non-credential information disclosures separately."""

    observations: list[HeaderObservation] = []

    for name, value in headers.items():
        normalized_name = name.lower().strip()
        normalized_value = value.strip()

        # Reporting headers contain benign opaque telemetry identifiers.
        if normalized_name in {
            "report-to",
            "reporting-endpoints",
            "nel",
        }:
            continue

        reasons: set[str] = set()
        category: str | None = None
        severity: str | None = None

        if PRIVATE_IP_PATTERN.search(normalized_value):
            category = "internal_infrastructure_disclosure"
            severity = "low"
            reasons.add("private_ip_disclosure")

        technology_header = (
            normalized_name in SENSITIVE_RESPONSE_HEADERS
            and TOKEN_CONTEXT_PATTERN.search(
                normalized_name
            )
            is None
        )

        if technology_header:
            category = (
                category
                or "technology_disclosure"
            )
            severity = severity or "informational"
            reasons.add("technology_header_disclosure")

        if VERSION_PATTERN.search(normalized_value):
            category = (
                category
                or "technology_disclosure"
            )
            severity = severity or "informational"
            reasons.add("software_version_disclosure")

        if not reasons or category is None or severity is None:
            continue

        observations.append(
            HeaderObservation(
                header_name=normalized_name,
                category=category,
                severity=severity,
                redacted_value=_redact_header_value(
                    normalized_name,
                    normalized_value,
                ),
                fingerprint_sha256=(
                    _fingerprint_header_value(
                        normalized_value,
                    )
                ),
                reasons=tuple(sorted(reasons)),
            )
        )

    return tuple(
        sorted(
            observations,
            key=lambda observation: (
                observation.category,
                observation.header_name,
            ),
        )
    )


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

    safe_response_headers = {
        header: _redact_header_value(
            header,
            normalized_headers[header],
        )
        for header in present_headers
    }

    return SecurityHeadersResult(
        target_url=target_url,
        status_code=status_code,
        present_headers=present_headers,
        missing_headers=missing_headers,
        response_headers=safe_response_headers,
        sensitive_headers=_find_sensitive_headers(
            normalized_headers,
        ),
        header_observations=_find_header_observations(
            normalized_headers,
        ),
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
            missing_headers=tuple(
                sorted(RECOMMENDED_SECURITY_HEADERS)
            ),
            response_headers={},
            sensitive_headers=(),
            error=str(exc),
        )
    finally:
        if owns_client:
            await client.aclose()
