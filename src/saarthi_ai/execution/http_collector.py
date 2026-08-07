from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from uuid import uuid4

import httpx

from saarthi_ai.assessments.schemas import AssetType
from saarthi_ai.assessments.scope import (
    ScopeValidationError,
    normalize_url,
    validate_assessment,
)
from saarthi_ai.config import tls_verify
from saarthi_ai.execution.http_models import (
    HttpMetadataCollectionRequest,
    HttpMetadataCollectionResponse,
    RedirectHop,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_EVIDENCE_ROOT = PROJECT_ROOT / "evidence/http"

REDIRECT_STATUS_CODES = {
    301,
    302,
    303,
    307,
    308,
}

SENSITIVE_RESPONSE_HEADERS = {
    "set-cookie",
    "proxy-authenticate",
    "www-authenticate",
}


class HttpCollectionError(RuntimeError):
    """Base error for controlled HTTP metadata collection."""


class HttpCollectionScopeError(HttpCollectionError):
    """Raised when a request or redirect leaves authorized scope."""


class HttpCollectionNetworkError(HttpCollectionError):
    """Raised when the authorized target cannot be reached safely."""


def effective_port(url: str) -> int | None:
    """Return the explicit or default port used by a URL."""

    parsed = urlsplit(url)

    if parsed.port is not None:
        return parsed.port

    if parsed.scheme.lower() == "https":
        return 443

    if parsed.scheme.lower() == "http":
        return 80

    return None


def same_origin(first_url: str, second_url: str) -> bool:
    """Check whether two URLs use the same scheme, hostname, and port."""

    first = urlsplit(first_url)
    second = urlsplit(second_url)

    return (
        first.scheme.lower(),
        first.hostname,
        effective_port(first_url),
    ) == (
        second.scheme.lower(),
        second.hostname,
        effective_port(second_url),
    )


def url_is_within_base(candidate_url: str, base_url: str) -> bool:
    """Check whether a candidate URL is inside an excluded URL base."""

    candidate = urlsplit(candidate_url)
    base = urlsplit(base_url)

    if not same_origin(candidate_url, base_url):
        return False

    candidate_path = candidate.path.rstrip("/") or "/"
    base_path = base.path.rstrip("/") or "/"

    if base_path == "/":
        return True

    return candidate_path == base_path or candidate_path.startswith(f"{base_path}/")


def sanitize_headers(headers: httpx.Headers) -> dict[str, str]:
    """Redact sensitive response-header values before storage."""

    sanitized: dict[str, str] = {}

    for name, value in headers.items():
        normalized_name = name.lower()

        if normalized_name in SENSITIVE_RESPONSE_HEADERS:
            sanitized[normalized_name] = "<redacted>"
        else:
            sanitized[normalized_name] = value

    return dict(sorted(sanitized.items()))


def validate_target_credentials(target: str) -> None:
    """Reject credentials embedded directly in a target URL."""

    parsed = urlsplit(target)

    if parsed.username is not None or parsed.password is not None:
        raise HttpCollectionScopeError("Credentials embedded in target URLs are not permitted.")


def normalize_redirect_url(current_url: str, location: str) -> str:
    """Resolve and normalize a redirect location."""

    redirect_candidate = urljoin(current_url, location)

    try:
        return normalize_url(redirect_candidate)
    except ScopeValidationError as exc:
        raise HttpCollectionScopeError(f"Invalid redirect URL: {redirect_candidate}") from exc


def validate_collection_target(
    request: HttpMetadataCollectionRequest,
) -> tuple[str, list[str]]:
    """Confirm that the requested URL exactly matches authorized scope."""

    validated = validate_assessment(request.assessment)

    allowed_targets = {
        target.normalized_value
        for target in validated.targets
        if target.asset_type in {AssetType.WEB, AssetType.API}
    }

    if not allowed_targets:
        raise HttpCollectionScopeError("HTTP metadata collection requires a Web or API target.")

    try:
        normalized_target = normalize_url(request.target)
    except ScopeValidationError as exc:
        raise HttpCollectionScopeError(str(exc)) from exc

    validate_target_credentials(normalized_target)

    if normalized_target not in allowed_targets:
        raise HttpCollectionScopeError(
            "The requested URL does not exactly match an authorized assessment target."
        )

    normalized_exclusions: list[str] = []

    for excluded_target in request.assessment.excluded_targets:
        try:
            normalized_exclusions.append(normalize_url(excluded_target))
        except ScopeValidationError:
            continue

    return normalized_target, normalized_exclusions


def ensure_redirect_is_allowed(
    original_target: str,
    redirect_url: str,
    exclusions: list[str],
) -> None:
    """Require redirects to remain on the original authorized origin."""

    validate_target_credentials(redirect_url)

    if not same_origin(original_target, redirect_url):
        raise HttpCollectionScopeError(
            f"Cross-origin redirect blocked: {original_target} -> {redirect_url}"
        )

    for excluded_url in exclusions:
        if url_is_within_base(redirect_url, excluded_url):
            raise HttpCollectionScopeError(f"Redirect entered excluded scope: {redirect_url}")


async def read_limited_body(
    response: httpx.Response,
    *,
    max_body_bytes: int,
) -> tuple[bytes, bool]:
    """Read no more than the approved number of response bytes."""

    collected = bytearray()
    truncated = False

    async for chunk in response.aiter_bytes():
        remaining = max_body_bytes - len(collected)

        if remaining <= 0:
            truncated = True
            break

        if len(chunk) > remaining:
            collected.extend(chunk[:remaining])
            truncated = True
            break

        collected.extend(chunk)

    return bytes(collected), truncated


def evidence_display_path(evidence_path: Path) -> str:
    """Return a project-relative evidence path when possible."""

    try:
        return str(evidence_path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(evidence_path)


def write_evidence(
    response: HttpMetadataCollectionResponse,
    evidence_root: Path,
) -> None:
    """Write evidence atomically as structured JSON."""

    evidence_root.mkdir(parents=True, exist_ok=True)

    evidence_path = evidence_root / f"{response.evidence_id}.json"
    temporary_path = evidence_path.with_suffix(".tmp")

    payload = response.model_dump(mode="json")

    with temporary_path.open("w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, ensure_ascii=False)
        file.write("\n")

    temporary_path.replace(evidence_path)


async def collect_http_metadata(
    request: HttpMetadataCollectionRequest,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    evidence_root: Path | None = None,
) -> HttpMetadataCollectionResponse:
    """Collect low-risk HTTP metadata from one authorized target."""

    target, exclusions = validate_collection_target(request)

    evidence_directory = evidence_root or DEFAULT_EVIDENCE_ROOT
    execution_id = f"http-exec-{uuid4()}"
    evidence_id = f"http-evidence-{uuid4()}"

    evidence_file = evidence_directory / f"{evidence_id}.json"

    timeout = httpx.Timeout(
        timeout=request.timeout_seconds,
        connect=request.timeout_seconds,
        read=request.timeout_seconds,
        write=request.timeout_seconds,
        pool=request.timeout_seconds,
    )

    limits = httpx.Limits(
        max_connections=1,
        max_keepalive_connections=0,
    )

    redirect_chain: list[RedirectHop] = []
    current_url = target

    request_delay = 1 / request.assessment.rate_limit_per_second

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
            verify=tls_verify(),
            headers={
                "User-Agent": "Saarthi-AI/0.4 authorized-vapt",
                "Accept": "*/*",
            },
        ) as client:
            for redirect_number in range(request.max_redirects + 1):
                if redirect_number > 0:
                    await asyncio.sleep(request_delay)

                async with client.stream("GET", current_url) as response:
                    location = response.headers.get("location")

                    if response.status_code in REDIRECT_STATUS_CODES and location:
                        if redirect_number >= request.max_redirects:
                            raise HttpCollectionScopeError(
                                "Maximum approved redirect count exceeded."
                            )

                        redirect_url = normalize_redirect_url(
                            current_url,
                            location,
                        )

                        ensure_redirect_is_allowed(
                            target,
                            redirect_url,
                            exclusions,
                        )

                        redirect_chain.append(
                            RedirectHop(
                                url=current_url,
                                status_code=response.status_code,
                                location=redirect_url,
                            )
                        )

                        client.cookies.clear()
                        current_url = redirect_url
                        continue

                    body, truncated = await read_limited_body(
                        response,
                        max_body_bytes=request.max_body_bytes,
                    )

                    result = HttpMetadataCollectionResponse(
                        execution_id=execution_id,
                        evidence_id=evidence_id,
                        collected_at=datetime.now(UTC),
                        target=target,
                        final_url=str(response.url),
                        status_code=response.status_code,
                        http_version=response.http_version,
                        content_type=response.headers.get("content-type"),
                        headers=sanitize_headers(response.headers),
                        redirect_chain=redirect_chain,
                        body_bytes_captured=len(body),
                        body_truncated=truncated,
                        body_sha256=sha256(body).hexdigest(),
                        evidence_path=evidence_display_path(evidence_file),
                    )

                    write_evidence(result, evidence_directory)

                    return result

    except HttpCollectionScopeError:
        raise
    except (
        httpx.TimeoutException,
        httpx.NetworkError,
        httpx.ProtocolError,
    ) as exc:
        raise HttpCollectionNetworkError(f"Controlled HTTP request failed: {exc}") from exc

    raise HttpCollectionNetworkError("Controlled HTTP request ended without a response.")
