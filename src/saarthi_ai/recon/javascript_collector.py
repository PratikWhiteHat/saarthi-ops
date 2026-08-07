"""Controlled Phase 3E JavaScript intelligence collector."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit
from uuid import uuid4

import httpx

from saarthi_ai.config import tls_verify
from saarthi_ai.recon.dns_collector import (
    DnsCollectionError,
    normalize_domain,
)
from saarthi_ai.recon.javascript_models import (
    JavaScriptAssetRecord,
    JavaScriptCollectionResult,
    JavaScriptEndpointRecord,
    JavaScriptFetchRecord,
    JavaScriptParameterRecord,
    JavaScriptSecretCandidate,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_EVIDENCE_ROOT = PROJECT_ROOT / "evidence" / "javascript-intelligence"

MAX_JAVASCRIPT_ASSETS = 100
MAX_BODY_BYTES = 524_288
MAX_ENDPOINTS_PER_ASSET = 250
MAX_PARAMETERS_PER_ASSET = 250
MAX_SECRET_CANDIDATES_PER_ASSET = 50
FETCH_CONCURRENCY = 3
FETCH_TIMEOUT_SECONDS = 10.0

URL_PATTERN = re.compile(
    r"""(?P<quote>["'])
    (?P<value>
        (?:
            https?://
            |wss?://
            |/
        )
        [^"'\\\s]{2,2048}
    )
    (?P=quote)""",
    re.IGNORECASE | re.VERBOSE,
)

SOURCE_MAP_PATTERN = re.compile(
    r"sourceMappingURL\s*=\s*(?P<value>[^\s*]+)",
    re.IGNORECASE,
)

QUERY_PARAMETER_PATTERN = re.compile(
    r"[?&](?P<name>[A-Za-z_][A-Za-z0-9_.-]{0,63})=",
)

SEARCH_PARAM_PATTERN = re.compile(
    r"""(?ix)
    \.
    (?:get|set|append|delete|has|getAll)
    \(
    \s*["']
    (?P<name>[A-Za-z_][A-Za-z0-9_.-]{0,63})
    ["']
    """
)

BRACKET_PARAMETER_PATTERN = re.compile(
    r"""(?ix)
    \b(?:params?|query|searchParams|body|payload)
    \s*\[
    \s*["']
    (?P<name>[A-Za-z_][A-Za-z0-9_.-]{0,63})
    ["']
    \s*\]
    """
)

OBJECT_PARAMETER_PATTERN = re.compile(
    r"""(?isx)
    \b(?:params?|query|body|payload)
    \s*[:=]
    \s*\{
    (?P<body>.{0,2000}?)
    \}
    """
)

OBJECT_KEY_PATTERN = re.compile(
    r"""(?ix)
    (?:
        ["'](?P<quoted>[A-Za-z_][A-Za-z0-9_.-]{0,63})["']
        |
        (?P<plain>[A-Za-z_][A-Za-z0-9_.-]{0,63})
    )
    \s*:
    """
)

PARAMETER_STOP_WORDS = {
    "function",
    "object",
    "string",
    "boolean",
    "number",
    "null",
    "undefined",
    "default",
    "void",
    "class",
    "new",
    "delete",
    "return",
    "this",
    "true",
    "false",
    "error",
    "document",
    "window",
    "prototype",
    "constructor",
}


SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "aws-access-key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "high",
    ),
    (
        "generic-api-key",
        re.compile(
            r"""(?ix)
            \b(?:api[_-]?key|secret|token|client[_-]?secret)
            \s*[:=]\s*
            ["'](?P<secret>[A-Za-z0-9_./+=-]{16,256})["']
            """
        ),
        "medium",
    ),
    (
        "bearer-token",
        re.compile(
            r"""(?ix)
            \bbearer\s+(?P<secret>[A-Za-z0-9._~+/=-]{20,512})
            """
        ),
        "medium",
    ),
)

FRAMEWORK_MARKERS = {
    "React": (
        "react.production.min",
        "react-dom",
        "__react",
    ),
    "Angular": (
        "ng-version",
        "angular.module",
        "zone.js",
    ),
    "Vue": (
        "__vue__",
        "createapp(",
        "vue.runtime",
    ),
    "Next.js": (
        "__next_data__",
        "/_next/",
    ),
    "Keycloak": (
        "keycloak",
        "keycloak-js",
    ),
    "Webpack": (
        "__webpack_require__",
        "webpackchunk",
    ),
    "Vite": (
        "import.meta.env",
        "/@vite/",
    ),
}


class JavaScriptCollectionError(RuntimeError):
    """Raised when Phase 3E collection cannot be completed."""


class JavaScriptInputError(JavaScriptCollectionError):
    """Raised when Phase 3D evidence is invalid or outside scope."""


def _display_path(path: Path) -> str:
    """Return a project-relative path when possible."""

    try:
        return str(path.resolve().relative_to(PROJECT_ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def _is_hostname_in_scope(hostname: str, domain: str) -> bool:
    """Check whether a hostname belongs to the approved parent domain."""

    return hostname == domain or hostname.endswith(f".{domain}")


def _normalize_http_url(
    value: object,
    domain: str,
) -> str | None:
    """Normalize an HTTP(S) URL and enforce parent-domain scope."""

    if not isinstance(value, str):
        return None

    candidate = value.strip()

    if not candidate:
        return None

    parsed = urlsplit(candidate)

    if parsed.scheme.lower() not in {"http", "https"}:
        return None

    if parsed.hostname is None:
        return None

    try:
        hostname = normalize_domain(parsed.hostname)
    except DnsCollectionError:
        return None

    if not _is_hostname_in_scope(hostname, domain):
        return None

    try:
        port = parsed.port
    except ValueError:
        return None

    netloc = hostname

    default_port = (parsed.scheme.lower() == "http" and port == 80) or (
        parsed.scheme.lower() == "https" and port == 443
    )

    if port is not None and not default_port:
        netloc = f"{hostname}:{port}"

    return urlunsplit(
        (
            parsed.scheme.lower(),
            netloc,
            parsed.path or "/",
            parsed.query,
            "",
        )
    )


def _load_crawl_evidence(
    evidence_path: Path,
) -> tuple[str, list[str], list[str], str | None, str | None]:
    """Load JavaScript URLs from Phase 3D crawl evidence."""

    if not evidence_path.is_file():
        raise JavaScriptInputError(f"Crawl evidence file does not exist: {evidence_path}")

    try:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise JavaScriptInputError(f"Unable to read crawl evidence: {exc}") from exc

    if not isinstance(payload, dict):
        raise JavaScriptInputError("Crawl evidence must contain a JSON object.")

    try:
        domain = normalize_domain(str(payload.get("domain", "")))
    except DnsCollectionError as exc:
        raise JavaScriptInputError("Crawl evidence contains an invalid parent domain.") from exc

    records = payload.get("urls")

    if not isinstance(records, list):
        raise JavaScriptInputError("Crawl evidence does not contain a urls list.")

    approved: set[str] = set()
    rejected: set[str] = set()

    for record in records:
        if not isinstance(record, dict):
            rejected.add(str(record))
            continue

        if record.get("is_javascript") is not True:
            continue

        raw_url = record.get("url")
        normalized_url = _normalize_http_url(raw_url, domain)

        if normalized_url is None:
            if raw_url is not None:
                rejected.add(str(raw_url))
            continue

        approved.add(normalized_url)

    if not approved:
        raise JavaScriptInputError("Crawl evidence contains no valid in-scope JavaScript URLs.")

    source_execution_id = payload.get("collector_execution_id")
    source_evidence_id = payload.get("collector_evidence_id")

    return (
        domain,
        sorted(approved)[:MAX_JAVASCRIPT_ASSETS],
        sorted(rejected),
        source_execution_id if isinstance(source_execution_id, str) else None,
        source_evidence_id if isinstance(source_evidence_id, str) else None,
    )


async def _read_limited_body(
    response: httpx.Response,
) -> tuple[bytes, bool]:
    """Read no more than the approved JavaScript body limit."""

    collected = bytearray()
    truncated = False

    async for chunk in response.aiter_bytes():
        remaining = MAX_BODY_BYTES - len(collected)

        if remaining <= 0:
            truncated = True
            break

        if len(chunk) > remaining:
            collected.extend(chunk[:remaining])
            truncated = True
            break

        collected.extend(chunk)

    return bytes(collected), truncated


def _redacted_preview(secret: str) -> str:
    """Return a non-reversible bounded preview."""

    if len(secret) <= 8:
        return "<redacted>"

    return f"{secret[:4]}…{secret[-4:]}"


def _redact_detected_secrets(text: str) -> str:
    """Remove detected secret values before other intelligence extraction."""

    sanitized = text

    for _, pattern, _ in SECRET_PATTERNS:

        def replace(match: re.Match[str]) -> str:
            secret = match.groupdict().get("secret") or match.group(0)

            if secret == match.group(0):
                return "<redacted-secret>"

            return match.group(0).replace(
                secret,
                "<redacted-secret>",
            )

        sanitized = pattern.sub(replace, sanitized)

    return sanitized


def _extract_secret_candidates(
    text: str,
    source_url: str,
) -> list[JavaScriptSecretCandidate]:
    """Extract redacted candidate-secret metadata."""

    results: dict[tuple[str, str], JavaScriptSecretCandidate] = {}

    for secret_type, pattern, confidence in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            secret = match.groupdict().get("secret") or match.group(0)

            fingerprint = hashlib.sha256(secret.encode("utf-8", errors="ignore")).hexdigest()

            key = (secret_type, fingerprint)

            results.setdefault(
                key,
                JavaScriptSecretCandidate(
                    secret_type=secret_type,
                    source_url=source_url,
                    fingerprint_sha256=fingerprint,
                    redacted_preview=_redacted_preview(secret),
                    confidence=confidence,
                ),
            )

            if len(results) >= MAX_SECRET_CANDIDATES_PER_ASSET:
                return list(results.values())

    return list(results.values())


def _extract_frameworks(text: str) -> list[str]:
    """Identify common JavaScript framework markers."""

    lowered = text.lower()

    return sorted(
        framework
        for framework, markers in FRAMEWORK_MARKERS.items()
        if any(marker.lower() in lowered for marker in markers)
    )


def _endpoint_kind(value: str) -> str:
    """Classify one endpoint-like value."""

    lowered = value.lower()

    if lowered.startswith(("ws://", "wss://")):
        return "websocket"

    if "/api/" in lowered or lowered.startswith("/api"):
        return "api"

    if lowered.endswith((".js", ".mjs", ".cjs")):
        return "javascript"

    return "route"


def _extract_endpoints(
    text: str,
    source_url: str,
    domain: str,
) -> list[JavaScriptEndpointRecord]:
    """Extract bounded endpoint-like strings from JavaScript."""

    results: dict[str, JavaScriptEndpointRecord] = {}

    for match in URL_PATTERN.finditer(text):
        raw_value = match.group("value").rstrip(".,;)}]")

        if not raw_value:
            continue

        absolute_url = urljoin(source_url, raw_value)
        parsed = urlsplit(absolute_url)
        hostname = parsed.hostname

        in_scope = False

        if hostname is not None:
            try:
                normalized_host = normalize_domain(hostname)
                in_scope = _is_hostname_in_scope(
                    normalized_host,
                    domain,
                )
            except DnsCollectionError:
                in_scope = False

        results.setdefault(
            raw_value,
            JavaScriptEndpointRecord(
                value=raw_value[:2_048],
                kind=_endpoint_kind(raw_value),
                source_url=source_url,
                in_scope=in_scope,
                absolute_url=absolute_url[:2_048],
            ),
        )

        if len(results) >= MAX_ENDPOINTS_PER_ASSET:
            break

    return list(results.values())


def _extract_parameters(
    text: str,
    source_url: str,
) -> list[JavaScriptParameterRecord]:
    """Extract high-confidence request parameter names."""

    names: set[str] = set()

    for pattern in (
        QUERY_PARAMETER_PATTERN,
        SEARCH_PARAM_PATTERN,
        BRACKET_PARAMETER_PATTERN,
    ):
        for match in pattern.finditer(text):
            names.add(match.group("name"))

    for object_match in OBJECT_PARAMETER_PATTERN.finditer(text):
        object_body = object_match.group("body")

        for key_match in OBJECT_KEY_PATTERN.finditer(object_body):
            name = key_match.group("quoted") or key_match.group("plain")

            if name:
                names.add(name)

    filtered_names = sorted(
        name
        for name in names
        if name.lower() not in PARAMETER_STOP_WORDS
        and not name.startswith("__")
        and "." not in name
    )

    return [
        JavaScriptParameterRecord(
            name=name,
            source_url=source_url,
        )
        for name in filtered_names[:MAX_PARAMETERS_PER_ASSET]
    ]


def _extract_source_maps(
    text: str,
    source_url: str,
    domain: str,
) -> list[str]:
    """Extract in-scope source-map references."""

    results: set[str] = set()

    for match in SOURCE_MAP_PATTERN.finditer(text):
        candidate = match.group("value").strip().strip("\"'")
        absolute = urljoin(source_url, candidate)
        normalized = _normalize_http_url(absolute, domain)

        if normalized is not None:
            results.add(normalized)

    return sorted(results)


async def _fetch_one(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    url: str,
    domain: str,
) -> JavaScriptAssetRecord:
    """Fetch and analyze one approved JavaScript asset."""

    async with semaphore:
        try:
            async with client.stream(
                "GET",
                url,
                follow_redirects=False,
            ) as response:
                final_url = _normalize_http_url(
                    str(response.url),
                    domain,
                )

                if final_url is None:
                    raise JavaScriptCollectionError(
                        f"Response URL left approved scope: {response.url}"
                    )

                content_type = response.headers.get("content-type")

                body, truncated = await _read_limited_body(response)

                fetch = JavaScriptFetchRecord(
                    url=url,
                    final_url=final_url,
                    status_code=response.status_code,
                    content_type=content_type,
                    content_length=(
                        int(response.headers["content-length"])
                        if response.headers.get(
                            "content-length",
                            "",
                        ).isdigit()
                        else None
                    ),
                    body_bytes_captured=len(body),
                    body_truncated=truncated,
                    body_sha256=hashlib.sha256(body).hexdigest(),
                )

                if response.status_code != 200:
                    return JavaScriptAssetRecord(fetch=fetch)

                text = body.decode(
                    "utf-8",
                    errors="replace",
                )

                secret_candidates = _extract_secret_candidates(
                    text,
                    final_url,
                )
                sanitized_text = _redact_detected_secrets(text)

                endpoints = _extract_endpoints(
                    sanitized_text,
                    final_url,
                    domain,
                )

                websocket_urls = sorted(
                    {
                        endpoint.absolute_url
                        for endpoint in endpoints
                        if endpoint.kind == "websocket" and endpoint.absolute_url is not None
                    }
                )

                return JavaScriptAssetRecord(
                    fetch=fetch,
                    endpoints=endpoints,
                    parameters=_extract_parameters(
                        sanitized_text,
                        final_url,
                    ),
                    websocket_urls=websocket_urls,
                    source_map_urls=_extract_source_maps(
                        text,
                        final_url,
                        domain,
                    ),
                    secret_candidates=secret_candidates,
                    framework_indicators=_extract_frameworks(text),
                )

        except (
            httpx.HTTPError,
            JavaScriptCollectionError,
            OSError,
        ) as exc:
            return JavaScriptAssetRecord(
                fetch=JavaScriptFetchRecord(
                    url=url,
                    error=str(exc)[:2_000],
                )
            )


def _write_evidence(
    result: JavaScriptCollectionResult,
    evidence_file: Path,
) -> tuple[str, int]:
    """Write structured evidence atomically."""

    evidence_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    temporary_file = evidence_file.with_suffix(".tmp")

    payload = result.model_dump(
        mode="json",
        exclude={
            "evidence_sha256",
            "evidence_size_bytes",
        },
    )

    serialized = (
        json.dumps(
            payload,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")

    temporary_file.write_bytes(serialized)
    temporary_file.replace(evidence_file)

    return hashlib.sha256(serialized).hexdigest(), len(serialized)


async def collect_javascript_intelligence(
    source_evidence_path: Path,
    *,
    evidence_root: Path | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    progress_callback: Callable[
        [JavaScriptAssetRecord],
        None,
    ]
    | None = None,
) -> JavaScriptCollectionResult:
    """Analyze approved Phase 3D JavaScript assets."""

    (
        domain,
        javascript_urls,
        rejected_inputs,
        source_execution_id,
        source_evidence_id,
    ) = _load_crawl_evidence(source_evidence_path)

    collector_execution_id = f"javascript-run-{uuid4()}"
    collector_evidence_id = f"javascript-evidence-{uuid4()}"
    collected_at = datetime.now(UTC)

    evidence_directory = evidence_root or DEFAULT_EVIDENCE_ROOT
    evidence_file = evidence_directory / f"{collector_evidence_id}.json"

    timeout = httpx.Timeout(
        timeout=FETCH_TIMEOUT_SECONDS,
        connect=FETCH_TIMEOUT_SECONDS,
        read=FETCH_TIMEOUT_SECONDS,
        write=FETCH_TIMEOUT_SECONDS,
        pool=FETCH_TIMEOUT_SECONDS,
    )

    limits = httpx.Limits(
        max_connections=FETCH_CONCURRENCY,
        max_keepalive_connections=FETCH_CONCURRENCY,
    )

    semaphore = asyncio.Semaphore(FETCH_CONCURRENCY)

    assets: list[JavaScriptAssetRecord] = []

    async with httpx.AsyncClient(
        timeout=timeout,
        limits=limits,
        transport=transport,
        verify=tls_verify(),
        headers={
            "User-Agent": (
                "Saarthi-OPS/0.1 "
                "Authorized-JavaScript-Intelligence"
            ),
            "Accept": (
                "application/javascript, "
                "text/javascript, */*;q=0.1"
            ),
        },
    ) as client:
        tasks = [
            asyncio.create_task(
                _fetch_one(
                    client,
                    semaphore,
                    url,
                    domain,
                )
            )
            for url in javascript_urls
        ]

        for completed_task in asyncio.as_completed(tasks):
            asset = await completed_task
            assets.append(asset)

            if progress_callback is not None:
                try:
                    progress_callback(asset)
                except Exception:
                    # Display/audit failures must never interrupt collection.
                    pass

    fetched_count = sum(asset.fetch.status_code is not None for asset in assets)

    failed_count = sum(asset.fetch.error is not None for asset in assets)

    endpoint_count = sum(len(asset.endpoints) for asset in assets)
    parameter_count = sum(len(asset.parameters) for asset in assets)
    websocket_count = sum(len(asset.websocket_urls) for asset in assets)
    source_map_count = sum(len(asset.source_map_urls) for asset in assets)
    secret_candidate_count = sum(len(asset.secret_candidates) for asset in assets)

    provisional = JavaScriptCollectionResult(
        collector_execution_id=collector_execution_id,
        collector_evidence_id=collector_evidence_id,
        source_evidence_path=_display_path(source_evidence_path),
        source_collector_execution_id=source_execution_id,
        source_collector_evidence_id=source_evidence_id,
        domain=domain,
        input_javascript_count=len(javascript_urls),
        fetched_javascript_count=fetched_count,
        failed_fetch_count=failed_count,
        endpoint_count=endpoint_count,
        parameter_count=parameter_count,
        websocket_count=websocket_count,
        source_map_count=source_map_count,
        secret_candidate_count=secret_candidate_count,
        rejected_inputs=rejected_inputs,
        assets=sorted(
            assets,
            key=lambda asset: asset.fetch.url,
        ),
        collected_at=collected_at,
        evidence_path=_display_path(evidence_file),
        evidence_sha256="0" * 64,
        evidence_size_bytes=0,
    )

    evidence_sha256, evidence_size_bytes = _write_evidence(
        provisional,
        evidence_file,
    )

    return provisional.model_copy(
        update={
            "evidence_sha256": evidence_sha256,
            "evidence_size_bytes": evidence_size_bytes,
        }
    )
