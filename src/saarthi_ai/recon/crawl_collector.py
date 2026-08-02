"""Controlled ProjectDiscovery Katana collector for Phase 3D."""

from __future__ import annotations

import hashlib
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit
from uuid import uuid4

from pydantic import ValidationError

from saarthi_ai.execution.tool_runner import (
    KATANA_PROFILE,
    ToolRunnerError,
    resolve_executable,
    run_tool,
)
from saarthi_ai.recon.crawl_models import (
    CrawlCollectionResult,
    CrawlFormRecord,
    CrawlParameterRecord,
    CrawlToolRun,
    CrawlUrlRecord,
)
from saarthi_ai.recon.dns_collector import (
    DnsCollectionError,
    normalize_domain,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_EVIDENCE_ROOT = PROJECT_ROOT / "evidence" / "crawling"

MAX_DISCOVERED_URLS = 500
MAX_FORMS = 250
MAX_PARAMETERS_PER_RECORD = 100


class CrawlCollectionError(RuntimeError):
    """Raised when Phase 3D crawling cannot be completed."""


class CrawlInputError(CrawlCollectionError):
    """Raised when Phase 3C evidence is invalid or outside scope."""


def _display_path(path: Path) -> str:
    """Return a project-relative path when possible."""

    try:
        return str(path.resolve().relative_to(PROJECT_ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def _safe_stderr_excerpt(stderr: str) -> str | None:
    """Return bounded stderr suitable for evidence metadata."""

    value = stderr.strip()
    return value[:2_000] if value else None


def _is_hostname_in_scope(hostname: str, domain: str) -> bool:
    """Check whether a hostname belongs to the approved parent domain."""

    return hostname == domain or hostname.endswith(f".{domain}")


def _normalize_http_url(
    value: object,
    domain: str,
) -> str | None:
    """Normalize one HTTP(S) URL and enforce parent-domain scope."""

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

    default_port = (parsed.scheme.lower() == "http" and port == 80) or (
        parsed.scheme.lower() == "https" and port == 443
    )

    netloc = hostname

    if port is not None and not default_port:
        netloc = f"{hostname}:{port}"

    path = parsed.path or "/"

    return urlunsplit(
        (
            parsed.scheme.lower(),
            netloc,
            path,
            parsed.query,
            "",
        )
    )


def _load_http_intelligence_evidence(
    evidence_path: Path,
) -> tuple[str, list[str], list[str], str | None, str | None]:
    """Load and validate Phase 3C HTTP intelligence evidence."""

    if not evidence_path.is_file():
        raise CrawlInputError(f"HTTP intelligence evidence file does not exist: {evidence_path}")

    try:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CrawlInputError(f"Unable to read HTTP intelligence evidence: {exc}") from exc

    if not isinstance(payload, dict):
        raise CrawlInputError("HTTP intelligence evidence must contain a JSON object.")

    try:
        domain = normalize_domain(str(payload.get("domain", "")))
    except DnsCollectionError as exc:
        raise CrawlInputError(
            "HTTP intelligence evidence contains an invalid parent domain."
        ) from exc

    records = payload.get("records")

    if not isinstance(records, list):
        raise CrawlInputError("HTTP intelligence evidence does not contain a records list.")

    approved: set[str] = set()
    rejected: set[str] = set()

    for record in records:
        if not isinstance(record, dict):
            rejected.add(str(record))
            continue

        raw_url = record.get("url")
        normalized_url = _normalize_http_url(raw_url, domain)

        if normalized_url is None:
            if raw_url is not None:
                rejected.add(str(raw_url))
            continue

        approved.add(normalized_url)

    if not approved:
        raise CrawlInputError("HTTP intelligence evidence contains no valid in-scope URLs.")

    source_execution_id = payload.get("collector_execution_id")
    source_evidence_id = payload.get("collector_evidence_id")

    return (
        domain,
        sorted(approved),
        sorted(rejected),
        source_execution_id if isinstance(source_execution_id, str) else None,
        source_evidence_id if isinstance(source_evidence_id, str) else None,
    )


def _extract_endpoint(payload: dict[str, Any]) -> str | None:
    """Extract the crawled endpoint from one Katana JSON object."""

    request = payload.get("request")

    if isinstance(request, dict):
        endpoint = request.get("endpoint")

        if isinstance(endpoint, str) and endpoint.strip():
            return endpoint.strip()

    url = payload.get("url")

    if isinstance(url, str) and url.strip():
        return url.strip()

    return None


def _extract_method(payload: dict[str, Any]) -> str:
    """Extract and normalize the HTTP method."""

    request = payload.get("request")

    if isinstance(request, dict):
        method = request.get("method")

        if isinstance(method, str) and method.strip():
            return method.strip().upper()[:16]

    method = payload.get("method")

    if isinstance(method, str) and method.strip():
        return method.strip().upper()[:16]

    return "GET"


def _extract_response(
    payload: dict[str, Any],
) -> tuple[int | None, str | None]:
    """Extract bounded response metadata without storing response bodies."""

    response = payload.get("response")

    if not isinstance(response, dict):
        return None, None

    status_code = response.get("status_code")

    if not isinstance(status_code, int):
        status_code = payload.get("statuscode")

    if not isinstance(status_code, int):
        status_code = None

    content_type = None
    headers = response.get("headers")

    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() == "content-type":
                content_type = str(value).strip()[:500] or None
                break

    return status_code, content_type


def _query_parameters(url: str) -> list[CrawlParameterRecord]:
    """Create parameter records from a URL query string."""

    parsed = urlsplit(url)
    parameters: list[CrawlParameterRecord] = []

    for name, value in parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )[:MAX_PARAMETERS_PER_RECORD]:
        parameters.append(
            CrawlParameterRecord(
                name=name[:500],
                location="query",
                value=value[:2_000],
            )
        )

    return parameters


def _normalize_form_fields(
    form: dict[str, Any],
) -> list[CrawlParameterRecord]:
    """Normalize form fields across supported Katana JSON variants."""

    raw_fields: object = form.get("parameters") or form.get("inputs") or form.get("fields")

    if not isinstance(raw_fields, list):
        return []

    parameters: list[CrawlParameterRecord] = []

    for field in raw_fields[:MAX_PARAMETERS_PER_RECORD]:
        if isinstance(field, str):
            name = field.strip()

            if name:
                parameters.append(
                    CrawlParameterRecord(
                        name=name[:500],
                        location="form",
                    )
                )

            continue

        if not isinstance(field, dict):
            continue

        raw_name = field.get("name") or field.get("key") or field.get("id")

        if not isinstance(raw_name, str) or not raw_name.strip():
            continue

        raw_value = field.get("value")

        parameters.append(
            CrawlParameterRecord(
                name=raw_name.strip()[:500],
                location="form",
                value=(str(raw_value)[:2_000] if raw_value is not None else None),
            )
        )

    return parameters


def _parse_forms(
    payload: dict[str, Any],
    *,
    page_url: str,
    domain: str,
) -> tuple[list[CrawlFormRecord], list[str]]:
    """Normalize top-level Katana form extraction results."""

    raw_forms = payload.get("forms")

    if isinstance(raw_forms, dict):
        raw_forms = [raw_forms]

    if not isinstance(raw_forms, list):
        return [], []

    forms: list[CrawlFormRecord] = []
    rejected: list[str] = []

    for raw_form in raw_forms:
        if len(forms) >= MAX_FORMS:
            break

        if not isinstance(raw_form, dict):
            continue

        raw_action = raw_form.get("action") or raw_form.get("action_url") or page_url

        action_url = _normalize_http_url(raw_action, domain)

        if action_url is None:
            rejected.append(str(raw_action))
            continue

        method = str(raw_form.get("method") or "GET").strip().upper()

        forms.append(
            CrawlFormRecord(
                page_url=page_url,
                action_url=action_url,
                method=method[:16] or "GET",
                parameters=_normalize_form_fields(raw_form),
            )
        )

    return forms, rejected


def _parse_record(
    payload: dict[str, Any],
    domain: str,
) -> tuple[CrawlUrlRecord | None, list[CrawlFormRecord], list[str]]:
    """Normalize one Katana JSONL result."""

    raw_endpoint = _extract_endpoint(payload)
    endpoint = _normalize_http_url(raw_endpoint, domain)

    if endpoint is None:
        rejected = [str(raw_endpoint)] if raw_endpoint else []
        return None, [], rejected

    parsed = urlsplit(endpoint)

    if parsed.hostname is None:
        return None, [], [endpoint]

    source_value = payload.get("source")

    source_url = (
        _normalize_http_url(source_value, domain) if isinstance(source_value, str) else None
    )

    status_code, content_type = _extract_response(payload)
    parameters = _query_parameters(endpoint)

    forms, rejected_forms = _parse_forms(
        payload,
        page_url=endpoint,
        domain=domain,
    )

    suffix = parsed.path.lower()
    is_javascript = suffix.endswith((".js", ".mjs", ".cjs"))
    is_websocket = parsed.scheme.lower() in {"ws", "wss"}

    record = CrawlUrlRecord(
        url=endpoint,
        scheme=parsed.scheme.lower(),
        host=normalize_domain(parsed.hostname),
        port=parsed.port,
        path=parsed.path or "/",
        query=parsed.query or None,
        fragment=None,
        method=_extract_method(payload),
        source_url=source_url,
        status_code=status_code,
        content_type=content_type,
        parameters=parameters,
        is_javascript=is_javascript,
        is_websocket=is_websocket,
        metadata={
            "depth": payload.get("depth") if isinstance(payload.get("depth"), int) else None,
            "tag": payload.get("tag") if isinstance(payload.get("tag"), str) else None,
            "technologies": payload.get("technologies")
            if isinstance(payload.get("technologies"), list)
            else [],
        },
    )

    return record, forms, rejected_forms


def _write_evidence(
    result: CrawlCollectionResult,
    evidence_file: Path,
) -> tuple[str, int]:
    """Write normalized evidence atomically and return hash and size."""

    evidence_file.parent.mkdir(parents=True, exist_ok=True)
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


def collect_crawl_intelligence(
    source_evidence_path: Path,
    *,
    evidence_root: Path | None = None,
) -> CrawlCollectionResult:
    """Crawl approved Phase 3C live URLs using controlled Katana."""

    (
        domain,
        input_urls,
        rejected_inputs,
        source_execution_id,
        source_evidence_id,
    ) = _load_http_intelligence_evidence(source_evidence_path)

    executable = resolve_executable(KATANA_PROFILE)

    if executable is None:
        raise CrawlCollectionError("Approved ProjectDiscovery Katana executable is not installed.")

    collector_execution_id = f"crawl-run-{uuid4()}"
    collector_evidence_id = f"crawl-evidence-{uuid4()}"
    collected_at = datetime.now(UTC)

    evidence_directory = evidence_root or DEFAULT_EVIDENCE_ROOT
    evidence_file = evidence_directory / f"{collector_evidence_id}.json"

    malformed_line_count = 0
    rejected_results: set[str] = set()
    records_by_url: dict[str, CrawlUrlRecord] = {}
    forms_by_key: dict[tuple[str, str, str], CrawlFormRecord] = {}

    with tempfile.TemporaryDirectory(
        prefix="saarthi-katana-",
    ) as temporary_directory:
        input_file = Path(temporary_directory) / "approved-live-urls.txt"
        input_file.write_text(
            "\n".join(input_urls) + "\n",
            encoding="utf-8",
        )

        arguments = [
            "-list",
            str(input_file),
            "-jsonl",
            "-silent",
            "-no-color",
            "-depth",
            "2",
            "-crawl-duration",
            "20s",
            "-js-crawl",
            "-form-extraction",
            "-field-scope",
            "fqdn",
            "-concurrency",
            "5",
            "-parallelism",
            "2",
            "-rate-limit",
            "2",
            "-timeout",
            "10",
            "-max-response-size",
            "1048576",
        ]

        try:
            tool_result = run_tool(
                KATANA_PROFILE,
                arguments,
            )
        except ToolRunnerError as exc:
            raise CrawlCollectionError(str(exc)) from exc

    tool_run = CrawlToolRun(
        tool_name=tool_result.tool_name,
        available=True,
        executable=tool_result.executable,
        arguments=list(tool_result.arguments),
        exit_code=tool_result.exit_code,
        timed_out=tool_result.timed_out,
        stdout_sha256=tool_result.stdout_sha256,
        stderr_sha256=tool_result.stderr_sha256,
        stderr_excerpt=_safe_stderr_excerpt(tool_result.stderr),
    )

    if tool_result.timed_out:
        raise CrawlCollectionError("ProjectDiscovery Katana timed out.")

    if tool_result.exit_code != 0:
        raise CrawlCollectionError(
            f"ProjectDiscovery Katana exited unsuccessfully: {tool_result.exit_code}"
        )

    for line in tool_result.stdout.splitlines():
        stripped = line.strip()

        if not stripped:
            continue

        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            malformed_line_count += 1
            continue

        if not isinstance(payload, dict):
            malformed_line_count += 1
            continue

        try:
            record, forms, rejected_forms = _parse_record(
                payload,
                domain,
            )
        except (ValidationError, DnsCollectionError, ValueError):
            malformed_line_count += 1
            continue

        rejected_results.update(rejected_forms)

        if record is None:
            endpoint = _extract_endpoint(payload)

            if endpoint:
                rejected_results.add(endpoint)

            continue

        if record.url not in records_by_url and len(records_by_url) >= MAX_DISCOVERED_URLS:
            rejected_results.add(f"output-cap:{record.url}")
            continue

        records_by_url.setdefault(record.url, record)

        for form in forms:
            if len(forms_by_key) >= MAX_FORMS:
                break

            key = (
                form.page_url,
                form.action_url,
                form.method,
            )
            forms_by_key.setdefault(key, form)

    records = sorted(
        records_by_url.values(),
        key=lambda item: (
            item.host,
            item.path,
            item.query or "",
            item.method,
        ),
    )

    forms = sorted(
        forms_by_key.values(),
        key=lambda item: (
            item.page_url,
            item.action_url,
            item.method,
        ),
    )

    parameter_count = sum(len(record.parameters) for record in records) + sum(
        len(form.parameters) for form in forms
    )

    provisional = CrawlCollectionResult(
        collector_execution_id=collector_execution_id,
        collector_evidence_id=collector_evidence_id,
        source_evidence_path=_display_path(source_evidence_path),
        source_collector_execution_id=source_execution_id,
        source_collector_evidence_id=source_evidence_id,
        domain=domain,
        input_service_count=len(input_urls),
        crawled_service_count=len({record.host for record in records}),
        discovered_url_count=len(records),
        form_count=len(forms),
        parameter_count=parameter_count,
        javascript_url_count=sum(record.is_javascript for record in records),
        websocket_url_count=sum(record.is_websocket for record in records),
        malformed_line_count=malformed_line_count,
        rejected_inputs=rejected_inputs,
        rejected_results=sorted(rejected_results),
        urls=records,
        forms=forms,
        tool_runs=[tool_run],
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
