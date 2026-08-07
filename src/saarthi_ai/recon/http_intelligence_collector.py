"""Controlled ProjectDiscovery httpx collector for Phase 3C."""

from __future__ import annotations

import hashlib
import json
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import ValidationError

from saarthi_ai.execution.tool_runner import (
    PD_HTTPX_PROFILE,
    ToolOutputEvent,
    ToolRunnerError,
    resolve_executable,
    run_tool,
)
from saarthi_ai.recon.dns_collector import (
    DnsCollectionError,
    normalize_domain,
)
from saarthi_ai.recon.http_intelligence_models import (
    HttpIntelligenceCollectionResult,
    HttpIntelligenceRecord,
    HttpIntelligenceToolRun,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_EVIDENCE_ROOT = PROJECT_ROOT / "evidence/http-intelligence"


class HttpIntelligenceCollectionError(RuntimeError):
    """Raised when Phase 3C intelligence collection cannot be completed."""


class HttpIntelligenceInputError(HttpIntelligenceCollectionError):
    """Raised when Phase 3B evidence is invalid or outside scope."""


def _display_path(path: Path) -> str:
    """Return a project-relative path when possible."""

    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def _is_hostname_in_scope(hostname: str, domain: str) -> bool:
    """Check whether a normalized hostname belongs to the parent domain."""

    return hostname == domain or hostname.endswith(f".{domain}")


def _normalize_input_hostname(
    value: object,
    domain: str,
) -> str | None:
    """Normalize one Phase 3B hostname and enforce domain scope."""

    if not isinstance(value, str):
        return None

    candidate = value.strip().lower().rstrip(".")

    if not candidate:
        return None

    try:
        normalized = normalize_domain(candidate)
    except DnsCollectionError:
        return None

    if not _is_hostname_in_scope(normalized, domain):
        return None

    return normalized


def _load_subdomain_evidence(
    evidence_path: Path,
) -> tuple[str, list[str], list[str], str | None, str | None]:
    """Load and validate Phase 3B evidence."""

    if not evidence_path.is_file():
        raise HttpIntelligenceInputError(
            f"Subdomain evidence file does not exist: {evidence_path}"
        )

    try:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HttpIntelligenceInputError(
            f"Unable to read subdomain evidence: {exc}"
        ) from exc

    if not isinstance(payload, dict):
        raise HttpIntelligenceInputError(
            "Subdomain evidence must contain a JSON object."
        )

    try:
        domain = normalize_domain(str(payload.get("domain", "")))
    except DnsCollectionError as exc:
        raise HttpIntelligenceInputError(
            "Subdomain evidence contains an invalid parent domain."
        ) from exc

    candidates = payload.get("candidates")

    if not isinstance(candidates, list):
        raise HttpIntelligenceInputError(
            "Subdomain evidence does not contain a candidates list."
        )

    approved: set[str] = set()
    rejected: set[str] = set()

    for candidate in candidates:
        if not isinstance(candidate, dict):
            rejected.add(str(candidate))
            continue

        raw_hostname = candidate.get("hostname")
        normalized = _normalize_input_hostname(
            raw_hostname,
            domain,
        )

        if normalized is None:
            if raw_hostname is not None:
                rejected.add(str(raw_hostname))
            continue

        approved.add(normalized)

    if not approved:
        raise HttpIntelligenceInputError(
            "Subdomain evidence contains no valid in-scope hostnames."
        )

    source_execution_id = payload.get("collector_execution_id")
    source_evidence_id = payload.get("collector_evidence_id")

    return (
        domain,
        sorted(approved),
        sorted(rejected),
        source_execution_id if isinstance(source_execution_id, str) else None,
        source_evidence_id if isinstance(source_evidence_id, str) else None,
    )


def _safe_stderr_excerpt(stderr: str) -> str | None:
    """Return bounded stderr suitable for evidence metadata."""

    value = stderr.strip()
    return value[:2_000] if value else None


def _extract_url(payload: dict[str, Any]) -> str | None:
    """Extract the best URL field from one httpx JSON result."""

    for key in ("url", "final_url", "location"):
        value = payload.get(key)

        if isinstance(value, str) and value.strip():
            return value.strip()

    return None


def _parse_record(
    payload: dict[str, Any],
    domain: str,
) -> HttpIntelligenceRecord | None:
    """Normalize one ProjectDiscovery httpx JSON object."""

    url = _extract_url(payload)

    if url is None:
        return None

    parsed = urlsplit(url)
    hostname = parsed.hostname

    if hostname is None:
        return None

    try:
        normalized_host = normalize_domain(hostname)
    except DnsCollectionError:
        return None

    if not _is_hostname_in_scope(normalized_host, domain):
        return None

    input_value = payload.get("input")

    if not isinstance(input_value, str) or not input_value.strip():
        input_value = normalized_host

    technologies = payload.get("tech")

    if not isinstance(technologies, list):
        technologies = []

    normalized_technologies = sorted(
        {
            str(item).strip()
            for item in technologies
            if str(item).strip()
        }
    )

    port = payload.get("port")

    if not isinstance(port, int):
        port = parsed.port

    status_code = payload.get("status_code")

    if not isinstance(status_code, int):
        status_code = None

    content_length = payload.get("content_length")

    if not isinstance(content_length, int):
        content_length = None

    redirect_chain = payload.get("chain")

    if not isinstance(redirect_chain, list):
        redirect_chain = []

    normalized_chain = [
        item
        for item in redirect_chain
        if isinstance(item, dict)
    ]

    tls_data = payload.get("tls")

    if not isinstance(tls_data, dict):
        tls_data = None

    final_url = payload.get("final_url")

    if not isinstance(final_url, str):
        final_url = None

    return HttpIntelligenceRecord(
        input=input_value.strip(),
        url=url,
        scheme=parsed.scheme.lower(),
        host=normalized_host,
        port=port,
        status_code=status_code,
        title=payload.get("title") if isinstance(payload.get("title"), str) else None,
        technologies=normalized_technologies,
        webserver=(
            payload.get("webserver")
            if isinstance(payload.get("webserver"), str)
            else None
        ),
        content_length=content_length,
        ip=payload.get("host_ip") if isinstance(payload.get("host_ip"), str) else (
            payload.get("ip") if isinstance(payload.get("ip"), str) else None
        ),
        final_url=final_url,
        redirect_chain=normalized_chain,
        tls=tls_data,
    )


def _write_evidence(
    result: HttpIntelligenceCollectionResult,
    evidence_file: Path,
) -> tuple[str, int]:
    """Write structured evidence atomically and return file hash and size."""

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


def collect_http_intelligence(
    source_evidence_path: Path,
    *,
    evidence_root: Path | None = None,
    progress_callback: Callable[
        [HttpIntelligenceRecord],
        None,
    ]
    | None = None,
) -> HttpIntelligenceCollectionResult:
    """Probe Phase 3B hostnames with allowlisted ProjectDiscovery httpx."""

    (
        domain,
        hostnames,
        rejected_inputs,
        source_execution_id,
        source_evidence_id,
    ) = _load_subdomain_evidence(source_evidence_path)

    executable = resolve_executable(PD_HTTPX_PROFILE)

    if executable is None:
        raise HttpIntelligenceCollectionError(
            "Approved ProjectDiscovery httpx executable is not installed."
        )

    collector_execution_id = f"http-intelligence-run-{uuid4()}"
    collector_evidence_id = f"http-intelligence-evidence-{uuid4()}"
    collected_at = datetime.now(UTC)

    evidence_directory = evidence_root or DEFAULT_EVIDENCE_ROOT
    evidence_file = evidence_directory / f"{collector_evidence_id}.json"

    malformed_line_count = 0
    rejected_results: set[str] = set()
    records_by_url: dict[str, HttpIntelligenceRecord] = {}

    with tempfile.TemporaryDirectory(
        prefix="saarthi-httpx-",
    ) as temporary_directory:
        input_file = Path(temporary_directory) / "approved-hosts.txt"
        input_file.write_text(
            "\n".join(hostnames) + "\n",
            encoding="utf-8",
        )

        arguments = [
            "-list",
            str(input_file),
            "-json",
            "-silent",
            "-no-color",
            "-status-code",
            "-title",
            "-tech-detect",
            "-content-length",
            "-ip",
            "-tls-grab",
            "-follow-redirects",
            "-include-chain",
            "-threads",
            "10",
            "-rate-limit",
            "2",
            "-timeout",
            "10",
            "-retries",
            "1",
        ]

        def emit_progress(event: ToolOutputEvent) -> None:
            """Forward only parsed, valid and in-scope httpx records."""

            if progress_callback is None:
                return

            if event.stream != "stdout":
                return

            stripped = event.line.strip()

            if not stripped:
                return

            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError:
                return

            if not isinstance(payload, dict):
                return

            try:
                record = _parse_record(
                    payload,
                    domain,
                )
            except ValidationError:
                return

            if record is None:
                return

            progress_callback(record)

        from saarthi_ai.automation.adaptive import run_tool_adaptively

        try:
            tool_result = run_tool_adaptively(
                PD_HTTPX_PROFILE,
                arguments,
                allow_waf_bypass=False,
                on_output=(
                    emit_progress if progress_callback is not None else None
                ),
                forward_aborted_output=False,
                runner=run_tool,
            )
        except ToolRunnerError as exc:
            raise HttpIntelligenceCollectionError(str(exc)) from exc

    tool_run = HttpIntelligenceToolRun(
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
        raise HttpIntelligenceCollectionError(
            "ProjectDiscovery httpx timed out."
        )

    if tool_result.exit_code != 0:
        raise HttpIntelligenceCollectionError(
            "ProjectDiscovery httpx exited unsuccessfully: "
            f"{tool_result.exit_code}"
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
            record = _parse_record(payload, domain)
        except ValidationError:
            malformed_line_count += 1
            continue

        if record is None:
            rejected_results.add(str(payload.get("url") or payload.get("input") or stripped))
            continue

        records_by_url[record.url] = record

    records = sorted(
        records_by_url.values(),
        key=lambda item: (
            item.host,
            item.port or 0,
            item.url,
        ),
    )

    provisional = HttpIntelligenceCollectionResult(
        collector_execution_id=collector_execution_id,
        collector_evidence_id=collector_evidence_id,
        source_evidence_path=_display_path(source_evidence_path),
        source_collector_execution_id=source_execution_id,
        source_collector_evidence_id=source_evidence_id,
        domain=domain,
        input_count=len(hostnames),
        live_service_count=len(records),
        malformed_line_count=malformed_line_count,
        rejected_inputs=rejected_inputs,
        rejected_results=sorted(rejected_results),
        records=records,
        tool_run=tool_run,
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
