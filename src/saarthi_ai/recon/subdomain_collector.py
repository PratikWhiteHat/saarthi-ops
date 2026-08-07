from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx
from pydantic import BaseModel, Field

from saarthi_ai.config import tls_verify
from saarthi_ai.execution.tool_runner import (
    AMASS_PROFILE,
    ASSETFINDER_PROFILE,
    SUBFINDER_PROFILE,
    ToolOutputEvent,
    ToolProfile,
    ToolRunnerError,
    ToolRunResult,
    resolve_executable,
    run_tool,
)
from saarthi_ai.recon.dns_collector import (
    DnsCollectionError,
    normalize_domain,
)

DEFAULT_CT_ENDPOINT = "https://crt.sh/"


class SubdomainCollectionError(RuntimeError):
    """Raised when passive subdomain collection cannot be completed."""


class SubdomainCandidate(BaseModel):
    """One normalized passive subdomain candidate."""

    hostname: str
    sources: list[str] = Field(default_factory=list)
    wildcard_source: bool = False


class ToolExecutionSummary(BaseModel):
    """Safe execution metadata for one passive provider."""

    tool_name: str
    available: bool
    executable: str | None = None
    arguments: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    timed_out: bool = False
    result_count: int = 0
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None
    stderr_excerpt: str | None = None
    error: str | None = None


class SubdomainCollectionResult(BaseModel):
    """Structured passive subdomain collection result."""

    collector_execution_id: str
    collector_evidence_id: str
    domain: str
    source: str
    candidates: list[SubdomainCandidate]
    raw_entry_count: int
    rejected_names: list[str] = Field(default_factory=list)
    tool_runs: list[ToolExecutionSummary] = Field(default_factory=list)
    collected_at: datetime
    evidence_path: str
    evidence_sha256: str
    evidence_size_bytes: int


def _normalize_candidate(
    candidate: str,
    parent_domain: str,
) -> tuple[str | None, bool]:
    """Normalize one hostname and enforce parent-domain scope."""

    value = candidate.strip().lower().rstrip(".")

    if not value:
        return None, False

    wildcard_source = value.startswith("*.")

    if wildcard_source:
        value = value[2:]

    try:
        normalized = normalize_domain(value)
    except DnsCollectionError:
        return None, wildcard_source

    if normalized == parent_domain:
        return normalized, wildcard_source

    if normalized.endswith(f".{parent_domain}"):
        return normalized, wildcard_source

    return None, wildcard_source


def _merge_candidate(
    candidates: dict[str, SubdomainCandidate],
    rejected_names: set[str],
    *,
    raw_name: str,
    parent_domain: str,
    source: str,
) -> bool:
    """Normalize and merge one discovered hostname."""

    hostname, wildcard_source = _normalize_candidate(
        raw_name,
        parent_domain,
    )

    if hostname is None:
        stripped = raw_name.strip()

        if stripped:
            rejected_names.add(stripped)

        return False

    existing = candidates.get(hostname)

    if existing is None:
        candidates[hostname] = SubdomainCandidate(
            hostname=hostname,
            sources=[source],
            wildcard_source=wildcard_source,
        )
        return True

    sources = list(existing.sources)

    if source not in sources:
        sources.append(source)
        sources.sort()

    candidates[hostname] = existing.model_copy(
        update={
            "sources": sources,
            "wildcard_source": (existing.wildcard_source or wildcard_source),
        }
    )

    return False


def _safe_stderr_excerpt(stderr: str) -> str | None:
    """Return a bounded stderr excerpt suitable for evidence metadata."""

    value = stderr.strip()

    if not value:
        return None

    return value[:2_000]


def _run_passive_tool(
    profile: ToolProfile,
    arguments: list[str],
    *,
    parent_domain: str,
    source: str,
    candidates: dict[str, SubdomainCandidate],
    rejected_names: set[str],
    progress_callback: Callable[[ToolOutputEvent], None] | None = None,
) -> tuple[ToolExecutionSummary, int]:
    """Run one allowlisted passive tool and merge its results."""

    executable = resolve_executable(profile)

    if executable is None:
        return (
            ToolExecutionSummary(
                tool_name=profile.name,
                available=False,
                error="Tool is not installed or executable.",
            ),
            0,
        )

    from saarthi_ai.automation.adaptive import run_tool_adaptively

    try:
        result = run_tool_adaptively(
            profile,
            arguments,
            allow_waf_bypass=False,
            on_output=progress_callback,
            forward_aborted_output=False,
            retune_on_thin=True,
            runner=run_tool,
        )
    except ToolRunnerError as exc:
        return (
            ToolExecutionSummary(
                tool_name=profile.name,
                available=True,
                executable=executable,
                arguments=arguments,
                error=str(exc),
            ),
            0,
        )

    result_count = 0

    for raw_name in result.stdout.splitlines():
        if _merge_candidate(
            candidates,
            rejected_names,
            raw_name=raw_name,
            parent_domain=parent_domain,
            source=source,
        ):
            result_count += 1

    return (
        _tool_summary(
            result,
            result_count=result_count,
        ),
        len(result.stdout.splitlines()),
    )


def _tool_summary(
    result: ToolRunResult,
    *,
    result_count: int,
) -> ToolExecutionSummary:
    """Convert a raw controlled-tool result into evidence metadata."""

    return ToolExecutionSummary(
        tool_name=result.tool_name,
        available=True,
        executable=result.executable,
        arguments=list(result.arguments),
        exit_code=result.exit_code,
        timed_out=result.timed_out,
        result_count=result_count,
        stdout_sha256=result.stdout_sha256,
        stderr_sha256=result.stderr_sha256,
        stderr_excerpt=_safe_stderr_excerpt(result.stderr),
    )


def _collect_certificate_transparency(
    domain: str,
    *,
    endpoint: str,
    client: httpx.Client | None,
    candidates: dict[str, SubdomainCandidate],
    rejected_names: set[str],
) -> tuple[ToolExecutionSummary, int]:
    """Query crt.sh as an additional passive provider."""

    owns_client = client is None
    active_client = client or httpx.Client(
        timeout=httpx.Timeout(20.0),
        follow_redirects=False,
        verify=tls_verify(),
        headers={
            "User-Agent": ("Saarthi-OPS/0.1 passive-subdomain-collector"),
            "Accept": "application/json",
        },
    )

    try:
        response = active_client.get(
            endpoint,
            params={
                "q": f"%.{domain}",
                "output": "json",
            },
        )
        response.raise_for_status()
        payload = response.json()

        if not isinstance(payload, list):
            raise SubdomainCollectionError(
                "Certificate Transparency provider returned an unexpected response."
            )

        result_count = 0

        for item in payload:
            if not isinstance(item, dict):
                continue

            raw_name_value = item.get("name_value")

            if not isinstance(raw_name_value, str):
                continue

            for raw_name in raw_name_value.splitlines():
                if _merge_candidate(
                    candidates,
                    rejected_names,
                    raw_name=raw_name,
                    parent_domain=domain,
                    source="certificate-transparency",
                ):
                    result_count += 1

        return (
            ToolExecutionSummary(
                tool_name="certificate-transparency",
                available=True,
                executable=endpoint,
                arguments=[
                    f"q=%.{domain}",
                    "output=json",
                ],
                exit_code=0,
                timed_out=False,
                result_count=result_count,
            ),
            len(payload),
        )

    except httpx.TimeoutException:
        return (
            ToolExecutionSummary(
                tool_name="certificate-transparency",
                available=True,
                executable=endpoint,
                timed_out=True,
                error="Certificate Transparency request timed out.",
            ),
            0,
        )

    except httpx.HTTPStatusError as exc:
        return (
            ToolExecutionSummary(
                tool_name="certificate-transparency",
                available=True,
                executable=endpoint,
                exit_code=exc.response.status_code,
                error=(
                    f"Certificate Transparency provider returned HTTP {exc.response.status_code}."
                ),
            ),
            0,
        )

    except (httpx.RequestError, ValueError) as exc:
        return (
            ToolExecutionSummary(
                tool_name="certificate-transparency",
                available=True,
                executable=endpoint,
                error=str(exc),
            ),
            0,
        )

    finally:
        if owns_client:
            active_client.close()


def collect_subdomains(
    domain: str,
    *,
    evidence_root: Path | None = None,
    client: httpx.Client | None = None,
    endpoint: str = DEFAULT_CT_ENDPOINT,
    progress_callback: Callable[[ToolOutputEvent], None] | None = None,
) -> SubdomainCollectionResult:
    """Collect passive candidates using approved local tools and CT."""

    normalized_domain = normalize_domain(domain)
    collector_execution_id = f"subdomain-run-{uuid4()}"
    collector_evidence_id = f"subdomain-evidence-{uuid4()}"
    collected_at = datetime.now(UTC)

    candidates: dict[str, SubdomainCandidate] = {}
    rejected_names: set[str] = set()
    tool_runs: list[ToolExecutionSummary] = []
    raw_entry_count = 0

    tool_definitions = (
        (
            SUBFINDER_PROFILE,
            ["-silent", "-d", normalized_domain],
            "subfinder",
        ),
        (
            AMASS_PROFILE,
            [
                "enum",
                "-passive",
                "-d",
                normalized_domain,
                "-timeout",
                "3",
            ],
            "amass",
        ),
        (
            ASSETFINDER_PROFILE,
            ["--subs-only", normalized_domain],
            "assetfinder",
        ),
    )

    for profile, arguments, source in tool_definitions:
        summary, raw_count = _run_passive_tool(
            profile,
            arguments,
            parent_domain=normalized_domain,
            source=source,
            candidates=candidates,
            rejected_names=rejected_names,
            progress_callback=progress_callback,
        )
        tool_runs.append(summary)
        raw_entry_count += raw_count

    ct_summary, ct_raw_count = _collect_certificate_transparency(
        normalized_domain,
        endpoint=endpoint,
        client=client,
        candidates=candidates,
        rejected_names=rejected_names,
    )

    tool_runs.append(ct_summary)
    raw_entry_count += ct_raw_count

    # Always preserve the authorized root domain as a candidate.
    _merge_candidate(
        candidates,
        rejected_names,
        raw_name=normalized_domain,
        parent_domain=normalized_domain,
        source="scope-root",
    )

    successful_sources = [
        run
        for run in tool_runs
        if run.available and not run.timed_out and run.error is None and run.exit_code in {None, 0}
    ]

    if not successful_sources:
        raise SubdomainCollectionError(
            "All passive subdomain providers failed or were unavailable."
        )

    sorted_candidates = sorted(
        candidates.values(),
        key=lambda candidate: candidate.hostname,
    )

    evidence_directory = evidence_root or Path("evidence") / "subdomains"
    evidence_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    evidence_file = evidence_directory / f"{collector_evidence_id}.json"

    evidence_payload = {
        "schema_version": "2.0",
        "collector": "internal-multi-source-subdomain-collector",
        "collector_execution_id": collector_execution_id,
        "collector_evidence_id": collector_evidence_id,
        "domain": normalized_domain,
        "mode": "passive",
        "source": "multi-provider",
        "candidate_count": len(sorted_candidates),
        "raw_entry_count": raw_entry_count,
        "candidates": [candidate.model_dump(mode="json") for candidate in sorted_candidates],
        "rejected_names": sorted(rejected_names),
        "tool_runs": [run.model_dump(mode="json") for run in tool_runs],
        "collected_at": collected_at.isoformat(),
    }

    evidence_bytes = json.dumps(
        evidence_payload,
        indent=2,
        sort_keys=True,
    ).encode("utf-8")

    evidence_file.write_bytes(evidence_bytes)

    return SubdomainCollectionResult(
        collector_execution_id=collector_execution_id,
        collector_evidence_id=collector_evidence_id,
        domain=normalized_domain,
        source="multi-provider",
        candidates=sorted_candidates,
        raw_entry_count=raw_entry_count,
        rejected_names=sorted(rejected_names),
        tool_runs=tool_runs,
        collected_at=collected_at,
        evidence_path=str(evidence_file),
        evidence_sha256=hashlib.sha256(evidence_bytes).hexdigest(),
        evidence_size_bytes=len(evidence_bytes),
    )
