"""Auto-verify findings to eliminate false positives.

Every finding a tool reports is re-checked, bounded and in-scope:
- nuclei: re-run the exact template against the exact matched URL and confirm
  the matcher fires again (deterministic reproduction check).
- sqlmap: classify the run's own verdict (it already tests multiple
  techniques before declaring an injection).

Each finding is labelled CONFIRMED / LIKELY / FALSE_POSITIVE so the report can
surface only what actually reproduces.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

from saarthi_ai.execution.tool_runner import (
    NUCLEI_PROFILE,
    ToolProfile,
    ToolRunResult,
    run_tool,
)

MAX_VERIFIED_FINDINGS = 40
VERIFY_NUCLEI_TIMEOUT_SECONDS = 60

# Build a short-timeout nuclei profile for single-template re-checks.
NUCLEI_VERIFY_PROFILE = ToolProfile(
    name=NUCLEI_PROFILE.name,
    executable_candidates=NUCLEI_PROFILE.executable_candidates,
    timeout_seconds=VERIFY_NUCLEI_TIMEOUT_SECONDS,
    max_output_bytes=NUCLEI_PROFILE.max_output_bytes,
    max_arguments=NUCLEI_PROFILE.max_arguments,
    max_argument_length=NUCLEI_PROFILE.max_argument_length,
)

_SQLMAP_VULNERABLE_MARKERS = (
    "is vulnerable",
    "sqlmap identified the following injection",
    "the following injection point",
    "appears to be injectable",
)
_SQLMAP_NEGATIVE_MARKERS = (
    "do not appear to be injectable",
    "does not seem to be injectable",
    "not injectable",
)


class FindingVerdict(StrEnum):
    """Result of re-checking a reported finding."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    FALSE_POSITIVE = "false_positive"


@dataclass(frozen=True)
class VerifiedFinding:
    """One finding plus its verification verdict."""

    source_tool: str
    identifier: str
    target: str
    severity: str
    verdict: FindingVerdict
    reason: str


def _normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _in_scope(url: str, allowed_hosts: tuple[str, ...]) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return False
    allowed = {_normalize_host(h) for h in allowed_hosts if h.strip()}
    return _normalize_host(parsed.hostname) in allowed


def parse_nuclei_findings(stdout: str) -> list[dict]:
    """Extract structured findings from nuclei -jsonl output."""

    findings: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and (
            record.get("template-id") or record.get("templateID")
        ):
            findings.append(record)
    return findings


def _finding_target(finding: dict) -> str:
    for key in ("matched-at", "matched_at", "host", "url"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def verify_nuclei_finding(
    finding: dict,
    *,
    allowed_hosts: tuple[str, ...],
    runner: Callable[..., ToolRunResult] = run_tool,
    profile: ToolProfile = NUCLEI_VERIFY_PROFILE,
) -> VerifiedFinding:
    """Re-run one nuclei template on its matched URL to confirm it reproduces."""

    template = finding.get("template-id") or finding.get("templateID") or ""
    target = _finding_target(finding)
    severity = str(
        (finding.get("info", {}) or {}).get("severity", "unknown")
    )

    if not template:
        return VerifiedFinding(
            "nuclei", "unknown", target, severity,
            FindingVerdict.LIKELY, "No template id to re-verify.",
        )

    if not target or not _in_scope(target, allowed_hosts):
        return VerifiedFinding(
            "nuclei", template, target, severity,
            FindingVerdict.LIKELY,
            "Matched target is not an in-scope URL; not re-run.",
        )

    result = runner(
        profile,
        [
            "-u", target,
            "-id", template,
            "-jsonl", "-silent", "-no-color",
            "-disable-update-check",
            "-timeout", "10", "-retries", "1",
        ],
    )

    if result.timed_out or result.aborted:
        return VerifiedFinding(
            "nuclei", template, target, severity,
            FindingVerdict.LIKELY, "Re-check timed out; could not confirm.",
        )

    reproduced = any(
        template in line
        for line in result.stdout.splitlines()
        if line.strip()
    )
    if reproduced:
        return VerifiedFinding(
            "nuclei", template, target, severity,
            FindingVerdict.CONFIRMED, "Template re-fired on re-run.",
        )
    return VerifiedFinding(
        "nuclei", template, target, severity,
        FindingVerdict.FALSE_POSITIVE, "Template did not re-fire.",
    )


def classify_sqlmap_run(run: dict) -> VerifiedFinding | None:
    """Classify a summarized sqlmap run into a verified finding, if any."""

    stdout = (run.get("stdout") or "").lower()
    parameter = str(run.get("parameter", "?"))
    target = str(run.get("url", ""))

    # Negative markers are checked first: phrases like "do not appear to be
    # injectable" contain "injectable" and would otherwise match a positive.
    if any(marker in stdout for marker in _SQLMAP_NEGATIVE_MARKERS):
        return VerifiedFinding(
            "sqlmap", parameter, target, "info",
            FindingVerdict.FALSE_POSITIVE,
            "sqlmap found no injectable parameter.",
        )
    if any(marker in stdout for marker in _SQLMAP_VULNERABLE_MARKERS):
        return VerifiedFinding(
            "sqlmap", parameter, target, "high",
            FindingVerdict.CONFIRMED,
            "sqlmap confirmed an injection point.",
        )
    if run.get("timed_out") or run.get("exit_code") == -1:
        return VerifiedFinding(
            "sqlmap", parameter, target, "unknown",
            FindingVerdict.LIKELY,
            "sqlmap did not finish; injection status unconfirmed.",
        )
    return None


def verify_findings(
    nuclei_stdout: str,
    sqlmap_runs: tuple[dict, ...],
    *,
    allowed_hosts: tuple[str, ...],
    runner: Callable[..., ToolRunResult] = run_tool,
    max_findings: int = MAX_VERIFIED_FINDINGS,
    on_progress: Callable[[VerifiedFinding], None] | None = None,
) -> list[VerifiedFinding]:
    """Verify all nuclei + sqlmap findings, bounded and in-scope."""

    verified: list[VerifiedFinding] = []

    for finding in parse_nuclei_findings(nuclei_stdout)[:max_findings]:
        result = verify_nuclei_finding(
            finding, allowed_hosts=allowed_hosts, runner=runner
        )
        verified.append(result)
        if on_progress is not None:
            on_progress(result)

    for run in sqlmap_runs:
        classified = classify_sqlmap_run(run)
        if classified is not None:
            verified.append(classified)
            if on_progress is not None:
                on_progress(classified)

    return verified
