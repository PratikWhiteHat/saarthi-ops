"""Automatic Nuclei and SQLMap validation for authorized targets."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from saarthi_ai.automation.adaptive import (
    AdaptationEvent,
    run_tool_adaptively,
)
from saarthi_ai.automation.verification import (
    VerifiedFinding,
    verify_findings,
)
from saarthi_ai.execution.tool_runner import (
    NUCLEI_PROFILE,
    SQLMAP_PROFILE,
    ToolOutputEvent,
    ToolProfile,
    ToolRunResult,
    run_tool,
)

DANGEROUS_NUCLEI_TAGS = (
    "bruteforce",
    "dos",
    "fuzz",
    "headless",
    "intrusive",
    "token-spray",
)

PROHIBITED_SQLMAP_SWITCHES = (
    "--dbs",
    "--tables",
    "--columns",
    "--dump",
    "--dump-all",
    "--passwords",
    "--users",
    "--roles",
    "--sql-shell",
    "--os-shell",
    "--os-pwn",
    "--file-read",
    "--file-write",
    "--crawl",
    "--forms",
    "--tamper",
)

# Switches that remain blocked even in confirmed-PoC mode. Detection
# evasion (--tamper), OS/SQL interaction, filesystem access, and bulk
# extraction are never enabled automatically, regardless of approval.
ALWAYS_PROHIBITED_SQLMAP_SWITCHES = (
    "--dump-all",
    "--passwords",
    "--users",
    "--roles",
    "--sql-shell",
    "--os-shell",
    "--os-pwn",
    "--file-read",
    "--file-write",
    "--crawl",
    "--forms",
    "--tamper",
)

# Read-only impact-proof switches enabled in confirmed-PoC mode. Once SQLMap
# fingerprints the DBMS it enumerates the database names (--dbs) and stops --
# a strong SQLi proof that lists databases without exfiltrating user records.
# Table/column/row dumping stays off (see ALWAYS_PROHIBITED + single-row opt).
SQLMAP_CONFIRMED_POC_SWITCHES = (
    "--banner",
    "--current-user",
    "--current-db",
    "--hostname",
    "--is-dba",
    "--dbs",
)


class AutoValidationError(RuntimeError):
    """Raised when automatic validation cannot proceed safely."""


@dataclass(frozen=True)
class SqlmapCandidate:
    """Approved SQL injection validation candidate."""

    url: str
    parameter: str
    method: str = "GET"
    data: str | None = None
    content_type: str | None = None


@dataclass(frozen=True)
class AutoValidationConfig:
    """Configuration for automatic Nuclei and SQLMap execution."""

    target_url: str
    allowed_hosts: tuple[str, ...]

    authorized: bool
    active_testing: bool
    intrusive_testing: bool
    approved: bool

    sqlmap_candidates: tuple[SqlmapCandidate, ...] = ()

    evidence_root: Path = Path("evidence/automatic-validation")

    nuclei_templates_path: str | None = None
    nuclei_rate_limit: int = 5
    nuclei_concurrency: int = 5
    nuclei_request_timeout_seconds: int = 10
    # Generous process budget so a full (throttled) template run completes
    # rather than being killed mid-scan. Not a rate change — the polite
    # rate-limit/concurrency still bound load on the target.
    nuclei_process_timeout_seconds: int = 10800

    sqlmap_level: int = 2
    sqlmap_risk: int = 1
    sqlmap_threads: int = 1
    sqlmap_request_timeout_seconds: int = 10
    # Generous process budget so the full technique battery can confirm an
    # injection even when adaptive throttling (delay/threads) slows it down.
    sqlmap_process_timeout_seconds: int = 3600
    sqlmap_techniques: str = "BEUSTQ"

    # Confirmed-PoC mode (explicitly authorized bug-bounty proof only).
    # Adds read-only identity/impact switches. Detection evasion, OS/SQL
    # shells, and filesystem access stay blocked (see
    # ALWAYS_PROHIBITED_SQLMAP_SWITCHES).
    sqlmap_confirmed_poc: bool = False
    # When paired with confirmed-PoC, permits a single-row --dump capped at
    # one entry (--start=1 --stop=1) to evidence data reachability.
    sqlmap_poc_single_row_dump: bool = False

    # Adaptive tool control: watch each tool's live output and automatically
    # retry with bounded, allowlisted settings on WAF / reconnect / rate-limit.
    adaptive: bool = False
    # When adaptive, permit bounded WAF bypass (sqlmap --tamper/--random-agent)
    # on WAF detection. Authorized targets only; OS/SQL/file switches never.
    allow_waf_bypass: bool = False

    # Auto-verify each finding (re-run the exact nuclei template in-scope,
    # classify sqlmap) to label CONFIRMED / LIKELY / FALSE_POSITIVE.
    verify_findings: bool = False


@dataclass(frozen=True)
class AutomaticValidationResult:
    """Summary of the completed automatic-validation run."""

    run_id: str
    started_at: str
    completed_at: str
    evidence_path: str
    nuclei: dict[str, Any]
    sqlmap: tuple[dict[str, Any], ...]
    verified_findings: tuple[dict[str, Any], ...] = ()


def _normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _validate_url(url: str, allowed_hosts: tuple[str, ...]) -> str:
    candidate = url.strip()
    parsed = urlsplit(candidate)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise AutoValidationError(
            f"Only HTTP and HTTPS targets are supported: {url!r}"
        )

    if parsed.hostname is None:
        raise AutoValidationError(f"Invalid target URL: {url!r}")

    if parsed.username is not None or parsed.password is not None:
        raise AutoValidationError(
            "Credentials embedded in target URLs are not allowed."
        )

    if any(ord(character) < 32 or ord(character) == 127 for character in candidate):
        raise AutoValidationError(
            "The target URL contains a control character."
        )

    host = _normalize_host(parsed.hostname)
    allowed = {
        _normalize_host(item)
        for item in allowed_hosts
        if item.strip()
    }

    if host not in allowed:
        raise AutoValidationError(
            f"Host {host!r} is outside the allowed host list: "
            f"{sorted(allowed)}"
        )

    return candidate


def _validate_config(config: AutoValidationConfig) -> None:
    if not config.authorized:
        raise AutoValidationError(
            "Written authorization must be confirmed."
        )

    if not config.active_testing:
        raise AutoValidationError(
            "Active-testing permission must be confirmed."
        )

    if config.sqlmap_candidates and not config.intrusive_testing:
        raise AutoValidationError(
            "Intrusive-testing permission is required for SQLMap."
        )

    if config.sqlmap_confirmed_poc and not config.intrusive_testing:
        raise AutoValidationError(
            "Confirmed-PoC SQLMap mode requires intrusive-testing permission."
        )

    if not config.approved:
        raise AutoValidationError(
            "The automatic workflow must be explicitly approved."
        )

    if not config.allowed_hosts:
        raise AutoValidationError(
            "At least one exact allowed hostname is required."
        )

    _validate_url(config.target_url, config.allowed_hosts)

    if not 1 <= config.nuclei_rate_limit <= 20:
        raise AutoValidationError(
            "Nuclei rate limit must be between 1 and 20."
        )

    if not 1 <= config.nuclei_concurrency <= 10:
        raise AutoValidationError(
            "Nuclei concurrency must be between 1 and 10."
        )

    if config.nuclei_request_timeout_seconds < 1:
        raise AutoValidationError(
            "Nuclei request timeout must be at least one second."
        )

    if not 1 <= config.sqlmap_level <= 3:
        raise AutoValidationError(
            "SQLMap level must be between 1 and 3."
        )

    if not 1 <= config.sqlmap_risk <= 2:
        raise AutoValidationError(
            "SQLMap risk must be 1 or 2."
        )

    if not 1 <= config.sqlmap_threads <= 3:
        raise AutoValidationError(
            "SQLMap threads must be between 1 and 3."
        )

    valid_techniques = set("BEUSTQ")
    requested_techniques = set(config.sqlmap_techniques.upper())

    if not requested_techniques:
        raise AutoValidationError(
            "At least one SQLMap technique is required."
        )

    if not requested_techniques.issubset(valid_techniques):
        raise AutoValidationError(
            "SQLMap techniques can only contain B, E, U, S, T and Q."
        )

    if config.sqlmap_poc_single_row_dump and not config.sqlmap_confirmed_poc:
        raise AutoValidationError(
            "Single-row PoC dump requires confirmed-PoC mode to be enabled."
        )

    for candidate in config.sqlmap_candidates:
        _validate_url(candidate.url, config.allowed_hosts)


def _nuclei_arguments(config: AutoValidationConfig) -> list[str]:
    """Create Nuclei arguments.

    When nuclei_templates_path is not configured, Nuclei uses all templates
    installed in its default template directory.
    """

    arguments = [
        "-u",
        _validate_url(config.target_url, config.allowed_hosts),
        "-jsonl",
        "-silent",
        "-no-color",
        "-disable-update-check",
        "-rate-limit",
        str(config.nuclei_rate_limit),
        "-concurrency",
        str(config.nuclei_concurrency),
        "-timeout",
        str(config.nuclei_request_timeout_seconds),
        "-retries",
        "1",
        "-exclude-tags",
        ",".join(DANGEROUS_NUCLEI_TAGS),
    ]

    if config.nuclei_templates_path:
        template_path = Path(
            config.nuclei_templates_path
        ).expanduser()

        if not template_path.exists():
            raise AutoValidationError(
                f"Nuclei templates path does not exist: {template_path}"
            )

        arguments.extend(
            [
                "-t",
                str(template_path),
            ]
        )

    return arguments


def _sqlmap_arguments(
    config: AutoValidationConfig,
    candidate: SqlmapCandidate,
    output_directory: Path,
) -> list[str]:
    url = _validate_url(
        candidate.url,
        config.allowed_hosts,
    )

    method = candidate.method.strip().upper()
    parameter = candidate.parameter.strip()

    if method not in {"GET", "POST"}:
        raise AutoValidationError(
            "SQLMap method must be GET or POST."
        )

    if not parameter:
        raise AutoValidationError(
            "SQLMap parameter cannot be empty."
        )

    if method == "GET":
        parameter_names = {
            name
            for name, _ in parse_qsl(
                urlsplit(url).query,
                keep_blank_values=True,
            )
        }

        if parameter not in parameter_names:
            raise AutoValidationError(
                f"GET parameter {parameter!r} is absent from {url!r}."
            )

        if candidate.data is not None:
            raise AutoValidationError(
                "GET SQLMap candidates cannot contain POST data."
            )

    if method == "POST" and not candidate.data:
        raise AutoValidationError(
            "POST SQLMap candidates require request data."
        )

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    arguments = [
        "-u",
        url,
        "-p",
        parameter,
        "--batch",
        "--flush-session",
        f"--level={config.sqlmap_level}",
        f"--risk={config.sqlmap_risk}",
        f"--threads={config.sqlmap_threads}",
        f"--timeout={config.sqlmap_request_timeout_seconds}",
        "--retries=1",
        f"--technique={config.sqlmap_techniques.upper()}",
        "--disable-coloring",
        f"--output-dir={output_directory}",
    ]

    if method == "POST":
        arguments.extend(
            [
                "--method=POST",
                f"--data={candidate.data}",
            ]
        )

        if candidate.content_type:
            arguments.append(
                f"--headers=Content-Type: {candidate.content_type}"
            )

    if config.sqlmap_confirmed_poc:
        arguments.extend(SQLMAP_CONFIRMED_POC_SWITCHES)

        if config.sqlmap_poc_single_row_dump:
            arguments.extend(
                [
                    "--dump",
                    "--start=1",
                    "--stop=1",
                ]
            )

    # Confirmed-PoC mode narrows the block list to the always-prohibited
    # switches so a bounded, read-only proof can run; detection evasion and
    # OS/SQL/filesystem interaction remain blocked in every mode.
    effective_prohibited = (
        ALWAYS_PROHIBITED_SQLMAP_SWITCHES
        if config.sqlmap_confirmed_poc
        else PROHIBITED_SQLMAP_SWITCHES
    )

    for argument in arguments:
        normalized_argument = argument.strip().lower()

        for blocked_switch in effective_prohibited:
            if (
                normalized_argument == blocked_switch
                or normalized_argument.startswith(
                    blocked_switch + "="
                )
            ):
                raise AutoValidationError(
                    f"Prohibited SQLMap switch requested: "
                    f"{blocked_switch}"
                )

    return arguments


def _event_printer(event: ToolOutputEvent) -> None:
    print(
        f"[{event.tool_name}:{event.stream}] {event.line}",
        flush=True,
    )


def _summarize_result(
    result: ToolRunResult,
    *,
    redact_data: bool = False,
) -> dict[str, Any]:
    arguments = list(result.arguments)

    if redact_data:
        arguments = [
            "--data=<redacted>"
            if argument.startswith("--data=")
            else argument
            for argument in arguments
        ]

    return {
        "tool_name": result.tool_name,
        "executable": result.executable,
        "arguments": arguments,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "stdout_sha256": result.stdout_sha256,
        "stderr_sha256": result.stderr_sha256,
        "stdout_truncated": result.stdout_truncated,
        "stderr_truncated": result.stderr_truncated,
    }


def _write_json_atomically(
    path: Path,
    payload: dict[str, Any],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    encoded_data = (
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")

    temporary_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            dir=path.parent,
            delete=False,
        ) as temporary_file:
            temporary_file.write(encoded_data)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
            temporary_path = Path(temporary_file.name)

        os.replace(
            temporary_path,
            path,
        )

    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink(
                missing_ok=True
            )


def run_automatic_validation(
    config: AutoValidationConfig,
    *,
    on_output: Callable[[ToolOutputEvent], None] | None = None,
    on_log: Callable[[str], None] | None = None,
    on_adapt: Callable[[AdaptationEvent], None] | None = None,
) -> AutomaticValidationResult:
    """Run Nuclei and every approved SQLMap candidate automatically.

    ``on_output`` receives each bounded tool line and ``on_log`` receives
    progress messages. Both default to stdout printing so the CLI runner is
    unchanged; the Saarthi OPS TUI passes callbacks that stream into the
    live activity log instead. ``on_adapt`` receives adaptive-control events
    (WAF/reconnect/rate-limit retries) when ``config.adaptive`` is set.
    """

    _validate_config(config)

    emit_output = on_output or _event_printer

    def emit_log(message: str) -> None:
        if on_log is not None:
            on_log(message)
        else:
            print(message, flush=True)

    def emit_adapt(event: AdaptationEvent) -> None:
        emit_log(
            f"[adapt] {event.tool_name}: {event.condition.value} "
            f"(attempt {event.attempt}) → {event.note}"
        )
        if on_adapt is not None:
            on_adapt(event)

    def run_or_adapt(
        profile: ToolProfile,
        arguments: list[str],
    ) -> ToolRunResult:
        if config.adaptive:
            return run_tool_adaptively(
                profile,
                arguments,
                allow_waf_bypass=config.allow_waf_bypass,
                on_output=emit_output,
                on_adapt=emit_adapt,
            )
        return run_tool(profile, arguments, on_output=emit_output)

    started = datetime.now(UTC)
    run_id = (
        f"auto-validation-"
        f"{started:%Y%m%dT%H%M%S}-"
        f"{started.microsecond:06d}Z"
    )

    run_root = config.evidence_root / run_id
    run_root.mkdir(
        parents=True,
        exist_ok=False,
    )

    nuclei_profile = NUCLEI_PROFILE.__class__(
        name=NUCLEI_PROFILE.name,
        executable_candidates=NUCLEI_PROFILE.executable_candidates,
        timeout_seconds=config.nuclei_process_timeout_seconds,
        max_output_bytes=NUCLEI_PROFILE.max_output_bytes,
        max_arguments=NUCLEI_PROFILE.max_arguments,
        max_argument_length=NUCLEI_PROFILE.max_argument_length,
    )

    emit_log("[Saarthi] Starting automatic Nuclei validation...")

    nuclei_result = run_or_adapt(
        nuclei_profile,
        _nuclei_arguments(config),
    )

    sqlmap_results: list[dict[str, Any]] = []
    ghauri_cross_checks: list[dict[str, Any]] = []

    sqlmap_profile = SQLMAP_PROFILE.__class__(
        name=SQLMAP_PROFILE.name,
        executable_candidates=SQLMAP_PROFILE.executable_candidates,
        timeout_seconds=config.sqlmap_process_timeout_seconds,
        max_output_bytes=SQLMAP_PROFILE.max_output_bytes,
        max_arguments=SQLMAP_PROFILE.max_arguments,
        max_argument_length=SQLMAP_PROFILE.max_argument_length,
    )

    total_candidates = len(
        config.sqlmap_candidates
    )

    for index, candidate in enumerate(
        config.sqlmap_candidates,
        start=1,
    ):
        emit_log(
            f"[Saarthi] Starting SQLMap candidate "
            f"{index}/{total_candidates}: "
            f"{candidate.parameter}"
        )

        candidate_output_directory = (
            run_root
            / "sqlmap-output"
            / f"candidate-{index}"
        )

        sqlmap_result = run_or_adapt(
            sqlmap_profile,
            _sqlmap_arguments(
                config,
                candidate,
                candidate_output_directory,
            ),
        )

        summarized_result = _summarize_result(
            sqlmap_result,
            redact_data=True,
        )

        summarized_result.update(
            {
                "candidate_index": index,
                "parameter": candidate.parameter,
                "method": candidate.method.upper(),
                "url": candidate.url,
            }
        )

        sqlmap_results.append(
            summarized_result
        )

        # Auto blind-SQLi cross-check: when sqlmap flags a blind injection,
        # independently confirm it with ghauri (non-destructive). Gated on the
        # same operator authorization this run already carries.
        if _sqlmap_flagged_blind(sqlmap_result.stdout):
            cross_check = _run_ghauri_cross_check(
                config,
                candidate,
                emit_log=emit_log,
            )
            if cross_check is not None:
                ghauri_cross_checks.append(cross_check)

    verified_findings: list[dict[str, Any]] = []
    if config.verify_findings:
        emit_log(
            "[Saarthi] Verifying findings (false-positive filter)..."
        )

        def _record_verified(item: VerifiedFinding) -> None:
            emit_log(
                f"[verify] {item.source_tool} {item.identifier} @ "
                f"{item.target}: {item.verdict.value} — {item.reason}"
            )

        for finding in verify_findings(
            nuclei_result.stdout,
            tuple(sqlmap_results),
            allowed_hosts=config.allowed_hosts,
            runner=run_tool,
            on_progress=_record_verified,
        ):
            verified_findings.append(
                {
                    "source_tool": finding.source_tool,
                    "identifier": finding.identifier,
                    "target": finding.target,
                    "severity": finding.severity,
                    "verdict": finding.verdict.value,
                    "reason": finding.reason,
                }
            )

        confirmed_count = sum(
            1 for f in verified_findings if f["verdict"] == "confirmed"
        )
        false_positive_count = sum(
            1
            for f in verified_findings
            if f["verdict"] == "false_positive"
        )
        emit_log(
            f"[Saarthi] Verification: {confirmed_count} confirmed, "
            f"{false_positive_count} false-positive, "
            f"{len(verified_findings)} checked."
        )

    completed = datetime.now(UTC)

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "run_id": run_id,
        "started_at": started.isoformat(),
        "completed_at": completed.isoformat(),
        "configuration": {
            **asdict(config),
            "evidence_root": str(
                config.evidence_root
            ),
            "sqlmap_candidates": [
                {
                    "url": candidate.url,
                    "parameter": candidate.parameter,
                    "method": candidate.method,
                    "data": (
                        "<redacted>"
                        if candidate.data
                        else None
                    ),
                    "content_type": candidate.content_type,
                }
                for candidate in config.sqlmap_candidates
            ],
        },
        "policy": {
            "nuclei_all_installed_templates": (
                config.nuclei_templates_path is None
            ),
            "nuclei_templates_path": (
                config.nuclei_templates_path
            ),
            "nuclei_excluded_tags": list(
                DANGEROUS_NUCLEI_TAGS
            ),
            "sqlmap_detection_only": (
                not config.sqlmap_confirmed_poc
            ),
            "sqlmap_confirmed_poc": config.sqlmap_confirmed_poc,
            "sqlmap_poc_single_row_dump": (
                config.sqlmap_poc_single_row_dump
            ),
            "sqlmap_confirmed_poc_switches": (
                list(SQLMAP_CONFIRMED_POC_SWITCHES)
                if config.sqlmap_confirmed_poc
                else []
            ),
            "sqlmap_prohibited_switches": list(
                ALWAYS_PROHIBITED_SQLMAP_SWITCHES
                if config.sqlmap_confirmed_poc
                else PROHIBITED_SQLMAP_SWITCHES
            ),
            "adaptive": config.adaptive,
            "allow_waf_bypass": config.allow_waf_bypass,
        },
        "nuclei": _summarize_result(
            nuclei_result
        ),
        "sqlmap": sqlmap_results,
        "ghauri": ghauri_cross_checks,
        "verified_findings": verified_findings,
    }

    checksum_payload = json.dumps(
        payload,
        sort_keys=True,
        default=str,
    ).encode("utf-8")

    payload["evidence_sha256"] = hashlib.sha256(
        checksum_payload
    ).hexdigest()

    evidence_path = (
        run_root
        / "automatic-validation.json"
    )

    _write_json_atomically(
        evidence_path,
        payload,
    )

    emit_log(f"[Saarthi] Evidence saved to: {evidence_path}")

    return AutomaticValidationResult(
        run_id=run_id,
        started_at=started.isoformat(),
        completed_at=completed.isoformat(),
        evidence_path=str(evidence_path),
        nuclei=payload["nuclei"],
        sqlmap=tuple(sqlmap_results),
        verified_findings=tuple(verified_findings),
    )


def _sqlmap_flagged_blind(stdout: str) -> bool:
    """True when sqlmap's output reports a confirmed BLIND injection."""

    low = (stdout or "").lower()
    confirmed = (
        "is vulnerable" in low
        or "injection point(s)" in low
        or "identified the following injection" in low
        or ("appears to be" in low and "injectable" in low)
    )
    if not confirmed:
        return False
    return "boolean-based blind" in low or "time-based blind" in low


def _run_ghauri_cross_check(
    config: AutoValidationConfig,
    candidate: SqlmapCandidate,
    *,
    emit_log: Callable[[str], None],
) -> dict[str, Any] | None:
    """Non-destructive ghauri confirmation of a sqlmap blind-SQLi candidate.

    Gated on the same operator authorization the sqlmap run already used, so it
    adds no un-approved active testing. GET candidates only. Best-effort — a
    ghauri hiccup is recorded, never raised, and never fails the run.
    """

    if not (
        config.authorized
        and config.approved
        and config.active_testing
        and config.intrusive_testing
    ):
        return None
    if candidate.method.upper() != "GET":
        return None

    from saarthi_ai.execution.ghauri_adapter import run_ghauri_crosscheck

    emit_log(
        "[Saarthi] ghauri cross-check (blind SQLi) on parameter "
        f"'{candidate.parameter}'..."
    )
    try:
        result = run_ghauri_crosscheck(
            candidate.url,
            candidate.parameter,
            technique="BT",
            identity_proof=True,
            authorized=True,
        )
    except Exception as exc:  # non-fatal cross-check
        emit_log(f"[Saarthi] ghauri cross-check skipped: {exc}")
        return {
            "parameter": candidate.parameter,
            "url": candidate.url,
            "technique": "BT",
            "status": "error",
            "error": str(exc),
        }

    verdict = "injectable" if result.injectable else "not_confirmed"
    emit_log(
        f"[verify] ghauri {candidate.parameter} @ {candidate.url}: {verdict}"
    )
    return {
        "parameter": candidate.parameter,
        "url": candidate.url,
        "technique": result.technique,
        "injectable": result.injectable,
        "exit_code": result.tool_result.exit_code,
        "timed_out": result.tool_result.timed_out,
        "stdout_sha256": result.tool_result.stdout_sha256,
    }
