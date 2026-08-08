"""AI-assisted triage of an assessment run's evidence (local Ollama)."""

from __future__ import annotations

import glob
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from saarthi_ai.automation.adaptive import AdaptationEvent
from saarthi_ai.llm.ollama_client import SaarthiOllamaClient
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import AuditEventType, ExecutionRecord
from saarthi_ai.schemas.chat import Message

ORCHESTRATION_PARENT_ROLE = "orchestration_parent"
DEFAULT_ORCHESTRATION_EVIDENCE_ROOT = Path("evidence/orchestrations")

MAX_FINDINGS = 60
MAX_FAILURES = 20
MAX_EVIDENCE_SIGNALS = 40
MAX_NUCLEI_HITS = 20
MAX_ANALYSIS_TOKENS = 900

ANALYST_SYSTEM_PROMPT = (
    "You are a senior application-security analyst triaging evidence from an "
    "AUTHORIZED VAPT assessment the operator ran. Analyze ONLY the evidence "
    "provided; never invent findings, hosts, or data. Be concise and "
    "specific. Produce:\n"
    "1. Executive summary (2-3 sentences).\n"
    "2. Findings ranked by severity (Critical/High/Medium/Low/Info). For "
    "each: what it is, why it matters, your confidence, and whether it looks "
    "like a likely false positive.\n"
    "3. Suggested next manual steps or plausible chains.\n"
    "4. Remediation notes.\n"
    "Prefer findings marked CONFIRMED by verification; treat FALSE_POSITIVE "
    "as noise and exclude it. If the evidence is thin or shows nothing "
    "exploitable, say so plainly. Do not fabricate exploitation detail."
)


class AnalysisError(RuntimeError):
    """Raised when a run cannot be assembled for AI analysis."""


@dataclass(frozen=True)
class RunDigest:
    """Bounded, sanitized summary of one assessment run for the model."""

    orchestration_id: str | None
    target: str
    parent_state: str
    assessment_name: str
    phases: tuple[tuple[str, str], ...]
    findings: tuple[str, ...] = ()
    failures: tuple[str, ...] = ()
    evidence_counts: dict[str, int] = field(default_factory=dict)
    evidence_signals: tuple[str, ...] = ()
    verified_findings: tuple[str, ...] = ()
    nuclei_summary: str | None = None
    sqlmap_summary: str | None = None
    ghauri_summary: str | None = None
    xsstrike_summary: str | None = None
    wayback_summary: str | None = None
    archive_summary: str | None = None


def _metadata(execution: ExecutionRecord) -> dict:
    return execution.metadata or {}


def _latest_parent(
    executions: list[ExecutionRecord],
    orchestration_id: str | None,
) -> ExecutionRecord | None:
    for execution in executions:
        meta = _metadata(execution)
        if meta.get("execution_role") != ORCHESTRATION_PARENT_ROLE:
            continue
        if (
            orchestration_id is not None
            and meta.get("orchestration_id") != orchestration_id
        ):
            continue
        return execution
    return None


def _compact_metadata(metadata: dict) -> str:
    """Render short scalar metadata as a compact key=value string."""

    interesting = (
        "action",
        "classification",
        "status",
        "outcome",
        "missing",
        "count",
        "observed",
        "risk",
        "check_id",
        "technique",
        "dbms",
        "parameter",
    )
    parts: list[str] = []
    for key, value in metadata.items():
        lowered = str(key).lower()
        if not any(term in lowered for term in interesting):
            continue
        if isinstance(value, bool | int | float):
            parts.append(f"{key}={value}")
        elif isinstance(value, str) and 0 < len(value) <= 80:
            parts.append(f"{key}={value}")
        if len(parts) >= 6:
            break
    return ", ".join(parts)


def _read_auto_validation(
    orchestration_id: str,
    evidence_root: Path,
) -> tuple[str | None, str | None, str | None, str | None, list[str]]:
    """Summarize nuclei/sqlmap/ghauri/xsstrike auto-validation evidence."""

    empty: tuple[None, None, None, None, list[str]] = (
        None,
        None,
        None,
        None,
        [],
    )
    pattern = str(
        evidence_root
        / orchestration_id
        / "auto-validation"
        / "*"
        / "automatic-validation.json"
    )
    files = sorted(glob.glob(pattern))
    if not files:
        return empty

    try:
        payload = json.loads(Path(files[-1]).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty

    nuclei = payload.get("nuclei", {}) or {}
    stdout = nuclei.get("stdout", "") or ""
    hits: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        template = record.get("template-id") or record.get("templateID")
        info = record.get("info", {}) or {}
        severity = info.get("severity", "unknown")
        matched = record.get("matched-at") or record.get("host") or ""
        hits.append(f"{severity}: {template} @ {matched}"[:160])
        if len(hits) >= MAX_NUCLEI_HITS:
            break

    nuclei_summary = (
        f"nuclei exit={nuclei.get('exit_code')} "
        f"timed_out={nuclei.get('timed_out')} template_hits={len(hits)}"
    )
    if hits:
        nuclei_summary += "\n  - " + "\n  - ".join(hits)

    sqlmap_runs = payload.get("sqlmap", []) or []
    sqlmap_lines: list[str] = []
    for run in sqlmap_runs:
        std = (run.get("stdout") or "").lower()
        vulnerable = (
            "is vulnerable" in std
            or "injectable" in std
            or "sqlmap identified" in std
        )
        dbms = ""
        marker = "the back-end dbms is"
        if marker in std:
            dbms = std.split(marker, 1)[1].strip()[:40]
        sqlmap_lines.append(
            f"param={run.get('parameter')} exit={run.get('exit_code')} "
            f"timed_out={run.get('timed_out')} sqli={vulnerable}"
            + (f" dbms={dbms}" if dbms else "")
        )
    sqlmap_summary = (
        "\n  - ".join(sqlmap_lines) if sqlmap_lines else None
    )
    if sqlmap_summary:
        sqlmap_summary = "  - " + sqlmap_summary

    ghauri_runs = payload.get("ghauri", []) or []
    ghauri_lines = [
        f"param={g.get('parameter')} injectable={g.get('injectable')}"
        + (f" [{g.get('status')}]" if g.get("status") else "")
        for g in ghauri_runs
        if isinstance(g, dict)
    ]
    ghauri_summary = (
        "  - " + "\n  - ".join(ghauri_lines) if ghauri_lines else None
    )

    xsstrike_runs = payload.get("xsstrike", []) or []
    xsstrike_lines = [
        f"url={x.get('url')} xss={x.get('vulnerable')}"
        + (
            f" efficiency={x.get('max_efficiency')}"
            if x.get("max_efficiency") is not None
            else ""
        )
        + (f" [{x.get('status')}]" if x.get("status") else "")
        for x in xsstrike_runs
        if isinstance(x, dict)
    ]
    xsstrike_summary = (
        "  - " + "\n  - ".join(xsstrike_lines) if xsstrike_lines else None
    )

    verified = payload.get("verified_findings", []) or []
    verified_lines = [
        f"{item.get('verdict')}: {item.get('source_tool')} "
        f"{item.get('identifier')} @ {item.get('target')}"
        for item in verified
        if isinstance(item, dict)
    ][:MAX_FINDINGS]

    return (
        nuclei_summary,
        sqlmap_summary,
        ghauri_summary,
        xsstrike_summary,
        verified_lines,
    )


def _read_wayback_intel(
    orchestration_id: str,
    evidence_root: Path,
) -> str | None:
    """Summarize Phase 3D Wayback CDX historical-URL intelligence."""

    pattern = str(
        evidence_root / orchestration_id / "crawling" / "wayback-cdx-*.json"
    )
    files = sorted(glob.glob(pattern))
    if not files:
        return None
    try:
        payload = json.loads(Path(files[-1]).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    urls = payload.get("urls", []) or []
    count = payload.get("url_count", len(urls))
    summary = f"wayback-cdx: {count} historical URLs"
    if payload.get("truncated"):
        summary += " (truncated)"
    sample = [str(url) for url in urls[:8]]
    if sample:
        summary += "\n  - " + "\n  - ".join(sample)
    return summary


def _read_local_archive(
    orchestration_id: str,
    evidence_root: Path,
) -> str | None:
    """Summarize the Phase 3D local page-snapshot archive."""

    index = (
        evidence_root
        / orchestration_id
        / "crawling"
        / "archive"
        / "archive-index.json"
    )
    if not index.exists():
        return None
    try:
        payload = json.loads(index.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    archived = payload.get("archived", 0)
    attempted = payload.get("attempted", 0)
    summary = f"local-archive: {archived}/{attempted} pages saved locally"
    sample = [
        str(entry.get("url"))
        for entry in (payload.get("entries") or [])
        if isinstance(entry, dict) and entry.get("sha256")
    ][:6]
    if sample:
        summary += "\n  - " + "\n  - ".join(sample)
    return summary


def gather_run_digest(
    database: SaarthiDatabase,
    *,
    orchestration_id: str | None = None,
    evidence_root: Path = DEFAULT_ORCHESTRATION_EVIDENCE_ROOT,
) -> RunDigest:
    """Assemble a bounded digest of the latest (or given) run for analysis."""

    executions = database.list_executions(limit=1_000)
    if not executions:
        raise AnalysisError("No executions are stored; run an assessment first.")

    parent = _latest_parent(executions, orchestration_id)
    if parent is None:
        raise AnalysisError(
            "No orchestration-parent execution found to analyze."
        )
    if not parent.targets:
        raise AnalysisError(
            f"Execution {parent.execution_id} has no target."
        )

    meta = _metadata(parent)
    oid = meta.get("orchestration_id")
    children = [
        execution
        for execution in executions
        if _metadata(execution).get("orchestration_id") == oid
        and _metadata(execution).get("execution_role") == "orchestration_child"
    ]
    children.sort(key=lambda execution: execution.created_at)

    phases = tuple(
        (
            str(_metadata(child).get("phase_code", "?")),
            child.state.value,
        )
        for child in children
    )

    findings: list[str] = []
    failures: list[str] = []
    evidence_counts: Counter[str] = Counter()
    evidence_signals: list[str] = []

    for execution in [parent, *children]:
        phase_code = _metadata(execution).get("phase_code", "-")
        for event in database.list_audit_events(execution.execution_id):
            if event.event_type is AuditEventType.FINDING_CREATED:
                detail = _compact_metadata(event.details or {})
                findings.append(
                    f"[{phase_code}] {event.message}"
                    + (f" ({detail})" if detail else "")
                )
            elif event.event_type is AuditEventType.TOOL_FAILED:
                failures.append(f"[{phase_code}] {event.message}"[:200])

        for evidence in database.list_evidence(execution.execution_id):
            evidence_counts[evidence.evidence_type.value] += 1
            signal = _compact_metadata(evidence.metadata or {})
            if signal:
                evidence_signals.append(
                    f"[{phase_code}] {evidence.evidence_type.value}: {signal}"
                )

    nuclei_summary = sqlmap_summary = None
    ghauri_summary = xsstrike_summary = wayback_summary = None
    archive_summary = None
    verified_lines: list[str] = []
    if isinstance(oid, str) and oid:
        (
            nuclei_summary,
            sqlmap_summary,
            ghauri_summary,
            xsstrike_summary,
            verified_lines,
        ) = _read_auto_validation(oid, evidence_root)
        wayback_summary = _read_wayback_intel(oid, evidence_root)
        archive_summary = _read_local_archive(oid, evidence_root)

    return RunDigest(
        orchestration_id=oid if isinstance(oid, str) else None,
        target=str(parent.targets[0]),
        parent_state=parent.state.value,
        assessment_name=parent.assessment_name,
        phases=phases,
        findings=tuple(findings[:MAX_FINDINGS]),
        failures=tuple(failures[:MAX_FAILURES]),
        evidence_counts=dict(evidence_counts),
        evidence_signals=tuple(evidence_signals[:MAX_EVIDENCE_SIGNALS]),
        verified_findings=tuple(verified_lines),
        nuclei_summary=nuclei_summary,
        sqlmap_summary=sqlmap_summary,
        ghauri_summary=ghauri_summary,
        xsstrike_summary=xsstrike_summary,
        wayback_summary=wayback_summary,
        archive_summary=archive_summary,
    )


LIVE_WATCH_SYSTEM_PROMPT = (
    "You are a senior offensive-security analyst watching an AUTHORIZED VAPT "
    "scanner run live. Given the latest raw output lines from the tool, reply "
    "in ONE or TWO short sentences noting anything notable so far — a finding, "
    "an injection/DBMS signal, a WAF/IPS block, or say 'progressing, nothing "
    "notable yet' when there is nothing. Analyze ONLY what is shown; never "
    "invent findings, hosts, or data. No preamble, no lists."
)


async def comment_on_live_output(
    client: SaarthiOllamaClient,
    tool_name: str,
    target: str,
    lines: list[str],
    *,
    num_predict: int = 110,
) -> str:
    """Terse live AI note on streamed tool output while a scan is running."""

    excerpt = "\n".join(line.strip() for line in lines if line.strip())[-1800:]
    prompt = (
        f"Tool: {tool_name}\nTarget: {target}\n"
        f"Latest output lines:\n{excerpt or '(no new output)'}"
    )
    content, _thinking = await client.chat(
        [Message(role="user", content=prompt)],
        system_prompt=LIVE_WATCH_SYSTEM_PROMPT,
        num_predict=num_predict,
    )
    return content


def build_analysis_prompt(digest: RunDigest) -> str:
    """Render the digest as the user message for the analyst model."""

    lines: list[str] = [
        "AUTHORIZED VAPT run evidence to triage:",
        f"Target: {digest.target}",
        f"Assessment: {digest.assessment_name}",
        f"Overall state: {digest.parent_state}",
        "",
        "Phase outcomes:",
    ]
    lines += [f"  {code}: {state}" for code, state in digest.phases] or [
        "  (none)"
    ]

    counts = ", ".join(
        f"{name}={count}" for name, count in sorted(digest.evidence_counts.items())
    )
    lines += ["", f"Evidence collected: {counts or '(none)'}"]

    lines += ["", f"Findings ({len(digest.findings)}):"]
    lines += [f"  - {item}" for item in digest.findings] or [
        "  - none recorded"
    ]

    if digest.verified_findings:
        lines += [
            "",
            "Verified findings (auto re-checked; prefer CONFIRMED, "
            "treat FALSE_POSITIVE as noise):",
        ]
        lines += [f"  - {item}" for item in digest.verified_findings]

    if digest.evidence_signals:
        lines += ["", "Observation signals:"]
        lines += [f"  - {item}" for item in digest.evidence_signals]

    if digest.nuclei_summary:
        lines += ["", "Nuclei:", f"  {digest.nuclei_summary}"]
    if digest.sqlmap_summary:
        lines += ["", "SQLMap:", digest.sqlmap_summary]
    if digest.ghauri_summary:
        lines += [
            "",
            "Ghauri (blind-SQLi cross-check):",
            digest.ghauri_summary,
        ]
    if digest.xsstrike_summary:
        lines += ["", "XSStrike (XSS):", digest.xsstrike_summary]
    if digest.wayback_summary:
        lines += [
            "",
            "Wayback URL intelligence:",
            f"  {digest.wayback_summary}",
        ]
    if digest.archive_summary:
        lines += [
            "",
            "Local page archive:",
            f"  {digest.archive_summary}",
        ]

    if digest.failures:
        lines += ["", "Phase failures:"]
        lines += [f"  - {item}" for item in digest.failures]

    lines += [
        "",
        "Triage this evidence per your instructions.",
    ]
    return "\n".join(lines)


async def analyze_run(
    client: SaarthiOllamaClient,
    digest: RunDigest,
    *,
    num_predict: int = MAX_ANALYSIS_TOKENS,
) -> str:
    """Send the digest to the local model and return its triage text."""

    prompt = build_analysis_prompt(digest)
    content, _thinking = await client.chat(
        [Message(role="user", content=prompt)],
        system_prompt=ANALYST_SYSTEM_PROMPT,
        num_predict=num_predict,
    )
    return content


# --- Real-time, per-phase advisory -------------------------------------------

MAX_PHASE_TOOL_LINES = 14
MAX_PHASE_SIGNALS = 10
MAX_PHASE_TOKENS = 400

PHASE_ADVISOR_SYSTEM_PROMPT = (
    "You are the operator's live AI co-pilot during an AUTHORIZED VAPT. A "
    "single phase just finished. From ONLY its evidence, give 2-4 short, "
    "specific, actionable suggestions: what's notable, what to investigate "
    "next, and concrete attack angles worth trying (name parameters, paths, "
    "headers, endpoints where possible). Terse bullet points, no preamble, "
    "no fabrication. If nothing actionable, say 'nothing notable' in one line."
)


@dataclass(frozen=True)
class PhaseDigest:
    """Bounded evidence summary for a single completed phase."""

    phase_code: str
    phase_name: str
    state: str
    target: str
    findings: tuple[str, ...] = ()
    signals: tuple[str, ...] = ()
    tool_lines: tuple[str, ...] = ()


def gather_phase_digest(
    database: SaarthiDatabase,
    execution: ExecutionRecord,
    *,
    target: str,
) -> PhaseDigest:
    """Assemble a bounded digest for one completed child execution."""

    meta = _metadata(execution)
    findings: list[str] = []
    tool_lines: list[str] = []

    for event in database.list_audit_events(execution.execution_id):
        if event.event_type is AuditEventType.FINDING_CREATED:
            detail = _compact_metadata(event.details or {})
            findings.append(
                event.message + (f" ({detail})" if detail else "")
            )
        elif event.event_type in (
            AuditEventType.TOOL_OUTPUT,
            AuditEventType.TOOL_COMPLETED,
            AuditEventType.TOOL_FAILED,
        ):
            tool_lines.append(event.message[:200])

    signals: list[str] = []
    for evidence in database.list_evidence(execution.execution_id):
        signal = _compact_metadata(evidence.metadata or {})
        if signal:
            signals.append(f"{evidence.evidence_type.value}: {signal}")

    return PhaseDigest(
        phase_code=str(meta.get("phase_code", "?")),
        phase_name=str(meta.get("phase_name", "")),
        state=execution.state.value,
        target=target,
        findings=tuple(findings),
        signals=tuple(signals[:MAX_PHASE_SIGNALS]),
        tool_lines=tuple(tool_lines[-MAX_PHASE_TOOL_LINES:]),
    )


def build_phase_prompt(digest: PhaseDigest) -> str:
    """Render a single-phase digest as the advisor user message."""

    lines = [
        f"Target: {digest.target}",
        f"Phase {digest.phase_code} ({digest.phase_name}) — {digest.state}.",
    ]
    if digest.findings:
        lines += ["Findings:"]
        lines += [f"  - {item}" for item in digest.findings]
    if digest.signals:
        lines += ["Observed signals:"]
        lines += [f"  - {item}" for item in digest.signals]
    if digest.tool_lines:
        lines += ["Tool output:"]
        lines += [f"  - {item}" for item in digest.tool_lines]
    if not (digest.findings or digest.signals or digest.tool_lines):
        lines += ["(no notable evidence recorded for this phase)"]
    lines += ["", "Give your live suggestions for this phase."]
    return "\n".join(lines)


async def suggest_for_phase(
    client: SaarthiOllamaClient,
    digest: PhaseDigest,
    *,
    num_predict: int = MAX_PHASE_TOKENS,
) -> str:
    """Ask the local model for live suggestions about one phase."""

    prompt = build_phase_prompt(digest)
    content, _thinking = await client.chat(
        [Message(role="user", content=prompt)],
        system_prompt=PHASE_ADVISOR_SYSTEM_PROMPT,
        num_predict=num_predict,
    )
    return content


ADAPT_ADVISOR_SYSTEM_PROMPT = (
    "You are a VAPT tool operator. In ONE short sentence, explain why this "
    "adaptive change to the running scanner is reasonable and what it should "
    "achieve. No preamble, no list."
)


async def explain_adaptation(
    client: SaarthiOllamaClient,
    event: AdaptationEvent,
    *,
    num_predict: int = 80,
) -> str:
    """One-line AI rationale for an adaptive tool change."""

    args_preview = " ".join(event.arguments)[:280]
    prompt = (
        f"Scanner {event.tool_name} hit condition "
        f"'{event.condition.value}' (attempt {event.attempt}). "
        f"Adaptation applied: {event.note}. New arguments include: "
        f"{args_preview}. Explain in one sentence."
    )
    content, _thinking = await client.chat(
        [Message(role="user", content=prompt)],
        system_prompt=ADAPT_ADVISOR_SYSTEM_PROMPT,
        num_predict=num_predict,
    )
    return content
