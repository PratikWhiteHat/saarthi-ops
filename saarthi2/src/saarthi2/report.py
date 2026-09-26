"""Report generation — render a run + its findings to Markdown/JSON.

Mirrors Osmedeus's report/artifact-export: after (or during) a run, turn the
stored runs/steps/findings rows into a human-readable Markdown report and a
machine-readable JSON summary. Pure functions over plain dicts so they are
trivially testable and reusable by the CLI and the API.
"""

from __future__ import annotations

import json
from typing import Any

# Highest-impact first; anything unknown sorts last.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")


def _sev_rank(severity: str) -> int:
    sev = (severity or "unknown").lower()
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


def severity_counts(findings: list[dict]) -> dict[str, int]:
    """Count findings per severity, in impact order (zeros omitted)."""

    counts: dict[str, int] = {}
    for finding in findings:
        sev = str(finding.get("severity", "unknown")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    return {sev: counts[sev] for sev in SEVERITY_ORDER if sev in counts}


def findings_table(findings: list[dict]) -> str:
    """Render findings as a Markdown table, most-severe first."""

    if not findings:
        return "_No findings recorded._"
    ordered = sorted(findings, key=lambda f: _sev_rank(str(f.get("severity", ""))))
    lines = [
        "| Severity | Tool | Rule | Message | Location |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in ordered:
        cells = [
            str(finding.get("severity", "")).lower(),
            str(finding.get("tool", "")),
            str(finding.get("rule_id", "")),
            str(finding.get("message", "")).replace("|", "\\|").replace("\n", " ")[:160],
            str(finding.get("location", "")).replace("|", "\\|")[:120],
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def steps_table(steps: list[dict]) -> str:
    """Render the step timeline as a Markdown table."""

    if not steps:
        return "_No steps recorded._"
    lines = ["| Step | Status | Exit | ms | Error |", "| --- | --- | --- | --- | --- |"]
    for step in steps:
        cells = [
            str(step.get("step_id", "")),
            str(step.get("status", "")),
            "" if step.get("exit_code") is None else str(step.get("exit_code")),
            str(step.get("duration_ms", "")),
            str(step.get("error") or "").replace("|", "\\|").replace("\n", " ")[:100],
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def render_markdown(
    run: dict | None, steps: list[dict], findings: list[dict]
) -> str:
    """Full Markdown report for a run."""

    run = run or {}
    counts = severity_counts(findings)
    summary = ", ".join(f"{sev}: {n}" for sev, n in counts.items()) or "none"
    parts = [
        f"# Saarthi 2.0 Report — {run.get('workflow', 'run')}",
        "",
        f"- **Run ID:** `{run.get('run_id', '-')}`",
        f"- **Target:** {run.get('target') or '-'}",
        f"- **Status:** {run.get('status', '-')}",
        f"- **Started:** {run.get('created_at', '-')}",
        f"- **Findings:** {len(findings)} ({summary})",
        "",
        "## Findings",
        "",
        findings_table(findings),
        "",
        "## Steps",
        "",
        steps_table(steps),
        "",
    ]
    return "\n".join(parts)


def render_json(run: dict | None, steps: list[dict], findings: list[dict]) -> str:
    """Machine-readable summary of a run."""

    payload: dict[str, Any] = {
        "run": run or {},
        "severity_counts": severity_counts(findings),
        "findings": findings,
        "steps": steps,
    }
    return json.dumps(payload, indent=2, default=str)
