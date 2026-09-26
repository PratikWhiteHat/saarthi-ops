"""Markdown/JSON run reporting."""

from __future__ import annotations

import json

from saarthi2.report import (
    findings_table,
    render_json,
    render_markdown,
    severity_counts,
    steps_table,
)

_FINDINGS = [
    {"severity": "low", "tool": "nuclei", "rule_id": "r1", "message": "minor", "location": "u1"},
    {"severity": "critical", "tool": "nuclei", "rule_id": "r2", "message": "boom", "location": "2"},
    {"severity": "medium", "tool": "semgrep", "rule_id": "r3", "message": "mid", "location": "u3"},
]


def test_severity_counts_ordered() -> None:
    counts = severity_counts(_FINDINGS)
    assert list(counts) == ["critical", "medium", "low"]
    assert counts == {"critical": 1, "medium": 1, "low": 1}


def test_findings_table_most_severe_first() -> None:
    table = findings_table(_FINDINGS)
    body = [row for row in table.splitlines() if row.startswith("| ") and "---" not in row][1:]
    # first data row is the critical finding
    assert "critical" in body[0]
    assert "low" in body[-1]


def test_findings_table_escapes_pipes() -> None:
    table = findings_table([{"severity": "info", "message": "a|b", "tool": "t"}])
    assert "a\\|b" in table


def test_empty_tables() -> None:
    assert findings_table([]) == "_No findings recorded._"
    assert steps_table([]) == "_No steps recorded._"


def test_render_markdown_has_sections() -> None:
    run = {"run_id": "r1", "workflow": "recon", "target": "ex.com", "status": "completed"}
    steps = [{"step_id": "a", "status": "completed", "exit_code": 0, "duration_ms": 5}]
    md = render_markdown(run, steps, _FINDINGS)
    assert "# Saarthi 2.0 Report — recon" in md
    assert "## Findings" in md and "## Steps" in md
    assert "critical: 1" in md


def test_render_json_roundtrips() -> None:
    run = {"run_id": "r1", "workflow": "recon"}
    payload = json.loads(render_json(run, [], _FINDINGS))
    assert payload["run"]["run_id"] == "r1"
    assert payload["severity_counts"]["critical"] == 1
    assert len(payload["findings"]) == 3
