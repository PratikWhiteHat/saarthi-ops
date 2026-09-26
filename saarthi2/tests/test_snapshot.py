"""Snapshot export (render_json) -> import round-trip."""

from __future__ import annotations

import json

from saarthi2.engine.models import RunResult, StepResult, StepStatus
from saarthi2.report import render_json
from saarthi2.state import Store


def _store(tmp_path, name="db") -> Store:
    return Store(tmp_path / f"{name}.sqlite", tmp_path / f"{name}-ev", tmp_path / f"{name}.jsonl")


def _seed(store: Store) -> str:
    run = RunResult(
        run_id="run-xyz", workflow="vuln", target="https://ex.com/a",
        workspace="ex_com_a", status=StepStatus.COMPLETED,
    )
    store.create_run(run)
    store.update_run(run)
    store.record_step(
        "run-xyz",
        StepResult(step_id="nuclei", status=StepStatus.COMPLETED, exit_code=0, duration_ms=12),
    )
    store.record_findings(
        "run-xyz",
        [{"tool": "nuclei", "rule_id": "cve-1", "severity": "high", "message": "x"}],
    )
    return "run-xyz"


def test_snapshot_roundtrip(tmp_path) -> None:
    src = _store(tmp_path, "src")
    run_id = _seed(src)
    payload = json.loads(
        render_json(src.get_run(run_id), src.list_steps(run_id), src.list_findings(run_id=run_id))
    )
    src.close()

    dst = _store(tmp_path, "dst")
    imported = dst.import_snapshot(payload)
    assert imported == "run-xyz"
    run = dst.get_run("run-xyz")
    assert run["workflow"] == "vuln"
    assert run["workspace"] == "ex_com_a"
    assert len(dst.list_steps("run-xyz")) == 1
    findings = dst.list_findings(run_id="run-xyz")
    assert len(findings) == 1 and findings[0]["severity"] == "high"
    dst.close()


def test_snapshot_import_new_run_id(tmp_path) -> None:
    src = _store(tmp_path, "src")
    run_id = _seed(src)
    payload = json.loads(
        render_json(src.get_run(run_id), src.list_steps(run_id), src.list_findings(run_id=run_id))
    )
    src.close()

    dst = _store(tmp_path, "dst")
    imported = dst.import_snapshot(payload, new_run_id="run-copy")
    assert imported == "run-copy"
    assert dst.get_run("run-copy") is not None
    assert dst.get_run("run-xyz") is None
    dst.close()


def test_import_without_run_id_errors(tmp_path) -> None:
    dst = _store(tmp_path, "dst")
    try:
        import pytest

        with pytest.raises(ValueError):
            dst.import_snapshot({"run": {}})
    finally:
        dst.close()
