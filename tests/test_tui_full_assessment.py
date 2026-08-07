"""End-to-end TUI test for the typed-URL full-assessment flow.

The orchestration pipeline, Phase 6 chain, config derivation, and tool
runner are all stubbed, so this performs no network activity and needs no
external tools. It verifies the input -> worker -> pipeline -> scan wiring.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from textual.widgets import Input

from saarthi_ai.automation.auto_validation import AutomaticValidationResult
from saarthi_ai.execution.tool_runner import ToolOutputEvent
from saarthi_ai.orchestration.models import OrchestrationContext
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.tui.app import SaarthiDashboard


def _init_db(tmp_path):
    path = tmp_path / "adhoc.db"
    SaarthiDatabase(path).initialize()
    return path


def _install_stubs(monkeypatch, calls, captured):
    context = OrchestrationContext(
        orchestration_id="orchestration-tui-adhoc",
        parent_execution_id="execution-adhoc-1",
        target_url="https://app.example.com/item?id=1",
        target_domain="app.example.com",
    )

    def fake_create_orchestration(database, **kwargs):
        calls.append("create_orchestration")
        captured["target_url"] = kwargs.get("target_url")
        captured["intrusive"] = kwargs.get("intrusive_testing_allowed")
        return context

    def fake_pipeline(database, ctx, **kwargs):
        calls.append("run_assessment_pipeline")
        phase = SimpleNamespace(
            phase=SimpleNamespace(value="3A"),
            outcome=SimpleNamespace(value="completed"),
        )
        return SimpleNamespace(context=ctx, phase_results=[phase])

    async def fake_chain(database, ctx, **kwargs):
        calls.append("run_phase6_safe_chain")
        return None

    def fake_build(database, **kwargs):
        calls.append("build_config")
        captured["confirmed_poc"] = kwargs.get("confirmed_poc")
        return SimpleNamespace(
            config=SimpleNamespace(),
            target_url="https://app.example.com/item?id=1",
            sqlmap_parameters=("id",),
        )

    def fake_run(config, *, on_output=None, on_log=None):
        calls.append("run_automatic_validation")
        if on_log is not None:
            on_log("[fake] scanning")
        if on_output is not None:
            on_output(
                ToolOutputEvent(
                    tool_name="nuclei",
                    stream="stdout",
                    line="fake-finding-line",
                )
            )
        return AutomaticValidationResult(
            run_id="run-1",
            started_at="2026-01-01T00:00:00Z",
            completed_at="2026-01-01T00:00:01Z",
            evidence_path="/tmp/evidence/run-1/automatic-validation.json",
            nuclei={"exit_code": 0},
            sqlmap=(),
        )

    monkeypatch.setattr(
        "saarthi_ai.persistence.orchestration_workflow.create_orchestration",
        fake_create_orchestration,
    )
    monkeypatch.setattr(
        "saarthi_ai.persistence.orchestration_workflow.run_assessment_pipeline",
        fake_pipeline,
    )
    monkeypatch.setattr(
        "saarthi_ai.persistence.phase6_chain_workflow.run_phase6_safe_chain",
        fake_chain,
    )
    monkeypatch.setattr(
        "saarthi_ai.automation.chain_config."
        "build_auto_validation_config_from_chain",
        fake_build,
    )
    monkeypatch.setattr(
        "saarthi_ai.automation.auto_validation.run_automatic_validation",
        fake_run,
    )


@pytest.mark.asyncio
async def test_typed_url_runs_full_assessment(tmp_path, monkeypatch):
    path = _init_db(tmp_path)
    calls: list[str] = []
    captured: dict = {}
    _install_stubs(monkeypatch, calls, captured)

    app = SaarthiDashboard(database_path=path)
    async with app.run_test() as pilot:
        url_input = app.query_one("#target-url-input", Input)
        url_input.focus()
        url_input.value = "https://app.example.com/item?id=1"
        await pilot.press("enter")
        await app.workers.wait_for_complete()
        await pilot.pause()

        assert app._validation_running is False
        # Full pipeline ran in order, then the real scan.
        assert calls == [
            "create_orchestration",
            "run_assessment_pipeline",
            "run_phase6_safe_chain",
            "build_config",
            "run_automatic_validation",
        ]
        assert captured["target_url"] == "https://app.example.com/item?id=1"
        assert captured["intrusive"] is True
        assert captured["confirmed_poc"] is True

        joined = "\n".join(app._live_validation_lines)
        assert "recon pipeline" in joined.lower()
        assert "fake-finding-line" in joined
        assert "Full assessment complete" in joined


@pytest.mark.asyncio
async def test_invalid_url_is_rejected(tmp_path, monkeypatch):
    path = _init_db(tmp_path)
    calls: list[str] = []
    captured: dict = {}
    _install_stubs(monkeypatch, calls, captured)

    app = SaarthiDashboard(database_path=path)
    async with app.run_test() as pilot:
        url_input = app.query_one("#target-url-input", Input)
        url_input.focus()
        url_input.value = "not-a-url"
        await pilot.press("enter")
        await app.workers.wait_for_complete()
        await pilot.pause()

        assert app._validation_running is False
        assert calls == []
