"""TUI test for the 'a' AI-analyze action (LLM fully stubbed)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from saarthi_ai.tui.app import SaarthiDashboard


@pytest.mark.asyncio
async def test_pressing_a_streams_ai_analysis(tmp_path, monkeypatch):
    digest = SimpleNamespace(
        target="https://app.example.com/item?id=1",
        orchestration_id="orchestration-x",
        findings=("SQLi on id",),
        phases=(("3A", "completed"),),
        parent_state="completed",
    )
    monkeypatch.setattr(
        "saarthi_ai.analysis.gather_run_digest",
        lambda database, **kwargs: digest,
    )

    async def fake_analyze(client, run_digest, **kwargs):
        return "Executive summary: 1 High SQLi.\nRemediation: parameterize."

    monkeypatch.setattr("saarthi_ai.analysis.analyze_run", fake_analyze)

    app = SaarthiDashboard(database_path=tmp_path / "missing.db")
    async with app.run_test() as pilot:
        await pilot.press("a")
        await app.workers.wait_for_complete()
        await pilot.pause()

        assert app._analysis_running is False
        joined = "\n".join(app._live_validation_lines)
        assert "[AI]" in joined
        assert "Executive summary: 1 High SQLi." in joined
        assert "Remediation: parameterize." in joined


@pytest.mark.asyncio
async def test_ai_analyze_reports_missing_run(tmp_path, monkeypatch):
    from saarthi_ai.analysis import AnalysisError

    def raise_no_run(database, **kwargs):
        raise AnalysisError("No orchestration-parent execution found to analyze.")

    monkeypatch.setattr(
        "saarthi_ai.analysis.gather_run_digest", raise_no_run
    )

    ran = {"analyze": False}

    async def fake_analyze(client, run_digest, **kwargs):
        ran["analyze"] = True
        return "should not be called"

    monkeypatch.setattr("saarthi_ai.analysis.analyze_run", fake_analyze)

    app = SaarthiDashboard(database_path=tmp_path / "missing.db")
    async with app.run_test() as pilot:
        await pilot.press("a")
        await app.workers.wait_for_complete()
        await pilot.pause()

        assert app._analysis_running is False
        assert ran["analyze"] is False
        assert "[AI][ERR]" in "\n".join(app._live_validation_lines)
