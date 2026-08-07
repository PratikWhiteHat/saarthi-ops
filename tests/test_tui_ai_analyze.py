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


@pytest.mark.asyncio
async def test_ai_observer_comments_per_phase(tmp_path, monkeypatch):
    from saarthi_ai.persistence.database import SaarthiDatabase
    from saarthi_ai.persistence.models import ExecutionCreate

    path = tmp_path / "obs.db"
    database = SaarthiDatabase(path)
    database.initialize()
    oid = "orchestration-obs-1"
    database.create_execution(
        ExecutionCreate(
            assessment_name="Obs",
            asset_types=["url"],
            targets=["https://app.example.com/item?id=1"],
            authorization_confirmed=True,
            active_testing_allowed=True,
            metadata={
                "execution_role": "orchestration_parent",
                "orchestration_id": oid,
            },
        )
    )
    for code in ("3A", "3B"):
        database.create_execution(
            ExecutionCreate(
                assessment_name="Obs",
                asset_types=["url"],
                targets=["https://app.example.com/item?id=1"],
                authorization_confirmed=True,
                active_testing_allowed=True,
                metadata={
                    "execution_role": "orchestration_child",
                    "orchestration_id": oid,
                    "phase_code": code,
                    "phase_name": f"Phase {code}",
                },
            )
        )
    # Mark children terminal so the observer comments on them.
    from saarthi_ai.persistence.models import ExecutionState

    for execution in database.list_executions(limit=50):
        if (execution.metadata or {}).get("execution_role") == (
            "orchestration_child"
        ):
            for state in (
                ExecutionState.VALIDATED,
                ExecutionState.PLANNED,
                ExecutionState.RUNNING,
                ExecutionState.ANALYZING,
                ExecutionState.COMPLETED,
            ):
                database.transition_execution(
                    execution.execution_id, state, actor="test"
                )

    async def fake_phase(client, digest, **kwargs):
        return f"- suggestion for {digest.phase_code}"

    async def fake_run(client, digest, **kwargs):
        return "Final triage: nothing critical."

    monkeypatch.setattr("saarthi_ai.analysis.suggest_for_phase", fake_phase)
    monkeypatch.setattr("saarthi_ai.analysis.analyze_run", fake_run)

    app = SaarthiDashboard(database_path=path)
    async with app.run_test() as pilot:
        app._validation_running = False  # observer does one pass then finishes
        app.run_worker(
            lambda: app._run_ai_observer_worker(oid),
            thread=True,
        )
        await app.workers.wait_for_complete()
        await pilot.pause()

        assert app._ai_observer_running is False
        joined = "\n".join(app._live_validation_lines)
        assert "suggestion for 3A" in joined
        assert "suggestion for 3B" in joined
        assert "Final triage" in joined
