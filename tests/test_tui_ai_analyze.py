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
        parent_execution_id="execution-parent",
        findings=("SQLi on id",),
        phases=(("3A", "completed"),),
        parent_state="completed",
    )
    monkeypatch.setattr(
        "saarthi_ai.analysis.gather_run_digest",
        lambda database, **kwargs: digest,
    )

    result = SimpleNamespace(findings=("finding",))

    async def fake_analyze(client, run_digest, **kwargs):
        return result

    monkeypatch.setattr(
        "saarthi_ai.analysis.analyze_run_quality", fake_analyze
    )
    monkeypatch.setattr(
        "saarthi_ai.analysis.render_quality_analysis",
        lambda value: (
            "Executive summary: 1 High SQLi.\nRemediation: parameterize."
        ),
    )
    monkeypatch.setattr(
        "saarthi_ai.analysis.persist_quality_analysis",
        lambda *args, **kwargs: SimpleNamespace(
            evidence_id="evidence-ai", path="/tmp/evidence-ai.json"
        ),
    )

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
        raise AnalysisError(
            "No orchestration parent [type=missing_record] found to analyze."
        )

    monkeypatch.setattr(
        "saarthi_ai.analysis.gather_run_digest", raise_no_run
    )

    ran = {"analyze": False}

    async def fake_analyze(client, run_digest, **kwargs):
        ran["analyze"] = True
        return "should not be called"

    monkeypatch.setattr(
        "saarthi_ai.analysis.analyze_run_quality", fake_analyze
    )

    app = SaarthiDashboard(database_path=tmp_path / "missing.db")
    async with app.run_test() as pilot:
        await pilot.press("a")
        await app.workers.wait_for_complete()
        await pilot.pause()

        assert app._analysis_running is False
        assert ran["analyze"] is False
        assert "[AI][ERR]" in "\n".join(app._live_validation_lines)


@pytest.mark.asyncio
async def test_ai_analyze_uses_interim_snapshot_during_assessment(tmp_path, monkeypatch):
    digest = SimpleNamespace(
        target="https://app.example.com/item?id=1",
        orchestration_id="orchestration-running",
        parent_execution_id="execution-parent",
        findings=(),
        phases=(("3A", "completed"), ("3B", "running")),
        parent_state="running",
    )
    monkeypatch.setattr(
        "saarthi_ai.analysis.gather_run_digest",
        lambda database, **kwargs: digest,
    )
    stages = []

    async def fake_analyze(client, run_digest, **kwargs):
        stages.append("analyzed")
        return SimpleNamespace(model_copy=lambda update: SimpleNamespace(**update))

    monkeypatch.setattr(
        "saarthi_ai.analysis.analyze_run_quality",
        fake_analyze,
    )
    monkeypatch.setattr(
        "saarthi_ai.analysis.persist_quality_analysis",
        lambda database, execution_id, result, **kwargs: (
            stages.append(result.analysis_stage)
            or SimpleNamespace(evidence_id="evidence-interim", path="/tmp/interim.json")
        ),
    )
    monkeypatch.setattr(
        "saarthi_ai.analysis.render_quality_analysis",
        lambda result: "Interim evidence review.",
    )

    app = SaarthiDashboard(database_path=tmp_path / "running.db")
    async with app.run_test() as pilot:
        await pilot.press("a")
        await app.workers.wait_for_complete()
        await pilot.pause()

        assert stages == ["analyzed", "interim"]
        assert "Interim evidence review" in "\n".join(app._live_validation_lines)


@pytest.mark.asyncio
async def test_ai_observer_comments_per_phase(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
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
    for code in ("3A", "3B", "4A-cors"):
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

    async def fake_phase_agent(client, execution_id, digest):
        from saarthi_ai.analysis.phase_agents import PhaseAgentReview

        return PhaseAgentReview(
            execution_id, digest.phase_code, "recon", "grounded",
            evidence_refs=("evidence-test",),
            skills_supplied=("hunt-sqli",),
            note=f"- suggestion for {digest.phase_code} [evidence-test]",
        )

    run_stages = []
    async def fake_run(client, digest, **kwargs):
        run_stages.append("analysis")
        app._validation_running = False
        return SimpleNamespace(
            findings=(), skill_assessments=(),
            model_copy=lambda update: SimpleNamespace(
                findings=(), skill_assessments=(), **update
            ),
        )

    monkeypatch.setattr(
        "saarthi_ai.analysis.phase_agents.review_phase_agent",
        fake_phase_agent,
    )
    monkeypatch.setattr(
        "saarthi_ai.analysis.analyze_run_quality", fake_run
    )
    monkeypatch.setattr(
        "saarthi_ai.analysis.render_quality_analysis",
        lambda result: "Final triage: nothing critical.",
    )
    monkeypatch.setattr(
        "saarthi_ai.analysis.persist_quality_analysis",
        lambda database, execution_id, result, **kwargs: (
            run_stages.append(getattr(result, "analysis_stage", "final"))
            or SimpleNamespace(evidence_id="evidence-ai", path="/tmp/evidence-ai.json")
        ),
    )

    app = SaarthiDashboard(database_path=path)
    async with app.run_test() as pilot:
        app._validation_running = True
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
        assert run_stages == ["analysis", "interim", "analysis", "final"]
        assert "Interim evidence review stored" in joined
        assert "Phase-agent supervisor" in joined
        assert (tmp_path / "evidence" / "ai-agents" / oid / "supervisor.json").exists()
