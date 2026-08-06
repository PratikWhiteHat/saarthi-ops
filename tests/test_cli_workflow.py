"""CLI tests for Phase 5 assessment orchestration."""

from __future__ import annotations

from types import SimpleNamespace

from typer.testing import CliRunner

from saarthi_ai.cli import app
from saarthi_ai.orchestration.models import (
    OrchestrationPhase,
    OrchestrationStatus,
)
from saarthi_ai.persistence.orchestration_workflow import (
    OrchestrationWorkflowError,
)

runner = CliRunner()


def test_workflow_command_is_available() -> None:
    result = runner.invoke(
        app,
        ["workflow", "--help"],
    )

    assert result.exit_code == 0
    assert "run" in result.stdout
    assert "multi-phase assessment workflows" in result.stdout


def test_workflow_run_requires_authorization() -> None:
    result = runner.invoke(
        app,
        [
            "workflow",
            "run",
            "--url",
            "https://example.com/",
            "--active",
            "--approved",
        ],
    )

    assert result.exit_code == 1
    assert "Authorization confirmation required" in result.stdout


def test_workflow_run_requires_active_testing_approval() -> None:
    result = runner.invoke(
        app,
        [
            "workflow",
            "run",
            "--url",
            "https://example.com/",
            "--authorized",
            "--approved",
        ],
    )

    assert result.exit_code == 1
    assert "Active-testing approval required" in result.stdout


def test_workflow_run_requires_explicit_approval() -> None:
    result = runner.invoke(
        app,
        [
            "workflow",
            "run",
            "--url",
            "https://example.com/",
            "--authorized",
            "--active",
        ],
    )

    assert result.exit_code == 1
    assert "Explicit execution approval required" in result.stdout


def test_workflow_nuclei_execution_requires_preview_approval() -> None:
    result = runner.invoke(
        app,
        [
            "workflow",
            "run",
            "--url",
            "https://example.com/",
            "--authorized",
            "--active",
            "--approved",
            "--execute-nuclei",
        ],
    )

    assert result.exit_code == 1
    assert "Nuclei preview approval required" in result.stdout


def test_workflow_run_forwards_scope_and_prints_results(
    tmp_path,
    monkeypatch,
) -> None:
    import saarthi_ai.cli as cli_module

    captured: dict[str, object] = {}
    database = object()

    context = SimpleNamespace(
        orchestration_id="orchestration-test",
        parent_execution_id="execution-parent",
        target_url="https://example.com/",
        target_domain="example.com",
    )

    def fake_create_orchestration(
        database_argument,
        *,
        assessment_name,
        target_url,
        active_testing_allowed,
        intrusive_testing_allowed,
        rate_limit_per_second,
        actor,
    ):
        captured["create_database"] = database_argument
        captured["assessment_name"] = assessment_name
        captured["target_url"] = target_url
        captured["active_testing_allowed"] = active_testing_allowed
        captured["intrusive_testing_allowed"] = (
            intrusive_testing_allowed
        )
        captured["rate_limit_per_second"] = rate_limit_per_second
        captured["create_actor"] = actor
        return context

    def phase_result(
        phase: OrchestrationPhase,
        suffix: str,
    ) -> SimpleNamespace:
        return SimpleNamespace(
            phase=phase,
            outcome=SimpleNamespace(value="completed"),
            required=True,
            execution_id=f"execution-{suffix}",
            evidence_id=f"evidence-{suffix}",
            evidence_path=str(
                tmp_path / "evidence" / f"{suffix}.json"
            ),
            reason=None,
            error_summary=None,
            metrics={},
        )

    workflow_result = SimpleNamespace(
        context=SimpleNamespace(
            parent_execution_id="execution-parent",
            status=OrchestrationStatus.COMPLETED,
        ),
        dns=phase_result(OrchestrationPhase.DNS, "dns"),
        subdomains=phase_result(
            OrchestrationPhase.SUBDOMAINS,
            "subdomains",
        ),
        http_intelligence=phase_result(
            OrchestrationPhase.HTTP_INTELLIGENCE,
            "http",
        ),
        crawl=phase_result(
            OrchestrationPhase.CRAWL,
            "crawl",
        ),
        javascript=phase_result(
            OrchestrationPhase.JAVASCRIPT,
            "javascript",
        ),
        security_headers=phase_result(
            OrchestrationPhase.SECURITY_HEADERS,
            "security-headers",
        ),
        cors=phase_result(
            OrchestrationPhase.CORS,
            "cors",
        ),
    )

    def fake_run_assessment_pipeline(
        database_argument,
        context_argument,
        *,
        evidence_root,
        explicitly_approved,
        actor,
    ):
        captured["run_database"] = database_argument
        captured["context"] = context_argument
        captured["evidence_root"] = evidence_root
        captured["explicitly_approved"] = explicitly_approved
        captured["run_actor"] = actor
        return workflow_result

    async def fake_run_phase6_safe_chain(
        database_argument,
        context_argument,
        *,
        evidence_root,
        explicitly_approved,
        nuclei_preview_approved,
        sqlmap_preview_approved,
        nuclei_execute_approved,
        actor,
    ):
        captured["phase6_database"] = database_argument
        captured["phase6_context"] = context_argument
        captured["phase6_evidence_root"] = evidence_root
        captured["phase6_approved"] = explicitly_approved
        captured["nuclei_preview_approved"] = (
            nuclei_preview_approved
        )
        captured["sqlmap_preview_approved"] = (
            sqlmap_preview_approved
        )
        captured["nuclei_execute_approved"] = (
            nuclei_execute_approved
        )
        captured["phase6_actor"] = actor
        return SimpleNamespace(
            phase_results=[],
            calculated_status=OrchestrationStatus.COMPLETED,
        )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        cli_module,
        "get_database",
        lambda: database,
    )
    monkeypatch.setattr(
        cli_module,
        "create_orchestration",
        fake_create_orchestration,
    )
    monkeypatch.setattr(
        cli_module,
        "run_assessment_pipeline",
        fake_run_assessment_pipeline,
    )
    monkeypatch.setattr(
        cli_module,
        "run_phase6_safe_chain",
        fake_run_phase6_safe_chain,
    )

    result = runner.invoke(
        app,
        [
            "workflow",
            "run",
            "--url",
            "https://example.com/",
            "--name",
            "Authorized Example Assessment",
            "--authorized",
            "--active",
            "--approved",
            "--rate-limit",
            "4",
            "--intrusive",
            "--approve-nuclei-preview",
            "--execute-nuclei",
            "--approve-sqlmap-preview",
        ],
    )

    assert result.exit_code == 0

    assert captured["create_database"] is database
    assert captured["assessment_name"] == (
        "Authorized Example Assessment"
    )
    assert captured["target_url"] == "https://example.com/"
    assert captured["active_testing_allowed"] is True
    assert captured["intrusive_testing_allowed"] is True
    assert captured["rate_limit_per_second"] == 4
    assert captured["create_actor"] == "cli-workflow-orchestrator"

    assert captured["run_database"] is database
    assert captured["context"] is context
    assert captured["explicitly_approved"] is True
    assert captured["run_actor"] == "cli-workflow-orchestrator"
    assert captured["evidence_root"] == (
        tmp_path
        / "evidence"
        / "orchestrations"
        / "orchestration-test"
    )
    assert captured["phase6_database"] is database
    assert captured["phase6_context"] is workflow_result.context
    assert captured["phase6_approved"] is True
    assert captured["nuclei_preview_approved"] is True
    assert captured["sqlmap_preview_approved"] is True
    assert captured["nuclei_execute_approved"] is True
    assert captured["phase6_evidence_root"] == (
        tmp_path
        / "evidence"
        / "orchestrations"
        / "orchestration-test"
        / "phase6"
    )

    assert (
        "Assessment and safe Phase 6C workflow completed"
        in result.stdout
    )
    assert "execution-parent" in result.stdout
    assert "completed" in result.stdout
    assert "Assessment and Phase 6C Workflow Results" in result.stdout
    assert "Final state: completed" in result.stdout


def test_workflow_failure_returns_exit_code_one(
    tmp_path,
    monkeypatch,
) -> None:
    import saarthi_ai.cli as cli_module

    context = SimpleNamespace(
        orchestration_id="orchestration-failing",
        parent_execution_id="execution-parent-failing",
        target_url="https://example.com/",
        target_domain="example.com",
    )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        cli_module,
        "get_database",
        lambda: object(),
    )
    monkeypatch.setattr(
        cli_module,
        "create_orchestration",
        lambda *args, **kwargs: context,
    )

    def failing_pipeline(*args, **kwargs):
        raise OrchestrationWorkflowError(
            "simulated orchestration failure"
        )

    monkeypatch.setattr(
        cli_module,
        "run_assessment_pipeline",
        failing_pipeline,
    )

    result = runner.invoke(
        app,
        [
            "workflow",
            "run",
            "--url",
            "https://example.com/",
            "--authorized",
            "--active",
            "--approved",
        ],
    )

    assert result.exit_code == 1
    assert "Assessment workflow failed" in result.stdout
    assert "simulated orchestration failure" in result.stdout
