"""CLI tests for the `saarthi analyze` AI-triage command."""

from __future__ import annotations

from types import SimpleNamespace

from typer.testing import CliRunner

from saarthi_ai import cli
from saarthi_ai.analysis import AnalysisError
from saarthi_ai.persistence.database import SaarthiDatabase

runner = CliRunner()


def test_analyze_no_runs_exits_cleanly(tmp_path, monkeypatch):
    empty = SaarthiDatabase(tmp_path / "empty.db")
    empty.initialize()
    monkeypatch.setattr(cli, "get_database", lambda: empty)

    result = runner.invoke(cli.app, ["analyze"])

    assert result.exit_code == 1
    assert "Cannot analyze" in result.stdout


def test_analyze_success_prints_model_output(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "get_database", lambda: object())

    digest = SimpleNamespace(
        target="https://app.example.com/item?id=1",
        orchestration_id="orchestration-x",
        findings=("SQLi on id",),
        phases=(("3A", "completed"),),
        parent_state="completed",
    )
    monkeypatch.setattr(
        cli, "gather_run_digest", lambda database, orchestration_id=None: digest
    )

    async def fake_analyze(client, run_digest, **kwargs):
        return "Executive summary: one High-severity SQLi on `id`."

    monkeypatch.setattr(cli, "analyze_run", fake_analyze)
    monkeypatch.setattr(cli, "SaarthiOllamaClient", lambda settings: object())

    result = runner.invoke(cli.app, ["analyze"])

    assert result.exit_code == 0
    assert "AI analysis of assessment run" in result.stdout
    assert "High-severity SQLi" in result.stdout


def test_analyze_command_is_registered():
    result = runner.invoke(cli.app, ["analyze", "--help"])

    assert result.exit_code == 0
    assert "--orchestration" in result.stdout


def test_gather_error_type_is_exposed():
    # Guard against accidental rename that would break the CLI catch.
    assert issubclass(AnalysisError, RuntimeError)
