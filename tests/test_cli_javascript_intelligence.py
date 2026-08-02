"""CLI tests for Phase 3E JavaScript intelligence."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from saarthi_ai.cli import app

runner = CliRunner()


def test_javascript_intelligence_command_is_available() -> None:
    """Recon help should expose the Phase 3E command."""

    result = runner.invoke(
        app,
        [
            "recon",
            "--help",
        ],
    )

    assert result.exit_code == 0
    assert "javascript-intelligence" in result.stdout
    assert "JavaScript assets" in result.stdout


def test_javascript_intelligence_requires_explicit_approval(
    tmp_path: Path,
) -> None:
    """The CLI must not fetch JavaScript without approval."""

    source_evidence = tmp_path / "crawl.json"
    source_evidence.write_text(
        '{"domain": "example.com", "urls": []}',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "recon",
            "javascript-intelligence",
            "--execution",
            "execution-test",
            "--source-evidence",
            str(source_evidence),
        ],
    )

    assert result.exit_code == 1
    assert "Approval required" in result.stdout


def test_javascript_intelligence_uses_project_evidence_directory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Phase 3E evidence must use the project-local directory."""

    import saarthi_ai.cli as cli_module

    source_evidence = tmp_path / "crawl.json"
    source_evidence.write_text(
        '{"domain": "example.com", "urls": []}',
        encoding="utf-8",
    )

    captured: dict[str, object] = {}

    def fake_workflow(
        database,
        execution_id,
        source_evidence_path,
        *,
        actor,
        evidence_root,
    ):
        captured["execution_id"] = execution_id
        captured["source_evidence_path"] = source_evidence_path
        captured["actor"] = actor
        captured["evidence_root"] = evidence_root

        return SimpleNamespace(
            execution=SimpleNamespace(
                state=SimpleNamespace(value="completed"),
            ),
            collection=SimpleNamespace(
                domain="example.com",
                input_javascript_count=2,
                fetched_javascript_count=1,
                failed_fetch_count=1,
                endpoint_count=3,
                parameter_count=2,
                websocket_count=1,
                source_map_count=1,
                secret_candidate_count=0,
                rejected_inputs=[],
                assets=[
                    SimpleNamespace(
                        fetch=SimpleNamespace(
                            status_code=200,
                            url=("https://example.com/assets/app.js"),
                        )
                    )
                ],
            ),
            evidence=SimpleNamespace(
                evidence_id="evidence-test",
                path=str(evidence_root / "evidence-test.json"),
            ),
        )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        cli_module,
        "get_database",
        lambda: object(),
    )
    monkeypatch.setattr(
        cli_module,
        "run_tracked_javascript_intelligence",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "recon",
            "javascript-intelligence",
            "--execution",
            "execution-test",
            "--source-evidence",
            str(source_evidence),
            "--approved",
        ],
    )

    assert result.exit_code == 0
    assert captured["execution_id"] == "execution-test"
    assert captured["source_evidence_path"] == source_evidence
    assert captured["actor"] == "cli-javascript-intelligence-collector"
    assert captured["evidence_root"] == (tmp_path / "evidence" / "javascript-intelligence")

    assert "JavaScript intelligence collection completed" in result.stdout
    assert "Endpoints discovered: 3" in result.stdout
    assert "Source maps: 1" in result.stdout
