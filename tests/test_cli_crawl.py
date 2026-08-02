"""CLI tests for Phase 3D crawling and URL intelligence."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from saarthi_ai.cli import app

runner = CliRunner()


def test_crawl_command_is_available() -> None:
    """Recon help should expose the Phase 3D crawl command."""

    result = runner.invoke(
        app,
        [
            "recon",
            "--help",
        ],
    )

    assert result.exit_code == 0
    assert "crawl" in result.stdout


def test_crawl_requires_explicit_approval(
    tmp_path: Path,
) -> None:
    """The CLI must not start crawling without explicit approval."""

    source_evidence = tmp_path / "http-intelligence.json"
    source_evidence.write_text(
        '{"domain": "example.com", "records": []}',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "recon",
            "crawl",
            "--execution",
            "execution-test",
            "--source-evidence",
            str(source_evidence),
        ],
    )

    assert result.exit_code == 1
    assert "Approval required" in result.stdout


def test_crawl_uses_project_evidence_directory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """CLI crawl evidence must be written under the project directory."""

    import saarthi_ai.cli as cli_module

    source_evidence = tmp_path / "http-intelligence.json"
    source_evidence.write_text(
        '{"domain": "example.com", "records": []}',
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
                input_service_count=2,
                crawled_service_count=1,
                discovered_url_count=1,
                form_count=0,
                parameter_count=0,
                javascript_url_count=0,
                websocket_url_count=0,
                malformed_line_count=0,
                rejected_inputs=[],
                rejected_results=[],
                urls=[
                    SimpleNamespace(
                        status_code=200,
                        method="GET",
                        url="https://example.com/",
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
        "run_tracked_crawl",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "recon",
            "crawl",
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
    assert captured["actor"] == "cli-crawl-collector"
    assert captured["evidence_root"] == (tmp_path / "evidence" / "crawling")

    assert "URL crawling completed" in result.stdout
    assert "URLs discovered: 1" in result.stdout
