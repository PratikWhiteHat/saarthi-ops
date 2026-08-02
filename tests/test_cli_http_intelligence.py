"""CLI tests for Phase 3C live-host intelligence."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from saarthi_ai.cli import app

runner = CliRunner()


def test_live_hosts_command_is_available() -> None:
    """Recon help should expose the Phase 3C command."""

    result = runner.invoke(
        app,
        [
            "recon",
            "--help",
        ],
    )

    assert result.exit_code == 0
    assert "live-hosts" in result.stdout
    assert "HTTP intelligence" in result.stdout


def test_live_hosts_requires_explicit_approval(
    tmp_path: Path,
) -> None:
    """The CLI must not start probing without explicit approval."""

    source_evidence = tmp_path / "subdomains.json"
    source_evidence.write_text(
        '{"domain": "example.com", "candidates": []}',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "recon",
            "live-hosts",
            "--execution",
            "execution-test",
            "--source-evidence",
            str(source_evidence),
        ],
    )

    assert result.exit_code == 1
    assert "Approval required" in result.stdout


def test_live_hosts_uses_project_evidence_directory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """CLI evidence must be written outside the virtual environment."""

    from types import SimpleNamespace

    import saarthi_ai.cli as cli_module

    source_evidence = tmp_path / "subdomains.json"
    source_evidence.write_text(
        '{"domain": "example.com", "candidates": []}',
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
                input_count=0,
                live_service_count=0,
                malformed_line_count=0,
                rejected_inputs=[],
                rejected_results=[],
                records=[],
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
        "run_tracked_http_intelligence",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "recon",
            "live-hosts",
            "--execution",
            "execution-test",
            "--source-evidence",
            str(source_evidence),
            "--approved",
        ],
    )

    assert result.exit_code == 0
    assert captured["evidence_root"] == (
        tmp_path / "evidence" / "http-intelligence"
    )
