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
