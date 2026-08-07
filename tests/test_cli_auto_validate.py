"""CLI guard tests for the workflow-run auto-validate flags.

These assert the flag-combination guards fail closed *before* any
orchestration or network activity begins.
"""

from __future__ import annotations

from typer.testing import CliRunner

from saarthi_ai.cli import app

runner = CliRunner()

_BASE = [
    "workflow",
    "run",
    "--url",
    "https://example.com/item?id=1",
    "--authorized",
    "--active",
    "--approved",
]


def test_auto_validate_flags_present_in_help() -> None:
    result = runner.invoke(app, ["workflow", "run", "--help"])

    assert result.exit_code == 0
    assert "--auto-validate" in result.stdout
    assert "--confirmed-poc" in result.stdout
    assert "--dump-row" in result.stdout


def test_confirmed_poc_requires_auto_validate() -> None:
    result = runner.invoke(app, [*_BASE, "--intrusive", "--confirmed-poc"])

    assert result.exit_code == 1
    assert "--confirmed-poc requires --auto-validate" in result.stdout


def test_dump_row_requires_confirmed_poc() -> None:
    result = runner.invoke(
        app,
        [*_BASE, "--intrusive", "--auto-validate", "--dump-row"],
    )

    assert result.exit_code == 1
    assert "--dump-row requires --confirmed-poc" in result.stdout


def test_confirmed_poc_requires_intrusive() -> None:
    result = runner.invoke(
        app,
        [*_BASE, "--auto-validate", "--confirmed-poc"],
    )

    assert result.exit_code == 1
    assert "--confirmed-poc requires --intrusive" in result.stdout
