"""CLI tests for Phase 4A direct vulnerability checks."""

from __future__ import annotations

from types import SimpleNamespace

from typer.testing import CliRunner

from saarthi_ai.cli import app

runner = CliRunner()


def test_direct_check_command_is_available() -> None:
    result = runner.invoke(
        app,
        [
            "check",
            "--help",
        ],
    )

    assert result.exit_code == 0
    assert "direct" in result.stdout
    assert "vulnerability checks" in result.stdout


def test_direct_check_requires_explicit_approval() -> None:
    result = runner.invoke(
        app,
        [
            "check",
            "direct",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
            "--check",
            "security-headers",
        ],
    )

    assert result.exit_code == 1
    assert "Approval required" in result.stdout


def test_direct_check_uses_project_evidence_directory(
    tmp_path,
    monkeypatch,
) -> None:
    import saarthi_ai.cli as cli_module

    captured: dict[str, object] = {}

    def fake_workflow(
        database,
        request,
        *,
        actor,
        evidence_root,
    ):
        captured["request"] = request
        captured["actor"] = actor
        captured["evidence_root"] = evidence_root

        return SimpleNamespace(
            execution=SimpleNamespace(
                state=SimpleNamespace(value="completed"),
            ),
            check=SimpleNamespace(
                check_id=request.check_id,
                target_url=request.target_url,
                policy=SimpleNamespace(
                    decision=SimpleNamespace(value="allow"),
                ),
                executed=True,
                result=SimpleNamespace(
                    status_code=200,
                    present_headers=("content-security-policy",),
                    missing_headers=("strict-transport-security",),
                    error=None,
                ),
            ),
            evidence=SimpleNamespace(
                evidence_id="evidence-test",
                path=str(evidence_root / "evidence-test.json"),
                sha256="a" * 64,
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
        "run_tracked_direct_check",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "check",
            "direct",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
            "--check",
            "security-headers",
            "--approved",
        ],
    )

    assert result.exit_code == 0

    request = captured["request"]

    assert request.execution_id == "execution-test"
    assert request.target_url == "https://example.com/"
    assert request.check_id == "security-headers"
    assert request.authorized is True
    assert request.explicitly_approved is True

    assert captured["actor"] == "cli-direct-check-executor"
    assert captured["evidence_root"] == (
        tmp_path / "evidence" / "direct-checks"
    )

    assert "Direct check completed" in result.stdout
    assert "Missing security headers: 1" in result.stdout
    assert "strict-transport-security" in result.stdout
    assert "Evidence SHA-256" in result.stdout
