"""CLI tests for Phase 4B blind-validation correlation records."""

from __future__ import annotations

from types import SimpleNamespace

from typer.testing import CliRunner

from saarthi_ai.cli import app

runner = CliRunner()


def test_blind_command_is_available() -> None:
    result = runner.invoke(
        app,
        ["blind", "--help"],
    )

    assert result.exit_code == 0
    assert "create" in result.stdout
    assert "blind-validation" in result.stdout.lower()


def test_blind_create_requires_explicit_approval() -> None:
    result = runner.invoke(
        app,
        [
            "blind",
            "create",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
        ],
    )

    assert result.exit_code == 1
    assert "Approval required" in result.stdout


def test_blind_create_builds_bounded_request(
    tmp_path,
    monkeypatch,
) -> None:
    import saarthi_ai.cli as cli_module

    captured: dict[str, object] = {}
    raw_token = "one-time-secret-token"

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
            status=SimpleNamespace(value="waiting"),
            token=SimpleNamespace(
                token_id="blind-token-test",
                token_value=raw_token,
                token_hash="b" * 64,
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
        "run_tracked_blind_validation",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "blind",
            "create",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
            "--protocol",
            "https",
            "--poll-attempts",
            "6",
            "--poll-interval",
            "10",
            "--approved",
        ],
    )

    assert result.exit_code == 0

    request = captured["request"]

    assert request.execution_id == "execution-test"
    assert request.target_url == "https://example.com/"
    assert request.authorized is True
    assert request.active_testing is True
    assert request.explicitly_approved is True
    assert request.callback_protocol.value == "https"
    assert request.requested_poll_attempts == 6
    assert request.requested_poll_interval_seconds == 10

    assert captured["actor"] == "cli-blind-validation-manager"
    assert captured["evidence_root"] == (
        tmp_path / "evidence" / "blind-validation"
    )

    assert "Correlation record created" in result.stdout
    assert raw_token in result.stdout
    assert "not persisted" in result.stdout
    assert "No payload was sent" in result.stdout
    assert "Evidence SHA-256" in result.stdout
