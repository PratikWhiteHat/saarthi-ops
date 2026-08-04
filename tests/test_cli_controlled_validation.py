"""CLI tests for Phase 6C controlled-validation planning."""

from __future__ import annotations

from types import SimpleNamespace

from typer.testing import CliRunner

from saarthi_ai.cli import app
from saarthi_ai.controlled_validation.models import (
    ControlledValidationAction,
)

runner = CliRunner()


def test_controlled_command_is_available() -> None:
    result = runner.invoke(
        app,
        ["controlled", "--help"],
    )

    assert result.exit_code == 0
    assert "plan" in result.stdout
    assert "controlled-validation" in result.stdout.lower()


def test_controlled_plan_requires_explicit_approval() -> None:
    result = runner.invoke(
        app,
        [
            "controlled",
            "plan",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/account",
        ],
    )

    assert result.exit_code == 1
    assert "Approval required" in result.stdout


def test_controlled_plan_builds_non_executed_request(
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
        captured["database"] = database
        captured["request"] = request
        captured["actor"] = actor
        captured["evidence_root"] = evidence_root

        return SimpleNamespace(
            execution=SimpleNamespace(
                state=SimpleNamespace(value="planned"),
            ),
            policy=SimpleNamespace(
                decision=SimpleNamespace(value="allow"),
                risk=SimpleNamespace(value="low"),
                reason="Authorized bounded plan.",
            ),
            evidence=SimpleNamespace(
                evidence_id="evidence-controlled-plan",
                path=str(evidence_root / "plan.json"),
                sha256="a" * 64,
            ),
        )

    database = object()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        cli_module,
        "get_database",
        lambda: database,
    )
    monkeypatch.setattr(
        cli_module,
        "create_tracked_controlled_validation_plan",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "controlled",
            "plan",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/account",
            "--action",
            "response_differential",
            "--requests",
            "2",
            "--approved",
        ],
    )

    assert result.exit_code == 0

    request = captured["request"]

    assert request.execution_id == "execution-test"
    assert request.target_url == "https://example.com/account"
    assert (
        request.action
        is ControlledValidationAction.RESPONSE_DIFFERENTIAL
    )
    assert request.authorized is True
    assert request.active_testing is True
    assert request.intrusive_testing is False
    assert request.explicitly_approved is True
    assert request.reversible is True
    assert request.requested_requests == 2

    assert captured["actor"] == (
        "cli-controlled-validation-planner"
    )
    assert captured["evidence_root"] == (
        tmp_path / "evidence" / "controlled-validation-plans"
    )

    assert "Controlled-validation plan persisted" in result.stdout
    assert "Execution state: planned" in result.stdout
    assert "Policy decision: allow" in result.stdout
    assert "Risk: low" in result.stdout
    assert "Executed: false" in result.stdout
    assert "Network activity: false" in result.stdout
    assert "Payload sent: false" in result.stdout
    normalized_output = " ".join(result.stdout.split())
    assert (
        "No request, payload, or subprocess was executed"
        in normalized_output
    )


def test_controlled_plan_forwards_intrusive_permission(
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

        return SimpleNamespace(
            execution=SimpleNamespace(
                state=SimpleNamespace(value="planned"),
            ),
            policy=SimpleNamespace(
                decision=SimpleNamespace(value="allow"),
                risk=SimpleNamespace(value="moderate"),
                reason="Authorized intrusive plan.",
            ),
            evidence=SimpleNamespace(
                evidence_id="evidence-intrusive-plan",
                path=str(evidence_root / "plan.json"),
                sha256="b" * 64,
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
        "create_tracked_controlled_validation_plan",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "controlled",
            "plan",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/account",
            "--action",
            "authorization_boundary",
            "--requests",
            "1",
            "--intrusive",
            "--approved",
        ],
    )

    assert result.exit_code == 0
    assert captured["request"].intrusive_testing is True
    assert (
        captured["request"].action
        is ControlledValidationAction.AUTHORIZATION_BOUNDARY
    )
    assert "Risk: moderate" in result.stdout


def test_controlled_plan_rejects_unsupported_action() -> None:
    result = runner.invoke(
        app,
        [
            "controlled",
            "plan",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/account",
            "--action",
            "unrestricted-exploit",
            "--approved",
        ],
    )

    assert result.exit_code != 0

    error_output = result.stdout

    if result.stderr:
        error_output += result.stderr

    assert "Invalid value" in error_output


def test_controlled_plan_rejects_request_count_above_bound() -> None:
    result = runner.invoke(
        app,
        [
            "controlled",
            "plan",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/account",
            "--requests",
            "6",
            "--approved",
        ],
    )

    assert result.exit_code != 0
