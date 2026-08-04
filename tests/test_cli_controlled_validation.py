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


def test_controlled_observe_requires_explicit_approval() -> None:
    result = runner.invoke(
        app,
        [
            "controlled",
            "observe",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/account",
        ],
    )

    assert result.exit_code == 1
    assert "Approval required" in result.stdout
    assert "active network activity" in result.stdout


def test_controlled_observe_builds_one_bounded_request(
    tmp_path,
    monkeypatch,
) -> None:
    import saarthi_ai.cli as cli_module

    captured: dict[str, object] = {}

    async def fake_workflow(
        database,
        request,
        *,
        transport=None,
        actor,
        evidence_root,
    ):
        captured["database"] = database
        captured["request"] = request
        captured["transport"] = transport
        captured["actor"] = actor
        captured["evidence_root"] = evidence_root

        return SimpleNamespace(
            execution=SimpleNamespace(
                state=SimpleNamespace(value="completed"),
            ),
            observation=SimpleNamespace(
                policy=SimpleNamespace(
                    decision=SimpleNamespace(value="allow"),
                ),
                method=request.method,
                request_attempted=True,
                response_received=True,
                status_code=200,
                final_url=request.validation.target_url,
                body_bytes_captured=18,
                body_truncated=False,
                body_sha256="b" * 64,
            ),
            evidence=SimpleNamespace(
                evidence_id="evidence-observation",
                path=str(evidence_root / "observation.json"),
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
        "run_tracked_controlled_validation_observation",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "controlled",
            "observe",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/account",
            "--action",
            "response_differential",
            "--method",
            "HEAD",
            "--timeout",
            "5",
            "--max-response-bytes",
            "4096",
            "--approved",
        ],
    )

    assert result.exit_code == 0

    request = captured["request"]

    assert request.validation.execution_id == "execution-test"
    assert (
        request.validation.target_url
        == "https://example.com/account"
    )
    assert (
        request.validation.action
        is ControlledValidationAction.RESPONSE_DIFFERENTIAL
    )
    assert request.validation.authorized is True
    assert request.validation.active_testing is True
    assert request.validation.intrusive_testing is False
    assert request.validation.explicitly_approved is True
    assert request.validation.reversible is True
    assert request.validation.requested_requests == 1

    assert request.method == "HEAD"
    assert request.timeout_seconds == 5.0
    assert request.max_response_bytes == 4096
    assert request.follow_redirects is False
    assert request.headers == ()
    assert request.body is None

    assert captured["transport"] is None
    assert captured["actor"] == (
        "cli-controlled-validation-observer"
    )
    assert captured["evidence_root"] == (
        tmp_path
        / "evidence"
        / "controlled-validation-observations"
    )

    assert "Active network observation approved" in result.stdout
    assert "Request budget: 1" in result.stdout
    assert "Redirects: disabled" in result.stdout
    assert "Controlled-validation observation completed" in result.stdout
    assert "Execution state: completed" in result.stdout
    assert "HTTP status: 200" in result.stdout
    assert "Captured bytes: 18" in result.stdout
    assert "Evidence SHA-256" in result.stdout


def test_controlled_observe_rejects_non_executable_action() -> None:
    result = runner.invoke(
        app,
        [
            "controlled",
            "observe",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/account",
            "--action",
            "authorization_boundary",
            "--approved",
        ],
    )

    assert result.exit_code == 1
    assert "Unsupported executable action" in result.stdout


def test_controlled_observe_rejects_unsupported_method() -> None:
    result = runner.invoke(
        app,
        [
            "controlled",
            "observe",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/account",
            "--method",
            "POST",
            "--approved",
        ],
    )

    assert result.exit_code == 1
    assert "Only GET and HEAD are allowed" in result.stdout
