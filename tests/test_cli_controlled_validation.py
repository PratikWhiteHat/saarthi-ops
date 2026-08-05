"""CLI tests for Phase 6C controlled-validation planning."""

from __future__ import annotations

from types import SimpleNamespace

from typer.testing import CliRunner

from saarthi_ai.cli import app
from saarthi_ai.controlled_validation.models import (
    ControlledValidationAction,
)
from saarthi_ai.persistence.controlled_validation_observation_workflow import (
    ControlledValidationObservationWorkflowError,
)
from saarthi_ai.persistence.database import InvalidStateTransitionError

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
            reused_existing_evidence=False,
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


def test_controlled_observe_reports_missing_matching_plan(
    monkeypatch,
) -> None:
    import saarthi_ai.cli as cli_module

    workflow_calls = 0

    async def fake_workflow(*args, **kwargs):
        nonlocal workflow_calls
        workflow_calls += 1
        raise ControlledValidationObservationWorkflowError(
            "A matching approved Phase 6B controlled-validation plan "
            "is required before observation."
        )

    monkeypatch.setattr(
        cli_module,
        "get_database",
        lambda: object(),
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
            "--approved",
        ],
    )

    assert result.exit_code == 1
    assert workflow_calls == 1
    assert "matching approved Phase 6B" in result.stdout
    assert "Automatic retry: disabled" in result.stdout


def test_controlled_observe_reports_out_of_scope_target(
    monkeypatch,
) -> None:
    import saarthi_ai.cli as cli_module

    async def fake_workflow(*args, **kwargs):
        raise InvalidStateTransitionError(
            "Target 'outside.example' is not associated with this execution."
        )

    monkeypatch.setattr(
        cli_module,
        "get_database",
        lambda: object(),
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
            "https://outside.example/account",
            "--approved",
        ],
    )

    assert result.exit_code == 1
    normalized_output = " ".join(result.stdout.split())
    assert "not associated with this execution" in normalized_output
    assert "Automatic retry: disabled" in normalized_output


def test_controlled_observe_failure_requires_new_execution(
    monkeypatch,
) -> None:
    import saarthi_ai.cli as cli_module

    async def fake_workflow(*args, **kwargs):
        raise ControlledValidationObservationWorkflowError(
            "simulated bounded network failure"
        )

    monkeypatch.setattr(
        cli_module,
        "get_database",
        lambda: object(),
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
            "--approved",
        ],
    )

    assert result.exit_code == 1
    normalized_output = " ".join(result.stdout.split())
    assert "simulated bounded network failure" in normalized_output
    assert "Automatic retry: disabled" in normalized_output
    assert "create and approve a new execution" in normalized_output


def test_controlled_observe_reports_idempotent_evidence_reuse(
    tmp_path,
    monkeypatch,
) -> None:
    import saarthi_ai.cli as cli_module

    workflow_calls = 0

    async def fake_workflow(
        database,
        request,
        *,
        transport=None,
        actor,
        evidence_root,
    ):
        nonlocal workflow_calls
        workflow_calls += 1

        assert transport is None

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
                evidence_id="existing-observation-evidence",
                path=str(evidence_root / "existing-observation.json"),
                sha256="c" * 64,
            ),
            reused_existing_evidence=True,
        )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        cli_module,
        "get_database",
        lambda: object(),
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
            "--approved",
        ],
    )

    assert result.exit_code == 0
    assert workflow_calls == 1
    normalized_output = " ".join(result.stdout.split())
    assert "existing-observation-evidence" in normalized_output
    assert "Existing evidence reused: true" in normalized_output
    assert "Existing persisted observation reused" in normalized_output
    assert "No second network request was sent" in normalized_output
    assert "no duplicate observation evidence" in normalized_output


def test_controlled_nuclei_preview_requires_approval() -> None:
    result = runner.invoke(
        app,
        [
            "controlled",
            "nuclei-preview",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
        ],
    )

    assert result.exit_code == 1
    assert "Approval required" in result.stdout
    assert "No Nuclei process" in result.stdout


def test_controlled_nuclei_preview_persists_dry_run(
    tmp_path,
    monkeypatch,
) -> None:
    import saarthi_ai.cli as cli_module

    captured: dict[str, object] = {}

    def fake_workflow(
        database,
        execution_id,
        request,
        *,
        actor,
        evidence_root,
    ):
        captured["database"] = database
        captured["execution_id"] = execution_id
        captured["request"] = request
        captured["actor"] = actor
        captured["evidence_root"] = evidence_root

        return SimpleNamespace(
            execution=SimpleNamespace(
                state=SimpleNamespace(value="planned"),
            ),
            preview=SimpleNamespace(
                tool_name="nuclei",
                target_url=request.target_url,
                arguments=(
                    "-u",
                    request.target_url,
                    "-jsonl",
                    "-silent",
                    "-no-color",
                    "-disable-update-check",
                    "-rate-limit",
                    str(request.rate_limit_per_second),
                    "-concurrency",
                    str(request.concurrency),
                    "-timeout",
                    str(request.timeout_seconds),
                    "-retries",
                    "0",
                ),
                rate_limit_per_second=(
                    request.rate_limit_per_second
                ),
                concurrency=request.concurrency,
                timeout_seconds=request.timeout_seconds,
                allowed_tags=(
                    "exposure",
                    "misconfig",
                    "tech",
                ),
                excluded_tags=(
                    "bruteforce",
                    "dos",
                    "fuzz",
                    "headless",
                    "intrusive",
                    "token-spray",
                ),
                executed=False,
                subprocess_started=False,
            ),
            evidence=SimpleNamespace(
                evidence_id="evidence-nuclei-preview",
                path=str(evidence_root / "preview.json"),
                sha256="a" * 64,
            ),
            reused_existing_evidence=False,
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
        "create_tracked_nuclei_preview",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "controlled",
            "nuclei-preview",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
            "--rate-limit",
            "2",
            "--concurrency",
            "2",
            "--timeout",
            "7",
            "--approved",
        ],
    )

    assert result.exit_code == 0

    request = captured["request"]

    assert captured["database"] is database
    assert captured["execution_id"] == "execution-test"
    assert request.target_url == "https://example.com/"
    assert request.authorized is True
    assert request.active_testing is True
    assert request.approval_granted is True
    assert request.rate_limit_per_second == 2
    assert request.concurrency == 2
    assert request.timeout_seconds == 7
    assert request.dry_run is True

    assert captured["actor"] == (
        "cli-controlled-nuclei-preview"
    )
    assert captured["evidence_root"] == (
        tmp_path
        / "evidence"
        / "controlled-nuclei-previews"
    )

    normalized_output = " ".join(result.stdout.split())

    assert "Controlled Nuclei preview persisted" in normalized_output
    assert "Execution state: planned" in normalized_output
    assert "Tool: nuclei" in normalized_output
    assert "Executed: false" in normalized_output
    assert "Network activity: false" in normalized_output
    assert "Subprocess started: false" in normalized_output
    assert "Existing evidence reused: false" in normalized_output
    assert "evidence-nuclei-preview" in normalized_output
    assert "Nuclei was not started" in normalized_output
    assert "no network request was sent" in normalized_output


def test_controlled_nuclei_preview_reports_reused_evidence(
    tmp_path,
    monkeypatch,
) -> None:
    import saarthi_ai.cli as cli_module

    def fake_workflow(
        database,
        execution_id,
        request,
        *,
        actor,
        evidence_root,
    ):
        return SimpleNamespace(
            execution=SimpleNamespace(
                state=SimpleNamespace(value="planned"),
            ),
            preview=SimpleNamespace(
                tool_name="nuclei",
                target_url=request.target_url,
                arguments=("-u", request.target_url),
                rate_limit_per_second=1,
                concurrency=1,
                timeout_seconds=10,
                allowed_tags=("exposure",),
                excluded_tags=("dos",),
                executed=False,
                subprocess_started=False,
            ),
            evidence=SimpleNamespace(
                evidence_id="existing-nuclei-preview",
                path=str(evidence_root / "existing.json"),
                sha256="b" * 64,
            ),
            reused_existing_evidence=True,
        )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        cli_module,
        "get_database",
        lambda: object(),
    )
    monkeypatch.setattr(
        cli_module,
        "create_tracked_nuclei_preview",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "controlled",
            "nuclei-preview",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
            "--approved",
        ],
    )

    assert result.exit_code == 0

    normalized_output = " ".join(result.stdout.split())

    assert "Existing evidence reused: true" in normalized_output
    assert "existing-nuclei-preview" in normalized_output


def test_controlled_nuclei_preview_reports_workflow_failure(
    monkeypatch,
) -> None:
    import saarthi_ai.cli as cli_module

    def fake_workflow(*args, **kwargs):
        raise cli_module.NucleiPreviewWorkflowError(
            "simulated preview persistence failure"
        )

    monkeypatch.setattr(
        cli_module,
        "get_database",
        lambda: object(),
    )
    monkeypatch.setattr(
        cli_module,
        "create_tracked_nuclei_preview",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "controlled",
            "nuclei-preview",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
            "--approved",
        ],
    )

    assert result.exit_code == 1

    normalized_output = " ".join(result.stdout.split())

    assert "simulated preview persistence failure" in normalized_output
    assert "Executed: false" in normalized_output
    assert "Network activity: false" in normalized_output
    assert "Subprocess started: false" in normalized_output


def test_controlled_nuclei_preview_enforces_cli_bounds() -> None:
    result = runner.invoke(
        app,
        [
            "controlled",
            "nuclei-preview",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
            "--rate-limit",
            "3",
            "--approved",
        ],
    )

    assert result.exit_code != 0
