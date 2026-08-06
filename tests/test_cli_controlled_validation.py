"""CLI tests for Phase 6C controlled-validation planning."""

from __future__ import annotations

from types import SimpleNamespace

from typer.testing import CliRunner

from saarthi_ai.cli import app
from saarthi_ai.controlled_validation.models import (
    ControlledValidationAction,
)
from saarthi_ai.execution.sqlmap_adapter import (
    PROHIBITED_SQLMAP_CAPABILITIES,
    SqlmapMethod,
    SqlmapPostContentType,
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


def test_controlled_validators_renders_module_summary() -> None:
    result = runner.invoke(
        app,
        ["controlled", "validators"],
    )

    assert result.exit_code == 0
    normalized = " ".join(result.stdout.split())
    assert "Phase 6C Attack Validator Readiness" in normalized
    assert "6C.1" in normalized
    assert "Injection Testing" in normalized
    assert "6C.7" in normalized
    assert "API & Business Logic Attacks" in normalized


def test_controlled_validators_filters_one_module() -> None:
    result = runner.invoke(
        app,
        ["controlled", "validators", "--module", "6C.6"],
    )

    assert result.exit_code == 0
    normalized = " ".join(result.stdout.split())
    assert "6C.6 — File & Execution Attacks" in normalized
    assert "Unrestricted File Upload" in normalized
    assert "file_upload_surface_validation" in normalized
    assert "Uploaded Script Execution" in normalized
    assert "manual_only" in normalized
    assert "SQL Injection" not in normalized


def test_controlled_validators_rejects_unknown_module() -> None:
    result = runner.invoke(
        app,
        ["controlled", "validators", "--module", "6C.8"],
    )

    assert result.exit_code == 1
    assert "Unknown validator module" in result.stdout


def test_controlled_sqlmap_preview_supports_verbose_post(
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
        captured["request"] = request
        captured["actor"] = actor
        captured["evidence_root"] = evidence_root
        return SimpleNamespace(
            execution=SimpleNamespace(
                state=SimpleNamespace(value="planned"),
            ),
            preview=SimpleNamespace(
                tool_name="sqlmap",
                method=SqlmapMethod.POST,
                target_display_url="https://example.com/login",
                parameter_name="username",
                post_parameter_names=("username", "password"),
                post_content_type=SqlmapPostContentType.JSON,
                redacted_arguments=(
                    "-u",
                    "https://example.com/login",
                    "-p",
                    "username",
                    "--method=POST",
                    '--data={"password":"<redacted>",'
                    '"username":"<redacted>"}',
                    "--level=1",
                    "--risk=1",
                ),
                timeout_seconds=5,
                level=1,
                risk=1,
                threads=1,
                retries=0,
                techniques="BE",
                prohibited_capabilities=(
                    PROHIBITED_SQLMAP_CAPABILITIES
                ),
            ),
            evidence=SimpleNamespace(
                evidence_id="evidence-sqlmap-preview",
                path=str(evidence_root / "sqlmap-preview.json"),
                sha256="a" * 64,
            ),
            reused_existing_evidence=False,
        )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        cli_module,
        "get_database",
        lambda: object(),
    )
    monkeypatch.setattr(
        cli_module,
        "create_tracked_sqlmap_preview",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "controlled",
            "sqlmap-preview",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/login",
            "--parameter",
            "username",
            "--method",
            "POST",
            "--post-parameters",
            "username,password",
            "--content-type",
            "application/json",
        ],
    )

    assert result.exit_code == 0
    request = captured["request"]
    assert request.method is SqlmapMethod.POST
    assert request.post_parameter_names == ("username", "password")
    assert request.post_content_type is SqlmapPostContentType.JSON
    assert request.intrusive_testing is True
    normalized = " ".join(result.stdout.split())
    assert "6C.1 SQLmap preview activity" in normalized
    assert "03 method: POST" in normalized
    assert "request values: not accepted" in normalized
    assert "permission and scope gates: passed" in normalized
    assert "level=1 risk=1 threads=1 retries=0" in normalized
    assert "techniques=BE" in normalized
    assert "prohibited capabilities" in normalized
    assert "evidence persisted: true" in normalized
    assert "request values stored: false" in normalized
    assert "executable arguments built: false" in normalized
    assert "executed: false" in normalized
    assert "network activity: false" in normalized
    assert "subprocess started: false" in normalized


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


def test_controlled_nuclei_prepare_requires_approval() -> None:
    result = runner.invoke(
        app,
        [
            "controlled",
            "nuclei-prepare",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
        ],
    )

    assert result.exit_code == 1

    normalized_output = " ".join(result.stdout.split())

    assert "Approval required" in normalized_output
    assert "Executed: false" in normalized_output
    assert "Network activity: false" in normalized_output
    assert "Subprocess started: false" in normalized_output
    assert "Runner invoked: false" in normalized_output
    assert "Executable resolved: false" in normalized_output


def test_controlled_nuclei_prepare_persists_non_executed_binding(
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
            plan=SimpleNamespace(
                tool_name="nuclei",
                target_url=request.preview.target_url,
                arguments=request.preview.arguments,
                rate_limit_per_second=(
                    request.preview.rate_limit_per_second
                ),
                concurrency=request.preview.concurrency,
                request_timeout_seconds=(
                    request.preview.timeout_seconds
                ),
            ),
            binding=SimpleNamespace(
                profile=SimpleNamespace(
                    timeout_seconds=120,
                    max_output_bytes=1_000_000,
                    max_arguments=len(
                        request.preview.arguments
                    ),
                ),
            ),
            preview_evidence=SimpleNamespace(
                evidence_id="evidence-nuclei-preview",
            ),
            evidence=SimpleNamespace(
                evidence_id="evidence-nuclei-preparation",
                path=str(
                    evidence_root / "preparation.json"
                ),
                sha256="d" * 64,
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
        "create_tracked_nuclei_preparation",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "controlled",
            "nuclei-prepare",
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
    assert request.authorization_confirmed is True
    assert request.active_testing_allowed is True
    assert request.explicitly_approved is True

    assert request.preview.target_url == "https://example.com/"
    assert request.preview.rate_limit_per_second == 2
    assert request.preview.concurrency == 2
    assert request.preview.timeout_seconds == 7
    assert request.preview.executed is False
    assert request.preview.subprocess_started is False

    assert captured["actor"] == (
        "cli-controlled-nuclei-preparation"
    )
    assert captured["evidence_root"] == (
        tmp_path
        / "evidence"
        / "controlled-nuclei-preparations"
    )

    normalized_output = " ".join(result.stdout.split())

    assert (
        "Controlled Nuclei preparation persisted"
        in normalized_output
    )
    assert "Execution state: planned" in normalized_output
    assert "Tool: nuclei" in normalized_output
    assert "Request timeout: 7 second(s)" in normalized_output
    assert "Process timeout: 120 second(s)" in normalized_output
    assert (
        "Output cap per stream: 1000000 byte(s)"
        in normalized_output
    )
    assert "Executed: false" in normalized_output
    assert "Network activity: false" in normalized_output
    assert "Subprocess started: false" in normalized_output
    assert "Runner invoked: false" in normalized_output
    assert "Executable resolved: false" in normalized_output
    assert "Existing evidence reused: false" in normalized_output
    assert "evidence-nuclei-preview" in normalized_output
    assert "evidence-nuclei-preparation" in normalized_output
    assert "runner was not invoked" in normalized_output
    assert "no executable was resolved" in normalized_output
    assert "no network request was sent" in normalized_output


def test_controlled_nuclei_prepare_reports_reused_evidence(
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
            plan=SimpleNamespace(
                tool_name="nuclei",
                target_url=request.preview.target_url,
                arguments=request.preview.arguments,
                rate_limit_per_second=1,
                concurrency=1,
                request_timeout_seconds=10,
            ),
            binding=SimpleNamespace(
                profile=SimpleNamespace(
                    timeout_seconds=120,
                    max_output_bytes=1_000_000,
                    max_arguments=len(
                        request.preview.arguments
                    ),
                ),
            ),
            preview_evidence=SimpleNamespace(
                evidence_id="existing-nuclei-preview",
            ),
            evidence=SimpleNamespace(
                evidence_id="existing-nuclei-preparation",
                path=str(
                    evidence_root / "existing.json"
                ),
                sha256="e" * 64,
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
        "create_tracked_nuclei_preparation",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "controlled",
            "nuclei-prepare",
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
    assert "existing-nuclei-preparation" in normalized_output


def test_controlled_nuclei_prepare_reports_workflow_failure(
    monkeypatch,
) -> None:
    import saarthi_ai.cli as cli_module

    def fake_workflow(*args, **kwargs):
        raise cli_module.NucleiPreparationWorkflowError(
            "simulated preparation persistence failure"
        )

    monkeypatch.setattr(
        cli_module,
        "get_database",
        lambda: object(),
    )
    monkeypatch.setattr(
        cli_module,
        "create_tracked_nuclei_preparation",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "controlled",
            "nuclei-prepare",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
            "--approved",
        ],
    )

    assert result.exit_code == 1

    normalized_output = " ".join(result.stdout.split())

    assert (
        "simulated preparation persistence failure"
        in normalized_output
    )
    assert "Executed: false" in normalized_output
    assert "Network activity: false" in normalized_output
    assert "Subprocess started: false" in normalized_output
    assert "Runner invoked: false" in normalized_output
    assert "Executable resolved: false" in normalized_output


def test_controlled_nuclei_prepare_enforces_cli_bounds() -> None:
    result = runner.invoke(
        app,
        [
            "controlled",
            "nuclei-prepare",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
            "--concurrency",
            "3",
            "--approved",
        ],
    )

    assert result.exit_code != 0


def test_controlled_nuclei_execute_requires_both_confirmations(
    monkeypatch,
) -> None:
    import saarthi_ai.cli as cli_module

    workflow_calls = 0

    def fake_workflow(*args, **kwargs):
        nonlocal workflow_calls
        workflow_calls += 1
        raise AssertionError("Execution workflow must not be called.")

    monkeypatch.setattr(
        cli_module,
        "run_tracked_nuclei_execution",
        fake_workflow,
    )

    missing_approval = runner.invoke(
        app,
        [
            "controlled",
            "nuclei-execute",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
            "--execute",
        ],
    )
    missing_execution_confirmation = runner.invoke(
        app,
        [
            "controlled",
            "nuclei-execute",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
            "--approved",
        ],
    )

    assert missing_approval.exit_code == 1
    assert missing_execution_confirmation.exit_code == 1
    assert workflow_calls == 0

    approval_output = " ".join(missing_approval.stdout.split())
    execution_output = " ".join(
        missing_execution_confirmation.stdout.split()
    )

    assert "Approval required" in approval_output
    assert "Execution confirmation required" in execution_output

    for output in (approval_output, execution_output):
        assert "Execution requested: false" in output
        assert "Network activity: false" in output
        assert "Subprocess started: false" in output
        assert "Runner invoked: false" in output


def test_controlled_nuclei_execute_runs_exact_verified_preparation(
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
        runner,
        actor,
        evidence_root,
    ):
        captured["database"] = database
        captured["execution_id"] = execution_id
        captured["request"] = request
        captured["runner"] = runner
        captured["actor"] = actor
        captured["evidence_root"] = evidence_root

        return SimpleNamespace(
            execution=SimpleNamespace(
                state=SimpleNamespace(value="completed"),
            ),
            verified_preparation=SimpleNamespace(
                evidence=SimpleNamespace(
                    evidence_id="evidence-nuclei-preparation",
                ),
            ),
            result=SimpleNamespace(
                tool_name="nuclei",
                target_url=request.target_url,
                executable="/opt/homebrew/bin/nuclei",
                arguments=request.arguments,
                exit_code=0,
                timed_out=False,
            ),
            evidence=SimpleNamespace(
                evidence_id="evidence-nuclei-execution",
                path=str(evidence_root / "execution.json"),
                sha256="f" * 64,
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
        "run_tracked_nuclei_execution",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "controlled",
            "nuclei-execute",
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
            "--execute",
        ],
    )

    assert result.exit_code == 0

    request = captured["request"]

    assert captured["database"] is database
    assert captured["execution_id"] == "execution-test"
    assert captured["runner"] is cli_module.run_tool
    assert captured["actor"] == "cli-controlled-nuclei-execution"
    assert captured["evidence_root"] == (
        tmp_path
        / "evidence"
        / "controlled-nuclei-executions"
    )
    assert request.target_url == "https://example.com/"
    assert request.authorization_confirmed is True
    assert request.active_testing_allowed is True
    assert request.explicitly_approved is True
    assert "-rate-limit" in request.arguments
    assert request.arguments[
        request.arguments.index("-rate-limit") + 1
    ] == "2"
    assert "-concurrency" in request.arguments
    assert request.arguments[
        request.arguments.index("-concurrency") + 1
    ] == "2"
    assert "-timeout" in request.arguments
    assert request.arguments[
        request.arguments.index("-timeout") + 1
    ] == "7"
    assert request.arguments[
        request.arguments.index("-retries") + 1
    ] == "0"

    normalized_output = " ".join(result.stdout.split())

    assert "Phase 6C controlled execution authorized" in normalized_output
    assert "One real Nuclei subprocess" in normalized_output
    assert "Phase 6C controlled Nuclei execution completed" in (
        normalized_output
    )
    assert "Execution state: completed" in normalized_output
    assert "Exit code: 0" in normalized_output
    assert "Timed out: false" in normalized_output
    assert "Automatic retry: false" in normalized_output
    assert "Executed: true" in normalized_output
    assert "Network activity: true" in normalized_output
    assert "Subprocess started: true" in normalized_output
    assert "Runner invoked: true" in normalized_output
    assert "evidence-nuclei-preparation" in normalized_output
    assert "evidence-nuclei-execution" in normalized_output


def test_controlled_nuclei_execute_reports_safe_failure(
    monkeypatch,
) -> None:
    import saarthi_ai.cli as cli_module

    def fake_workflow(*args, **kwargs):
        raise cli_module.NucleiExecutionWorkflowError(
            "simulated controlled execution failure"
        )

    monkeypatch.setattr(
        cli_module,
        "get_database",
        lambda: object(),
    )
    monkeypatch.setattr(
        cli_module,
        "run_tracked_nuclei_execution",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "controlled",
            "nuclei-execute",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
            "--approved",
            "--execute",
        ],
    )

    assert result.exit_code == 1

    normalized_output = " ".join(result.stdout.split())

    assert "simulated controlled execution failure" in normalized_output
    assert "Execution requested: true" in normalized_output
    assert "Automatic retry: false" in normalized_output
    assert "audit trail" in normalized_output


def test_controlled_nuclei_execute_enforces_cli_bounds() -> None:
    result = runner.invoke(
        app,
        [
            "controlled",
            "nuclei-execute",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
            "--timeout",
            "11",
            "--approved",
            "--execute",
        ],
    )

    assert result.exit_code != 0


def test_controlled_observe_renders_clickjacking_analysis(
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
        captured["request"] = request
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
                body_bytes_captured=0,
                body_truncated=False,
                body_sha256="b" * 64,
            ),
            validator_analysis=SimpleNamespace(
                classification=SimpleNamespace(value="protected"),
                reason="Restrictive frame policy observed.",
                protection_sources=("csp_frame_ancestors",),
                csp_frame_ancestors=("'none'",),
                x_frame_options=None,
            ),
            evidence=SimpleNamespace(
                evidence_id="evidence-clickjacking",
                path=str(evidence_root / "clickjacking.json"),
                sha256="a" * 64,
            ),
            reused_existing_evidence=False,
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
            "https://example.com/",
            "--action",
            "clickjacking_header_validation",
            "--method",
            "HEAD",
            "--approved",
        ],
    )

    assert result.exit_code == 0
    request = captured["request"]
    assert (
        request.validation.action
        is ControlledValidationAction.CLICKJACKING_HEADER_VALIDATION
    )
    normalized = " ".join(result.stdout.split())
    assert "6C.2 Clickjacking Header Validation" in normalized
    assert "Classification: protected" in normalized
    assert "csp_frame_ancestors" in normalized
    assert "CSP frame-ancestors: 'none'" in normalized
    assert "Header-only analysis: true" in normalized
    assert "Exploit page generated: false" in normalized
    assert "Browser launched: false" in normalized
    assert "Payload generated: false" in normalized


def test_controlled_observe_renders_parameter_surface_analysis(
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
        captured["request"] = request
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
                body_bytes_captured=0,
                body_truncated=False,
                body_sha256="b" * 64,
            ),
            validator_analysis=SimpleNamespace(
                validator_id=(
                    "6C.3-http-parameter-surface-validation"
                ),
                classification=SimpleNamespace(
                    value="ambiguous_surface_observed"
                ),
                reason="Duplicate parameter name observed.",
                parameter_count=2,
                duplicate_parameter_names=("id",),
                variant_parameter_groups=(),
            ),
            evidence=SimpleNamespace(
                evidence_id="evidence-parameter-surface",
                path=str(evidence_root / "parameters.json"),
                sha256="a" * 64,
            ),
            reused_existing_evidence=False,
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
            "https://example.com/?id=1&id=2",
            "--action",
            "http_parameter_surface_validation",
            "--approved",
        ],
    )

    assert result.exit_code == 0
    request = captured["request"]
    assert (
        request.validation.action
        is (
            ControlledValidationAction
            .HTTP_PARAMETER_SURFACE_VALIDATION
        )
    )
    normalized = " ".join(result.stdout.split())
    assert "6C.3 HTTP Parameter Surface Validation" in normalized
    assert "Classification: ambiguous_surface_observed" in normalized
    assert "Parameters: 2" in normalized
    assert "Duplicate names: id" in normalized
    assert "Target unchanged: true" in normalized
    assert "Parameters mutated: false" in normalized
    assert "Parser attack sent: false" in normalized
    assert "Payload generated: false" in normalized


def test_controlled_observe_renders_session_cookie_analysis(
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
        captured["request"] = request
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
                body_bytes_captured=0,
                body_truncated=False,
                body_sha256="b" * 64,
            ),
            validator_analysis=SimpleNamespace(
                validator_id=(
                    "6C.4-session-cookie-attribute-validation"
                ),
                classification=SimpleNamespace(
                    value="review_recommended"
                ),
                reason="Cookie attributes require review.",
                cookie_count=2,
                cookies_with_issues=1,
                issue_counts=(("missing_http_only", 1),),
            ),
            evidence=SimpleNamespace(
                evidence_id="evidence-session-cookie",
                path=str(evidence_root / "cookies.json"),
                sha256="a" * 64,
            ),
            reused_existing_evidence=False,
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
            "https://example.com/",
            "--action",
            "session_cookie_attribute_validation",
            "--method",
            "GET",
            "--approved",
        ],
    )

    assert result.exit_code == 0
    request = captured["request"]
    assert (
        request.validation.action
        is (
            ControlledValidationAction
            .SESSION_COOKIE_ATTRIBUTE_VALIDATION
        )
    )
    normalized = " ".join(result.stdout.split())
    assert "6C.4 Session Cookie Attribute Validation" in normalized
    assert "Classification: review_recommended" in normalized
    assert "Cookies observed: 2" in normalized
    assert "Cookies with issues: 1" in normalized
    assert "missing_http_only=1" in normalized
    assert "Cookie values discarded: true" in normalized
    assert "Raw Set-Cookie stored: false" in normalized
    assert "Cookie replayed: false" in normalized
    assert "Credential header sent: false" in normalized
    assert "Payload generated: false" in normalized


def test_controlled_observe_rejects_head_for_session_cookie() -> None:
    result = runner.invoke(
        app,
        [
            "controlled",
            "observe",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
            "--action",
            "session_cookie_attribute_validation",
            "--method",
            "HEAD",
            "--approved",
        ],
    )

    assert result.exit_code == 1
    normalized = " ".join(result.stdout.split())
    assert (
        "Session-cookie, CSRF, API exposure-surface, and file-upload "
        "surface validation require GET"
        in normalized
    )


def test_controlled_observe_renders_csrf_surface_analysis(
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
        captured["request"] = request
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
                body_bytes_captured=100,
                body_truncated=False,
                body_sha256="b" * 64,
            ),
            validator_analysis=SimpleNamespace(
                validator_id=(
                    "6C.2-csrf-protection-surface-validation"
                ),
                classification=SimpleNamespace(
                    value="protection_signals_observed"
                ),
                reason="Anti-CSRF field signal observed.",
                post_form_count=1,
                forms_with_token_signal=1,
                forms_without_token_signal=0,
                cross_origin_action_count=0,
                protection_sources=("anti_csrf_field_name",),
            ),
            evidence=SimpleNamespace(
                evidence_id="evidence-csrf-surface",
                path=str(evidence_root / "csrf.json"),
                sha256="a" * 64,
            ),
            reused_existing_evidence=False,
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
            "--action",
            "csrf_protection_surface_validation",
            "--method",
            "GET",
            "--approved",
        ],
    )

    assert result.exit_code == 0
    request = captured["request"]
    assert (
        request.validation.action
        is (
            ControlledValidationAction
            .CSRF_PROTECTION_SURFACE_VALIDATION
        )
    )
    normalized = " ".join(result.stdout.split())
    assert "6C.2 CSRF Protection Surface Validation" in normalized
    assert "Classification: protection_signals_observed" in normalized
    assert "POST forms: 1" in normalized
    assert "Forms with token signal: 1" in normalized
    assert "Forms without token signal: 0" in normalized
    assert "Token values discarded: true" in normalized
    assert "Form submitted: false" in normalized
    assert "Browser launched: false" in normalized
    assert "Request body sent: false" in normalized
    assert "Payload generated: false" in normalized


def test_controlled_observe_renders_api_exposure_analysis(
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
        captured["request"] = request
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
                body_bytes_captured=64,
                body_truncated=False,
                body_sha256="b" * 64,
            ),
            validator_analysis=SimpleNamespace(
                validator_id=(
                    "6C.7-api-data-exposure-surface-validation"
                ),
                classification=SimpleNamespace(
                    value="review_recommended"
                ),
                reason="Sensitive field-name categories observed.",
                nodes_inspected=5,
                sensitive_category_counts=(
                    ("credential_material", 1),
                    ("personal_contact", 1),
                ),
            ),
            evidence=SimpleNamespace(
                evidence_id="evidence-api-exposure",
                path=str(evidence_root / "api-exposure.json"),
                sha256="a" * 64,
            ),
            reused_existing_evidence=False,
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
            "https://example.com/api/profile",
            "--action",
            "api_data_exposure_surface_validation",
            "--method",
            "GET",
            "--approved",
        ],
    )

    assert result.exit_code == 0
    request = captured["request"]
    assert (
        request.validation.action
        is (
            ControlledValidationAction
            .API_DATA_EXPOSURE_SURFACE_VALIDATION
        )
    )
    normalized = " ".join(result.stdout.split())
    assert "6C.7 API Data-Exposure Surface Validation" in normalized
    assert "Classification: review_recommended" in normalized
    assert "JSON nodes inspected: 5" in normalized
    assert "credential_material=1" in normalized
    assert "personal_contact=1" in normalized
    assert "JSON keys discarded: true" in normalized
    assert "JSON values discarded: true" in normalized
    assert "Raw JSON stored: false" in normalized
    assert "Request body sent: false" in normalized
    assert "Authentication used: false" in normalized
    assert "Payload generated: false" in normalized


def test_controlled_observe_renders_upload_surface_analysis(
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
        captured["request"] = request
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
                body_bytes_captured=80,
                body_truncated=False,
                body_sha256="b" * 64,
            ),
            validator_analysis=SimpleNamespace(
                validator_id=(
                    "6C.6-file-upload-surface-validation"
                ),
                classification=SimpleNamespace(
                    value="upload_surface_observed"
                ),
                reason="A file-input surface was observed.",
                upload_form_count=1,
                file_input_count=2,
                post_upload_form_count=1,
                multipart_upload_form_count=1,
                restricted_accept_input_count=1,
                unrestricted_accept_input_count=1,
            ),
            evidence=SimpleNamespace(
                evidence_id="evidence-upload-surface",
                path=str(evidence_root / "upload-surface.json"),
                sha256="a" * 64,
            ),
            reused_existing_evidence=False,
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
            "https://example.com/upload",
            "--action",
            "file_upload_surface_validation",
            "--method",
            "GET",
            "--approved",
        ],
    )

    assert result.exit_code == 0
    request = captured["request"]
    assert (
        request.validation.action
        is ControlledValidationAction.FILE_UPLOAD_SURFACE_VALIDATION
    )
    normalized = " ".join(result.stdout.split())
    assert "6C.6 File Upload Surface Validation" in normalized
    assert "Classification: upload_surface_observed" in normalized
    assert "Upload forms: 1" in normalized
    assert "File inputs: 2" in normalized
    assert "POST / multipart upload forms: 1 / 1" in normalized
    assert "Restricted / unrestricted accept: 1 / 1" in normalized
    assert "Field names discarded: true" in normalized
    assert "Field values discarded: true" in normalized
    assert "Form actions discarded: true" in normalized
    assert "File uploaded: false" in normalized
    assert "Form submitted: false" in normalized
    assert "Request body sent: false" in normalized
    assert "Payload generated: false" in normalized
