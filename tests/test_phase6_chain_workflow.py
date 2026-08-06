"""Tests for the post-4A permission-gated Phase 6C chain."""

from __future__ import annotations

import hashlib
from pathlib import Path

import httpx
import pytest

from saarthi_ai.execution.tool_runner import ToolRunResult
from saarthi_ai.orchestration.models import (
    OrchestrationPhase,
    OrchestrationPhaseOutcome,
)
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.orchestration_workflow import (
    create_orchestration,
)
from saarthi_ai.persistence.phase6_chain_workflow import (
    SAFE_VALIDATOR_ACTIONS,
    run_phase6_safe_chain,
)
from saarthi_ai.tui.app import ReadOnlySaarthiRepository


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    database = SaarthiDatabase(tmp_path / "saarthi.db")
    database.initialize()
    return database


@pytest.mark.asyncio
async def test_safe_chain_runs_every_surface_validator(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            headers={
                "content-type": "text/html",
                "x-frame-options": "DENY",
            },
            text="<html><form><input name='id'></form></html>",
        )

    context = create_orchestration(
        database,
        assessment_name="Safe Phase 6 Chain",
        target_url="https://example.com/?id=1",
        active_testing_allowed=True,
    )

    result = await run_phase6_safe_chain(
        database,
        context,
        evidence_root=tmp_path / "evidence",
        explicitly_approved=True,
        nuclei_preview_approved=False,
        sqlmap_preview_approved=False,
        transport=httpx.MockTransport(handler),
    )

    validator_results = [
        item
        for item in result.phase_results
        if item.phase is OrchestrationPhase.SAFE_VALIDATOR
    ]
    assert len(validator_results) == len(SAFE_VALIDATOR_ACTIONS)
    assert len(requests) == len(SAFE_VALIDATOR_ACTIONS)
    assert all(request.method == "GET" for request in requests)
    assert all(item.completed for item in validator_results)
    assert {
        item.metrics["action"]
        for item in validator_results
    } == {action.value for action in SAFE_VALIDATOR_ACTIONS}

    prerequisite_gates = {
        item.phase: item
        for item in result.phase_results
        if item.phase
        in {
            OrchestrationPhase.BLIND_VALIDATION,
            OrchestrationPhase.OAST_MANAGER,
            OrchestrationPhase.CONFIRMATION,
        }
    }
    assert set(prerequisite_gates) == {
        OrchestrationPhase.BLIND_VALIDATION,
        OrchestrationPhase.OAST_MANAGER,
        OrchestrationPhase.CONFIRMATION,
    }
    assert all(
        item.outcome
        is OrchestrationPhaseOutcome.NOT_APPLICABLE
        for item in prerequisite_gates.values()
    )
    assert all(
        item.metrics["gate_evaluated"] is True
        for item in prerequisite_gates.values()
    )

    preview_results = [
        item
        for item in result.phase_results
        if item.phase
        in {
            OrchestrationPhase.NUCLEI_PREVIEW,
            OrchestrationPhase.SQLMAP_PREVIEW,
        }
    ]
    assert all(
        item.outcome is OrchestrationPhaseOutcome.SKIPPED
        for item in preview_results
    )


@pytest.mark.asyncio
async def test_approved_previews_are_persisted_but_not_executed(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html></html>")

    context = create_orchestration(
        database,
        assessment_name="Approved Preview Chain",
        target_url="https://example.com/search?id=1",
        active_testing_allowed=True,
        intrusive_testing_allowed=True,
    )

    result = await run_phase6_safe_chain(
        database,
        context,
        evidence_root=tmp_path / "evidence",
        explicitly_approved=True,
        nuclei_preview_approved=True,
        sqlmap_preview_approved=True,
        transport=httpx.MockTransport(handler),
    )

    nuclei = next(
        item
        for item in result.phase_results
        if item.phase is OrchestrationPhase.NUCLEI_PREVIEW
    )
    sqlmap = next(
        item
        for item in result.phase_results
        if item.phase is OrchestrationPhase.SQLMAP_PREVIEW
    )
    assert nuclei.phase is OrchestrationPhase.NUCLEI_PREVIEW
    assert sqlmap.phase is OrchestrationPhase.SQLMAP_PREVIEW
    assert nuclei.completed is True
    assert sqlmap.completed is True
    assert nuclei.metrics["executed"] is False
    assert sqlmap.metrics["executed"] is False
    assert nuclei.metrics["network_activity"] is False
    assert sqlmap.metrics["network_activity"] is False
    assert sqlmap.metrics["parameter"] == "id"
    assert result.calculated_status.value == "completed"

    snapshot = ReadOnlySaarthiRepository(
        database.database_path
    ).load()
    assert snapshot.phase6_chain_status["validator_completed"] == "9"
    assert snapshot.phase6_chain_status["nuclei"] == "PREVIEW READY"
    assert snapshot.phase6_chain_status["sqlmap"] == "AWAITING RESULT"
    assert sqlmap.metrics["status"] == "awaiting_external_result"
    assert Path(sqlmap.evidence_path or "").is_file()
    assert (
        snapshot.phase6_chain_status[
            "browser_attack_surface_validation"
        ]
        == "DONE"
    )
    assert (
        snapshot.phase6_chain_status[
            "server_parser_surface_validation"
        ]
        == "DONE"
    )
    assert "6C-safe-validator" in snapshot.completed_phases
    assert any("[6C" in line for line in snapshot.recent_activity)


@pytest.mark.asyncio
async def test_sqlmap_preview_reports_missing_permission_and_parameter(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html></html>")

    context = create_orchestration(
        database,
        assessment_name="Gated SQLmap Preview",
        target_url="https://example.com/",
        active_testing_allowed=True,
    )

    result = await run_phase6_safe_chain(
        database,
        context,
        evidence_root=tmp_path / "evidence",
        explicitly_approved=True,
        nuclei_preview_approved=False,
        sqlmap_preview_approved=True,
        transport=httpx.MockTransport(handler),
    )

    sqlmap = next(
        item
        for item in result.phase_results
        if item.phase is OrchestrationPhase.SQLMAP_PREVIEW
    )
    assert sqlmap.outcome is OrchestrationPhaseOutcome.SKIPPED
    assert "intrusive-testing permission is disabled" in (
        sqlmap.reason or ""
    )
    assert "target URL has no query parameter" in (sqlmap.reason or "")


@pytest.mark.asyncio
async def test_nuclei_execution_requires_distinct_approval_and_is_bounded(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    def http_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html></html>")

    runner_calls: list[tuple[str, tuple[str, ...]]] = []

    def nuclei_runner(profile, arguments, *, on_output=None):
        argument_tuple = tuple(arguments)
        runner_calls.append((profile.name, argument_tuple))
        stdout = '{"template-id":"safe-example"}\n'
        stderr = ""
        return ToolRunResult(
            tool_name=profile.name,
            executable="/test/bin/nuclei",
            arguments=argument_tuple,
            exit_code=0,
            stdout=stdout,
            stderr=stderr,
            stdout_sha256=hashlib.sha256(
                stdout.encode("utf-8")
            ).hexdigest(),
            stderr_sha256=hashlib.sha256(
                stderr.encode("utf-8")
            ).hexdigest(),
            timed_out=False,
        )

    context = create_orchestration(
        database,
        assessment_name="Approved Nuclei Execution Chain",
        target_url="https://example.com/",
        active_testing_allowed=True,
    )

    result = await run_phase6_safe_chain(
        database,
        context,
        evidence_root=tmp_path / "evidence",
        explicitly_approved=True,
        nuclei_preview_approved=True,
        nuclei_execute_approved=True,
        sqlmap_preview_approved=False,
        transport=httpx.MockTransport(http_handler),
        nuclei_runner=nuclei_runner,
    )

    nuclei = next(
        item
        for item in result.phase_results
        if item.phase is OrchestrationPhase.NUCLEI
    )
    assert nuclei.phase is OrchestrationPhase.NUCLEI
    assert nuclei.metrics["executed"] is True
    assert nuclei.metrics["network_activity"] is True
    assert nuclei.metrics["exit_code"] == 0
    assert len(runner_calls) == 1
    tool_name, arguments = runner_calls[0]
    assert tool_name == "nuclei"
    assert "-tags" in arguments
    assert "exposure,misconfig,tech" in arguments
    assert "-exclude-tags" in arguments
    assert "bruteforce,dos,fuzz,headless,intrusive,token-spray" in (
        arguments
    )
    assert arguments[arguments.index("-retries") + 1] == "0"

    snapshot = ReadOnlySaarthiRepository(
        database.database_path
    ).load()
    assert snapshot.phase6_chain_status["nuclei"] == "EXECUTED"
    assert snapshot.current_phase == (
        "6C — LOW-RISK ATTACK VALIDATORS"
    )


@pytest.mark.asyncio
async def test_nuclei_timeout_is_optional_and_chain_continues(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    def http_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html></html>")

    def timed_out_runner(profile, arguments, *, on_output=None):
        argument_tuple = tuple(arguments)
        return ToolRunResult(
            tool_name=profile.name,
            executable="/test/bin/nuclei",
            arguments=argument_tuple,
            exit_code=-1,
            stdout="partial bounded output\n",
            stderr="process timeout\n",
            stdout_sha256=hashlib.sha256(
                b"partial bounded output\n"
            ).hexdigest(),
            stderr_sha256=hashlib.sha256(
                b"process timeout\n"
            ).hexdigest(),
            timed_out=True,
        )

    context = create_orchestration(
        database,
        assessment_name="Nuclei Timeout Continuation",
        target_url="https://example.com/?id=1",
        active_testing_allowed=True,
        intrusive_testing_allowed=True,
    )

    result = await run_phase6_safe_chain(
        database,
        context,
        evidence_root=tmp_path / "evidence",
        explicitly_approved=True,
        nuclei_preview_approved=True,
        nuclei_execute_approved=True,
        sqlmap_preview_approved=True,
        transport=httpx.MockTransport(http_handler),
        nuclei_runner=timed_out_runner,
    )

    nuclei = next(
        item
        for item in result.phase_results
        if item.phase is OrchestrationPhase.NUCLEI
    )
    sqlmap = next(
        item
        for item in result.phase_results
        if item.phase is OrchestrationPhase.SQLMAP_PREVIEW
    )
    validators = [
        item
        for item in result.phase_results
        if item.phase is OrchestrationPhase.SAFE_VALIDATOR
    ]

    assert nuclei.failed is True
    assert nuclei.required is False
    assert nuclei.metrics["timed_out"] is True
    assert nuclei.metrics["continued_after_failure"] is True
    assert nuclei.evidence_id is not None
    assert sqlmap.metrics["status"] == "awaiting_external_result"
    assert len(validators) == len(SAFE_VALIDATOR_ACTIONS)
    assert all(item.completed for item in validators)
    assert result.calculated_status.value == "partial"

    snapshot = ReadOnlySaarthiRepository(
        database.database_path
    ).load()
    assert snapshot.phase6_chain_status["nuclei"] == "TIMED OUT"
    assert snapshot.phase6_chain_status["sqlmap"] == "AWAITING RESULT"
    assert snapshot.phase6_chain_status["validator_completed"] == "9"
