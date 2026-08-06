"""Tests for the post-4A permission-gated Phase 6C chain."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

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

    preview_results = result.phase_results[:2]
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

    nuclei, sqlmap = result.phase_results[:2]
    assert nuclei.phase is OrchestrationPhase.NUCLEI_PREVIEW
    assert sqlmap.phase is OrchestrationPhase.SQLMAP_PREVIEW
    assert nuclei.completed is True
    assert sqlmap.completed is True
    assert nuclei.metrics["executed"] is False
    assert sqlmap.metrics["executed"] is False
    assert nuclei.metrics["network_activity"] is False
    assert sqlmap.metrics["network_activity"] is False
    assert sqlmap.metrics["parameter"] == "id"

    snapshot = ReadOnlySaarthiRepository(
        database.database_path
    ).load()
    assert snapshot.phase6_chain_status["validator_completed"] == "9"
    assert snapshot.phase6_chain_status["nuclei"] == "PREVIEW READY"
    assert snapshot.phase6_chain_status["sqlmap"] == "PREVIEW READY"
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

    sqlmap = result.phase_results[1]
    assert sqlmap.outcome is OrchestrationPhaseOutcome.SKIPPED
    assert "intrusive-testing permission is disabled" in (
        sqlmap.reason or ""
    )
    assert "target URL has no query parameter" in (sqlmap.reason or "")
