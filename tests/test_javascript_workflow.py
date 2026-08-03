from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.javascript_workflow import (
    run_tracked_javascript_intelligence,
)
from saarthi_ai.persistence.models import (
    ExecutionCreate,
    ExecutionState,
)
from saarthi_ai.recon.javascript_models import (
    JavaScriptAssetRecord,
    JavaScriptCollectionResult,
    JavaScriptFetchRecord,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    """Create an isolated Phase 3E database."""

    repository = SaarthiDatabase(tmp_path / "javascript.db")
    repository.initialize()
    return repository


def create_execution(
    database: SaarthiDatabase,
    *,
    target: str = "example.com",
    active_testing_allowed: bool = True,
) -> str:
    """Create a scoped execution for Phase 3E."""

    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Phase 3E JavaScript Intelligence",
            asset_types=["web"],
            targets=[target],
            authorization_confirmed=True,
            active_testing_allowed=active_testing_allowed,
            intrusive_testing_allowed=False,
        )
    )

    return execution.execution_id


def build_collection_result(
    tmp_path: Path,
    *,
    domain: str = "example.com",
) -> JavaScriptCollectionResult:
    """Build deterministic Phase 3E collector output."""

    evidence_path = tmp_path / "javascript.json"
    evidence_path.write_text(
        json.dumps({"domain": domain}),
        encoding="utf-8",
    )

    return JavaScriptCollectionResult(
        collector_execution_id="javascript-run-test",
        collector_evidence_id="javascript-evidence-test",
        source_evidence_path="evidence/crawling/source.json",
        source_collector_execution_id="crawl-run-test",
        source_collector_evidence_id="crawl-evidence-test",
        domain=domain,
        input_javascript_count=2,
        fetched_javascript_count=1,
        failed_fetch_count=1,
        endpoint_count=2,
        parameter_count=1,
        websocket_count=0,
        source_map_count=1,
        secret_candidate_count=0,
        rejected_inputs=[],
        assets=[
            JavaScriptAssetRecord(
                fetch=JavaScriptFetchRecord(
                    url="https://example.com/assets/app.js",
                    final_url="https://example.com/assets/app.js",
                    status_code=200,
                    content_type="text/javascript",
                    body_bytes_captured=128,
                    body_truncated=False,
                    body_sha256="a" * 64,
                ),
            )
        ],
        collected_at=datetime.now(UTC),
        evidence_path=str(evidence_path),
        evidence_sha256="b" * 64,
        evidence_size_bytes=evidence_path.stat().st_size,
    )


def test_tracked_javascript_completes_and_registers_evidence(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful Phase 3E collection should persist evidence."""

    from saarthi_ai.persistence import javascript_workflow

    collection = build_collection_result(tmp_path)

    async def fake_collect(
        source_evidence_path: Path,
        *,
        evidence_root: Path | None = None,
    progress_callback=None,
    ) -> JavaScriptCollectionResult:
        return collection

    monkeypatch.setattr(
        javascript_workflow,
        "collect_javascript_intelligence",
        fake_collect,
    )

    execution_id = create_execution(database)

    result = run_tracked_javascript_intelligence(
        database,
        execution_id,
        tmp_path / "source-crawl.json",
        evidence_root=tmp_path,
    )

    assert result.execution.state is ExecutionState.COMPLETED
    assert result.collection.endpoint_count == 2
    assert result.evidence.evidence_type.value == "javascript_intelligence_result"
    assert result.evidence.tool_name == "saarthi-javascript-intelligence"

    evidence = database.list_evidence(execution_id)
    assert len(evidence) == 1

    events = database.list_audit_events(execution_id)
    event_types = [event.event_type.value for event in events]

    assert "tool_started" in event_types
    assert "tool_completed" in event_types
    assert "evidence_added" in event_types


def test_javascript_domain_must_match_execution_scope(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JavaScript evidence cannot attach to an unrelated execution."""

    from saarthi_ai.persistence import javascript_workflow

    collection = build_collection_result(
        tmp_path,
        domain="outside.test",
    )

    async def fake_collect(
        source_evidence_path: Path,
        *,
        evidence_root: Path | None = None,
    progress_callback=None,
    ) -> JavaScriptCollectionResult:
        return collection

    monkeypatch.setattr(
        javascript_workflow,
        "collect_javascript_intelligence",
        fake_collect,
    )

    execution_id = create_execution(database)

    with pytest.raises(
        InvalidStateTransitionError,
        match="not associated with this execution",
    ):
        run_tracked_javascript_intelligence(
            database,
            execution_id,
            tmp_path / "source-crawl.json",
            evidence_root=tmp_path,
        )

    execution = database.get_execution(execution_id)
    assert execution.state is ExecutionState.FAILED

    events = database.list_audit_events(execution_id)
    assert any(event.event_type.value == "tool_failed" for event in events)


def test_javascript_requires_active_testing_permission(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    """JavaScript fetching must not run without active permission."""

    execution_id = create_execution(
        database,
        active_testing_allowed=False,
    )

    with pytest.raises(
        InvalidStateTransitionError,
        match="does not allow active testing",
    ):
        run_tracked_javascript_intelligence(
            database,
            execution_id,
            tmp_path / "source-crawl.json",
            evidence_root=tmp_path,
        )

    execution = database.get_execution(execution_id)
    assert execution.state is ExecutionState.CREATED
