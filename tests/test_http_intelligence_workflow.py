from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.http_intelligence_workflow import (
    run_tracked_http_intelligence,
)
from saarthi_ai.persistence.models import (
    ExecutionCreate,
    ExecutionState,
)
from saarthi_ai.recon.http_intelligence_models import (
    HttpIntelligenceCollectionResult,
    HttpIntelligenceRecord,
    HttpIntelligenceToolRun,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    """Create an isolated Phase 3C database."""

    repository = SaarthiDatabase(tmp_path / "http-intelligence.db")
    repository.initialize()
    return repository


def create_execution(
    database: SaarthiDatabase,
    *,
    target: str = "example.com",
    authorized: bool = True,
) -> str:
    """Create a scoped execution for Phase 3C."""

    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Phase 3C HTTP Intelligence",
            asset_types=["web"],
            targets=[target],
            authorization_confirmed=authorized,
            active_testing_allowed=True,
            intrusive_testing_allowed=False,
        )
    )

    return execution.execution_id


def build_collection_result(
    tmp_path: Path,
    *,
    domain: str = "example.com",
) -> HttpIntelligenceCollectionResult:
    """Build deterministic collector output."""

    evidence_path = tmp_path / "http-intelligence.json"
    evidence_path.write_text(
        json.dumps({"domain": domain}),
        encoding="utf-8",
    )

    return HttpIntelligenceCollectionResult(
        collector_execution_id="http-intelligence-run-test",
        collector_evidence_id="http-intelligence-evidence-test",
        source_evidence_path="evidence/subdomains/source.json",
        source_collector_execution_id="subdomain-run-test",
        source_collector_evidence_id="subdomain-evidence-test",
        domain=domain,
        input_count=2,
        live_service_count=1,
        malformed_line_count=0,
        rejected_inputs=[],
        rejected_results=[],
        records=[
            HttpIntelligenceRecord(
                input="api.example.com",
                url="https://api.example.com",
                scheme="https",
                host="api.example.com",
                port=443,
                status_code=200,
                title="API",
                technologies=["nginx"],
                webserver="nginx",
                content_length=123,
                ip="192.0.2.10",
            )
        ],
        tool_run=HttpIntelligenceToolRun(
            tool_name="projectdiscovery-httpx",
            available=True,
            executable="/approved/httpx",
            arguments=["-json"],
            exit_code=0,
            timed_out=False,
            stdout_sha256="a" * 64,
            stderr_sha256="b" * 64,
        ),
        collected_at=datetime.now(UTC),
        evidence_path=str(evidence_path),
        evidence_sha256="c" * 64,
        evidence_size_bytes=evidence_path.stat().st_size,
    )


def test_tracked_http_intelligence_completes_and_registers_evidence(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful Phase 3C collection should complete and persist evidence."""

    from saarthi_ai.persistence import http_intelligence_workflow

    collection = build_collection_result(tmp_path)

    monkeypatch.setattr(
        http_intelligence_workflow,
        "collect_http_intelligence",
        lambda source_evidence_path, *, evidence_root=None, progress_callback=None: collection,
    )

    execution_id = create_execution(database)

    result = run_tracked_http_intelligence(
        database,
        execution_id,
        tmp_path / "source-subdomains.json",
        evidence_root=tmp_path,
    )

    assert result.execution.state is ExecutionState.COMPLETED
    assert result.collection.live_service_count == 1
    assert result.evidence.evidence_type.value == "http_intelligence_result"
    assert result.evidence.tool_name == "projectdiscovery-httpx"

    evidence = database.list_evidence(execution_id)
    assert len(evidence) == 1

    events = database.list_audit_events(execution_id)
    event_types = [event.event_type.value for event in events]

    assert "tool_started" in event_types
    assert "tool_completed" in event_types
    assert "evidence_added" in event_types


def test_collection_domain_must_match_execution_scope(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Collector evidence cannot be attached to an unrelated execution."""

    from saarthi_ai.persistence import http_intelligence_workflow

    collection = build_collection_result(
        tmp_path,
        domain="outside.test",
    )

    monkeypatch.setattr(
        http_intelligence_workflow,
        "collect_http_intelligence",
        lambda source_evidence_path, *, evidence_root=None, progress_callback=None: collection,
    )

    execution_id = create_execution(database)

    with pytest.raises(
        InvalidStateTransitionError,
        match="not associated with this execution",
    ):
        run_tracked_http_intelligence(
            database,
            execution_id,
            tmp_path / "source-subdomains.json",
            evidence_root=tmp_path,
        )

    execution = database.get_execution(execution_id)
    assert execution.state is ExecutionState.FAILED

    events = database.list_audit_events(execution_id)
    assert any(
        event.event_type.value == "tool_failed"
        for event in events
    )


def test_database_rejects_unauthorized_execution(
    database: SaarthiDatabase,
) -> None:
    """The persistence layer must reject unauthorized executions."""

    from saarthi_ai.persistence.database import PersistenceError

    with pytest.raises(
        PersistenceError,
        match="without confirmed authorization",
    ):
        create_execution(
            database,
            authorized=False,
        )
