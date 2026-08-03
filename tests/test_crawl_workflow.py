from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from saarthi_ai.persistence.crawl_workflow import run_tracked_crawl
from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.models import (
    ExecutionCreate,
    ExecutionState,
)
from saarthi_ai.recon.crawl_models import (
    CrawlCollectionResult,
    CrawlToolRun,
    CrawlUrlRecord,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    """Create an isolated Phase 3D database."""

    repository = SaarthiDatabase(tmp_path / "crawl.db")
    repository.initialize()
    return repository


def create_execution(
    database: SaarthiDatabase,
    *,
    target: str = "example.com",
    active_testing_allowed: bool = True,
) -> str:
    """Create a scoped execution for Phase 3D."""

    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Phase 3D Crawl Intelligence",
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
) -> CrawlCollectionResult:
    """Build deterministic Phase 3D collector output."""

    evidence_path = tmp_path / "crawl.json"
    evidence_path.write_text(
        json.dumps({"domain": domain}),
        encoding="utf-8",
    )

    return CrawlCollectionResult(
        collector_execution_id="crawl-run-test",
        collector_evidence_id="crawl-evidence-test",
        source_evidence_path="evidence/http-intelligence/source.json",
        source_collector_execution_id="http-intelligence-run-test",
        source_collector_evidence_id="http-intelligence-evidence-test",
        domain=domain,
        input_service_count=2,
        crawled_service_count=1,
        discovered_url_count=1,
        form_count=0,
        parameter_count=1,
        javascript_url_count=0,
        websocket_url_count=0,
        malformed_line_count=0,
        rejected_inputs=[],
        rejected_results=[],
        urls=[
            CrawlUrlRecord(
                url="https://example.com/search?q=saarthi",
                scheme="https",
                host="example.com",
                port=443,
                path="/search",
                query="q=saarthi",
                method="GET",
                status_code=200,
                content_type="text/html",
            )
        ],
        forms=[],
        tool_runs=[
            CrawlToolRun(
                tool_name="projectdiscovery-katana",
                available=True,
                executable="/approved/katana",
                arguments=["-jsonl"],
                exit_code=0,
                timed_out=False,
                stdout_sha256="a" * 64,
                stderr_sha256="b" * 64,
            )
        ],
        collected_at=datetime.now(UTC),
        evidence_path=str(evidence_path),
        evidence_sha256="c" * 64,
        evidence_size_bytes=evidence_path.stat().st_size,
    )


def test_tracked_crawl_completes_and_registers_evidence(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful Phase 3D crawling should persist evidence."""

    from saarthi_ai.persistence import crawl_workflow

    collection = build_collection_result(tmp_path)

    monkeypatch.setattr(
        crawl_workflow,
        "collect_crawl_intelligence",
        lambda source_evidence_path, *, evidence_root=None, progress_callback=None: collection,
    )

    execution_id = create_execution(database)

    result = run_tracked_crawl(
        database,
        execution_id,
        tmp_path / "source-http-intelligence.json",
        evidence_root=tmp_path,
    )

    assert result.execution.state is ExecutionState.COMPLETED
    assert result.collection.discovered_url_count == 1
    assert result.evidence.evidence_type.value == "crawl_result"
    assert result.evidence.tool_name == "projectdiscovery-katana"

    evidence = database.list_evidence(execution_id)
    assert len(evidence) == 1

    events = database.list_audit_events(execution_id)
    event_types = [event.event_type.value for event in events]

    assert "tool_started" in event_types
    assert "tool_completed" in event_types
    assert "evidence_added" in event_types


def test_crawl_domain_must_match_execution_scope(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Crawl evidence cannot be attached to an unrelated execution."""

    from saarthi_ai.persistence import crawl_workflow

    collection = build_collection_result(
        tmp_path,
        domain="outside.test",
    )

    monkeypatch.setattr(
        crawl_workflow,
        "collect_crawl_intelligence",
        lambda source_evidence_path, *, evidence_root=None, progress_callback=None: collection,
    )

    execution_id = create_execution(database)

    with pytest.raises(
        InvalidStateTransitionError,
        match="not associated with this execution",
    ):
        run_tracked_crawl(
            database,
            execution_id,
            tmp_path / "source-http-intelligence.json",
            evidence_root=tmp_path,
        )

    execution = database.get_execution(execution_id)
    assert execution.state is ExecutionState.FAILED

    events = database.list_audit_events(execution_id)
    assert any(event.event_type.value == "tool_failed" for event in events)


def test_crawl_requires_active_testing_permission(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    """Katana crawling must not run when active testing is disabled."""

    execution_id = create_execution(
        database,
        active_testing_allowed=False,
    )

    with pytest.raises(
        InvalidStateTransitionError,
        match="does not allow active testing",
    ):
        run_tracked_crawl(
            database,
            execution_id,
            tmp_path / "source-http-intelligence.json",
            evidence_root=tmp_path,
        )

    execution = database.get_execution(execution_id)
    assert execution.state is ExecutionState.CREATED
