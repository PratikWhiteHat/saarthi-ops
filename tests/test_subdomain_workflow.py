from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.models import (
    ExecutionCreate,
    ExecutionState,
)
from saarthi_ai.persistence.subdomain_workflow import (
    run_tracked_subdomain_collection,
)
from saarthi_ai.recon.subdomain_collector import (
    SubdomainCandidate,
    SubdomainCollectionError,
    SubdomainCollectionResult,
    ToolExecutionSummary,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "tracked-subdomains.db")
    repository.initialize()
    return repository


def create_execution(
    database: SaarthiDatabase,
    *,
    target: str = "https://example.com",
) -> str:
    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Tracked Subdomain VAPT",
            asset_types=["web"],
            targets=[target],
            authorization_confirmed=True,
            active_testing_allowed=True,
            intrusive_testing_allowed=False,
        )
    )
    return execution.execution_id


def build_collection_result(
    tmp_path: Path,
    *,
    domain: str = "example.com",
) -> SubdomainCollectionResult:
    evidence_path = tmp_path / "subdomains.json"
    evidence_path.write_text('{"domain": "example.com"}')

    return SubdomainCollectionResult(
        collector_execution_id="subdomain-run-test",
        collector_evidence_id="subdomain-evidence-test",
        domain=domain,
        source="multi-provider",
        candidates=[
            SubdomainCandidate(
                hostname=domain,
                sources=["scope-root"],
            ),
            SubdomainCandidate(
                hostname=f"api.{domain}",
                sources=["subfinder", "amass"],
            ),
        ],
        raw_entry_count=4,
        rejected_names=["outside.test"],
        tool_runs=[
            ToolExecutionSummary(
                tool_name="subfinder",
                available=True,
                executable="/approved/subfinder",
                arguments=["-silent", "-d", domain],
                exit_code=0,
                result_count=2,
            )
        ],
        collected_at=datetime.now(UTC),
        evidence_path=str(evidence_path),
        evidence_sha256="a" * 64,
        evidence_size_bytes=evidence_path.stat().st_size,
    )


def test_tracked_subdomain_collection_completes(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from saarthi_ai.persistence import subdomain_workflow

    def mocked_collect(
        domain: str,
        *,
        evidence_root: Path | None = None,
        progress_callback=None,
    ) -> SubdomainCollectionResult:
        assert domain == "example.com"
        assert evidence_root == tmp_path
        return build_collection_result(tmp_path)

    monkeypatch.setattr(
        subdomain_workflow,
        "collect_subdomains",
        mocked_collect,
    )

    execution_id = create_execution(database)

    result = run_tracked_subdomain_collection(
        database,
        execution_id,
        "example.com",
        evidence_root=tmp_path,
    )

    assert result.execution.state is ExecutionState.COMPLETED
    assert result.collection.source == "multi-provider"
    assert len(result.collection.candidates) == 2
    assert result.evidence.evidence_type.value == "subdomain_result"
    assert result.evidence.step_id == "recon-subdomains-001"

    evidence = database.list_evidence(execution_id)
    assert len(evidence) == 1

    events = database.list_audit_events(execution_id)
    event_types = [event.event_type.value for event in events]

    assert "tool_started" in event_types
    assert "tool_completed" in event_types
    assert "evidence_added" in event_types


def test_subdomain_domain_must_match_execution_scope(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)

    with pytest.raises(
        InvalidStateTransitionError,
        match="not associated with this execution",
    ):
        run_tracked_subdomain_collection(
            database,
            execution_id,
            "other.test",
            evidence_root=tmp_path,
        )

    execution = database.get_execution(execution_id)
    assert execution.state is ExecutionState.CREATED
    assert database.list_evidence(execution_id) == []


def test_subdomain_collection_accepts_scoped_subdomain(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from saarthi_ai.persistence import subdomain_workflow

    def mocked_collect(
        domain: str,
        *,
        evidence_root: Path | None = None,
        progress_callback=None,
    ) -> SubdomainCollectionResult:
        return build_collection_result(
            tmp_path,
            domain=domain,
        )

    monkeypatch.setattr(
        subdomain_workflow,
        "collect_subdomains",
        mocked_collect,
    )

    execution_id = create_execution(database)

    result = run_tracked_subdomain_collection(
        database,
        execution_id,
        "api.example.com",
        evidence_root=tmp_path,
    )

    assert result.execution.state is ExecutionState.COMPLETED
    assert result.collection.domain == "api.example.com"


def test_subdomain_failure_marks_execution_failed(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from saarthi_ai.persistence import subdomain_workflow

    def mocked_collect(
        domain: str,
        *,
        evidence_root: Path | None = None,
        progress_callback=None,
    ) -> SubdomainCollectionResult:
        raise SubdomainCollectionError(
            "All passive providers failed."
        )

    monkeypatch.setattr(
        subdomain_workflow,
        "collect_subdomains",
        mocked_collect,
    )

    execution_id = create_execution(database)

    with pytest.raises(
        SubdomainCollectionError,
        match="All passive providers failed",
    ):
        run_tracked_subdomain_collection(
            database,
            execution_id,
            "example.com",
            evidence_root=tmp_path,
        )

    execution = database.get_execution(execution_id)

    assert execution.state is ExecutionState.FAILED
    assert execution.failure_reason == "All passive providers failed."
    assert database.list_evidence(execution_id) == []

    events = database.list_audit_events(execution_id)
    event_types = [event.event_type.value for event in events]

    assert "tool_started" in event_types
    assert "tool_failed" in event_types
    assert "tool_completed" not in event_types
