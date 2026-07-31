from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    PersistenceError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.dns_workflow import (
    run_tracked_dns_collection,
)
from saarthi_ai.persistence.models import (
    ExecutionCreate,
    ExecutionState,
)
from saarthi_ai.recon.dns_collector import (
    DnsCollectionError,
    DnsCollectionResult,
    DnsRecord,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    """Create an isolated execution database."""

    repository = SaarthiDatabase(tmp_path / "tracked-dns.db")
    repository.initialize()
    return repository


def create_execution(
    database: SaarthiDatabase,
    *,
    target: str = "https://example.com",
) -> str:
    """Create a Web execution for DNS workflow testing."""

    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Tracked DNS VAPT",
            asset_types=["web"],
            targets=[target],
            authorization_confirmed=True,
            active_testing_allowed=True,
            intrusive_testing_allowed=False,
        )
    )

    return execution.execution_id


def build_dns_result(tmp_path: Path) -> DnsCollectionResult:
    """Create deterministic DNS collector output."""

    evidence_path = tmp_path / "dns-result.json"
    evidence_path.write_text('{"domain": "example.com"}')

    return DnsCollectionResult(
        collector_execution_id="dns-run-test",
        collector_evidence_id="dns-evidence-test",
        domain="example.com",
        nameserver="192.0.2.53",
        records={
            "A": [
                DnsRecord(
                    record_type="A",
                    value="192.0.2.10",
                    ttl=300,
                )
            ],
            "AAAA": [],
            "CNAME": [],
            "MX": [],
            "NS": [],
            "TXT": [],
        },
        errors={},
        collected_at=datetime.now(UTC),
        evidence_path=str(evidence_path),
        evidence_sha256="a" * 64,
        evidence_size_bytes=evidence_path.stat().st_size,
    )


def test_tracked_dns_collection_completes_and_registers_evidence(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful DNS collection should complete and register evidence."""

    from saarthi_ai.persistence import dns_workflow

    def mocked_collect_dns_records(
        domain: str,
        *,
        evidence_root: Path | None = None,
    ) -> DnsCollectionResult:
        assert domain == "example.com"
        assert evidence_root == tmp_path
        return build_dns_result(tmp_path)

    monkeypatch.setattr(
        dns_workflow,
        "collect_dns_records",
        mocked_collect_dns_records,
    )

    execution_id = create_execution(database)

    result = run_tracked_dns_collection(
        database,
        execution_id,
        "example.com",
        evidence_root=tmp_path,
    )

    assert result.execution.state is ExecutionState.COMPLETED
    assert result.collection.domain == "example.com"
    assert result.collection.records["A"][0].value == "192.0.2.10"
    assert result.evidence.evidence_type.value == "dns_result"
    assert result.evidence.step_id == "recon-dns-001"
    assert result.evidence.tool_name == "internal-dns-collector"

    evidence_items = database.list_evidence(execution_id)
    assert len(evidence_items) == 1
    assert evidence_items[0].evidence_type.value == "dns_result"

    events = database.list_audit_events(execution_id)
    event_types = [event.event_type.value for event in events]

    assert "tool_started" in event_types
    assert "tool_completed" in event_types
    assert "evidence_added" in event_types
    assert event_types.count("state_changed") >= 3


def test_dns_domain_must_match_execution_scope(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    """DNS domain must belong to the execution target scope."""

    execution_id = create_execution(database)

    with pytest.raises(
        InvalidStateTransitionError,
        match="not associated with this execution",
    ):
        run_tracked_dns_collection(
            database,
            execution_id,
            "other-example.net",
            evidence_root=tmp_path,
        )

    execution = database.get_execution(execution_id)
    assert execution.state is ExecutionState.CREATED
    assert database.list_evidence(execution_id) == []


def test_dns_subdomain_is_allowed_for_parent_domain_scope(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A subdomain should be accepted under an authorized parent domain."""

    from saarthi_ai.persistence import dns_workflow

    def mocked_collect_dns_records(
        domain: str,
        *,
        evidence_root: Path | None = None,
    ) -> DnsCollectionResult:
        result = build_dns_result(tmp_path)

        return result.model_copy(
            update={
                "domain": domain,
            }
        )

    monkeypatch.setattr(
        dns_workflow,
        "collect_dns_records",
        mocked_collect_dns_records,
    )

    execution_id = create_execution(
        database,
        target="https://example.com",
    )

    result = run_tracked_dns_collection(
        database,
        execution_id,
        "api.example.com",
        evidence_root=tmp_path,
    )

    assert result.execution.state is ExecutionState.COMPLETED
    assert result.collection.domain == "api.example.com"


def test_execution_cannot_be_created_without_authorization(
    database: SaarthiDatabase,
) -> None:
    """Persistence should reject executions without authorization."""

    with pytest.raises(
        PersistenceError,
        match="cannot be created without confirmed authorization",
    ):
        database.create_execution(
            ExecutionCreate(
                assessment_name="Unauthorized DNS VAPT",
                asset_types=["web"],
                targets=["https://example.com"],
                authorization_confirmed=False,
                active_testing_allowed=True,
                intrusive_testing_allowed=False,
            )
        )


def test_dns_collection_failure_marks_execution_failed(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Collector failures should be audited and fail the execution."""

    from saarthi_ai.persistence import dns_workflow

    def mocked_collect_dns_records(
        domain: str,
        *,
        evidence_root: Path | None = None,
    ) -> DnsCollectionResult:
        raise DnsCollectionError("DNS query timed out.")

    monkeypatch.setattr(
        dns_workflow,
        "collect_dns_records",
        mocked_collect_dns_records,
    )

    execution_id = create_execution(database)

    with pytest.raises(
        DnsCollectionError,
        match="DNS query timed out",
    ):
        run_tracked_dns_collection(
            database,
            execution_id,
            "example.com",
            evidence_root=tmp_path,
        )

    execution = database.get_execution(execution_id)

    assert execution.state is ExecutionState.FAILED
    assert execution.failure_reason == "DNS query timed out."
    assert database.list_evidence(execution_id) == []

    events = database.list_audit_events(execution_id)
    event_types = [event.event_type.value for event in events]

    assert "tool_started" in event_types
    assert "tool_failed" in event_types
    assert "tool_completed" not in event_types
