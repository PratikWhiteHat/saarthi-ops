"""Persistence tests for Phase 6A attack hypothesis generation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from saarthi_ai.attack_hypothesis import (
    AttackHypothesisFamily,
    AttackHypothesisGenerationRequest,
)
from saarthi_ai.persistence.attack_hypothesis_workflow import (
    create_tracked_attack_hypotheses,
)
from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceCreate,
    EvidenceType,
    ExecutionCreate,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "phase-6a.db")
    repository.initialize()
    return repository


def create_execution(
    database: SaarthiDatabase,
    *,
    target: str = "example.com",
    authorized: bool = True,
) -> str:
    return database.create_execution(
        ExecutionCreate(
            assessment_name="Phase 6A Hypothesis Generation",
            asset_types=["web"],
            targets=[target],
            authorization_confirmed=authorized,
        )
    ).execution_id


def add_source_evidence(
    database: SaarthiDatabase,
    execution_id: str,
) -> None:
    database.add_evidence(
        execution_id,
        EvidenceCreate(
            evidence_type=EvidenceType.CRAWL_RESULT,
            source="test-crawl",
            path="/tmp/test-crawl.json",
            sha256="a" * 64,
            size_bytes=10,
            content_type="application/json",
            metadata={
                "domain": "example.com",
                "parameter_count": 4,
                "form_count": 1,
            },
        ),
    )
    database.add_evidence(
        execution_id,
        EvidenceCreate(
            evidence_type=(
                EvidenceType.JAVASCRIPT_INTELLIGENCE_RESULT
            ),
            source="test-javascript",
            path="/tmp/test-javascript.json",
            sha256="b" * 64,
            size_bytes=10,
            content_type="application/json",
            metadata={
                "domain": "example.com",
                "endpoint_count": 3,
                "parameter_count": 2,
                "websocket_count": 0,
                "secret_candidate_count": 1,
                "secret_values_stored": False,
            },
        ),
    )


def make_request(
    execution_id: str,
    **overrides: object,
) -> AttackHypothesisGenerationRequest:
    values: dict[str, object] = {
        "execution_id": execution_id,
        "target_url": "https://example.com/",
        "authorized": True,
        "max_hypotheses": 20,
    }
    values.update(overrides)
    return AttackHypothesisGenerationRequest(
        **values,  # type: ignore[arg-type]
    )


def test_hypothesis_set_is_persisted_without_execution(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    add_source_evidence(database, execution_id)

    result = create_tracked_attack_hypotheses(
        database,
        make_request(execution_id),
        evidence_root=tmp_path / "evidence",
    )

    assert (
        result.evidence.evidence_type
        is EvidenceType.ATTACK_HYPOTHESIS_SET
    )
    assert result.reused_existing_evidence is False
    assert {
        item.family for item in result.hypothesis_set.hypotheses
    } == {
        AttackHypothesisFamily.INJECTION,
        AttackHypothesisFamily.API_BUSINESS_LOGIC,
        AttackHypothesisFamily.SENSITIVE_DATA_EXPOSURE,
    }

    evidence_bytes = Path(result.evidence.path).read_bytes()
    payload = json.loads(evidence_bytes)

    assert (
        hashlib.sha256(evidence_bytes).hexdigest()
        == result.evidence.sha256
    )
    assert payload["phase"] == "6A"
    assert payload["summary"]["hypothesis_count"] == 3
    assert payload["execution"] == {
        "executed": False,
        "network_activity": False,
        "payload_generated": False,
        "subprocess_started": False,
    }
    assert all(
        item["executed"] is False
        and item["network_activity"] is False
        and item["payload_generated"] is False
        and item["subprocess_started"] is False
        for item in payload["hypotheses"]
    )
    assert "secret" not in json.dumps(payload).lower() or (
        "secret candidates" in json.dumps(payload).lower()
    )

    events = database.list_audit_events(execution_id)
    assert any(
        event.event_type is AuditEventType.TOOL_PREPARED
        and event.details.get("phase_code") == "6A"
        for event in events
    )
    assert any(
        event.event_type is AuditEventType.TOOL_COMPLETED
        and event.details.get("phase_code") == "6A"
        for event in events
    )


def test_identical_hypothesis_set_reuses_evidence(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    add_source_evidence(database, execution_id)
    request = make_request(execution_id)

    first = create_tracked_attack_hypotheses(
        database,
        request,
        evidence_root=tmp_path / "evidence",
    )
    second = create_tracked_attack_hypotheses(
        database,
        request,
        evidence_root=tmp_path / "evidence",
    )

    assert second.reused_existing_evidence is True
    assert second.evidence.evidence_id == first.evidence.evidence_id
    assert len(
        database.list_evidence(
            execution_id,
            evidence_type=EvidenceType.ATTACK_HYPOTHESIS_SET,
        )
    ) == 1


def test_authorization_and_scope_are_required(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)

    with pytest.raises(InvalidStateTransitionError):
        create_tracked_attack_hypotheses(
            database,
            make_request(
                execution_id,
                target_url="https://outside.example/",
            ),
            evidence_root=tmp_path / "outside",
        )

    with pytest.raises(InvalidStateTransitionError):
        create_tracked_attack_hypotheses(
            database,
            make_request(
                execution_id,
                authorized=False,
            ),
            evidence_root=tmp_path / "request-denied",
        )


def test_empty_supported_evidence_persists_empty_safe_set(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)

    result = create_tracked_attack_hypotheses(
        database,
        make_request(execution_id),
        evidence_root=tmp_path / "evidence",
    )

    assert result.hypothesis_set.hypotheses == ()
    assert result.evidence.metadata["hypothesis_count"] == 0
    assert result.evidence.metadata["executed"] is False
    assert result.evidence.metadata["network_activity"] is False


def test_hypotheses_can_use_authorized_same_orchestration_sources(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    orchestration_id = "orchestration-phase6"
    target_execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Phase 6A Aggregate",
            asset_types=["web"],
            targets=["example.com"],
            authorization_confirmed=True,
            metadata={
                "orchestration_id": orchestration_id,
                "execution_role": "orchestration_child",
            },
        )
    )
    source_execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Phase 3 Evidence",
            asset_types=["web"],
            targets=["example.com"],
            authorization_confirmed=True,
            metadata={
                "orchestration_id": orchestration_id,
                "execution_role": "orchestration_child",
            },
        )
    )
    add_source_evidence(database, source_execution.execution_id)

    result = create_tracked_attack_hypotheses(
        database,
        make_request(target_execution.execution_id),
        evidence_root=tmp_path / "aggregate",
        source_execution_ids=(source_execution.execution_id,),
    )

    assert len(result.hypothesis_set.hypotheses) == 3
    assert len(result.hypothesis_set.considered_evidence_ids) == 2
