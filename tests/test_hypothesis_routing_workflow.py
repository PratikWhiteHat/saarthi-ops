"""Tests for the integrity-checked Phase 6A to 6B handoff."""

from __future__ import annotations

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
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.hypothesis_routing_workflow import (
    HypothesisRoutingRequest,
    HypothesisRoutingWorkflowError,
    route_hypothesis_to_controlled_validation,
)
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceCreate,
    EvidenceType,
    ExecutionCreate,
    ExecutionState,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "routing.db")
    repository.initialize()
    return repository


def create_source(database: SaarthiDatabase) -> str:
    return database.create_execution(
        ExecutionCreate(
            assessment_name="Phase 6 routing",
            asset_types=["web"],
            targets=["example.com"],
            authorization_confirmed=True,
            active_testing_allowed=True,
            metadata={
                "execution_role": "orchestration_child",
                "orchestration_id": "orchestration-test",
                "parent_execution_id": "execution-parent",
                "project_id": "project-test",
            },
        )
    ).execution_id


def add_recon_evidence(
    database: SaarthiDatabase,
    execution_id: str,
) -> None:
    database.add_evidence(
        execution_id,
        EvidenceCreate(
            evidence_type=EvidenceType.CRAWL_RESULT,
            source="test-crawl",
            path="/tmp/crawl.json",
            sha256="a" * 64,
            size_bytes=10,
            content_type="application/json",
            metadata={
                "domain": "example.com",
                "parameter_count": 3,
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
            source="test-js",
            path="/tmp/js.json",
            sha256="b" * 64,
            size_bytes=10,
            content_type="application/json",
            metadata={
                "domain": "example.com",
                "endpoint_count": 2,
                "parameter_count": 1,
                "secret_candidate_count": 1,
            },
        ),
    )


def generate_hypotheses(
    database: SaarthiDatabase,
    execution_id: str,
    tmp_path: Path,
):
    add_recon_evidence(database, execution_id)
    return create_tracked_attack_hypotheses(
        database,
        AttackHypothesisGenerationRequest(
            execution_id=execution_id,
            target_url="https://example.com/",
            authorized=True,
        ),
        evidence_root=tmp_path / "hypotheses",
    )


def route_request(
    execution_id: str,
    evidence_id: str,
    hypothesis_id: str,
    **overrides: object,
) -> HypothesisRoutingRequest:
    values: dict[str, object] = {
        "source_execution_id": execution_id,
        "hypothesis_evidence_id": evidence_id,
        "hypothesis_id": hypothesis_id,
        "explicitly_approved": True,
        "requested_requests": 2,
    }
    values.update(overrides)
    return HypothesisRoutingRequest(
        **values,  # type: ignore[arg-type]
    )


def test_low_risk_hypothesis_creates_linked_non_executing_plan(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    source_id = create_source(database)
    generated = generate_hypotheses(database, source_id, tmp_path)
    hypothesis = next(
        item
        for item in generated.hypothesis_set.hypotheses
        if item.family is AttackHypothesisFamily.INJECTION
    )

    result = route_hypothesis_to_controlled_validation(
        database,
        route_request(
            source_id,
            generated.evidence.evidence_id,
            hypothesis.hypothesis_id,
        ),
        evidence_root=tmp_path / "plans",
    )

    child = result.validation_execution
    assert child.execution_id != source_id
    assert child.state is ExecutionState.PLANNED
    assert child.metadata["phase_code"] == "6B"
    assert child.metadata["phase_name"] == "Policy & Approval Gate"
    assert child.metadata["execution_role"] == "orchestration_child"
    assert (
        child.metadata["workflow_role"]
        == "phase_6b_hypothesis_validation"
    )
    assert child.metadata["source_execution_id"] == source_id
    assert (
        child.metadata["source_hypothesis_evidence_id"]
        == generated.evidence.evidence_id
    )
    assert (
        child.metadata["source_hypothesis_id"]
        == hypothesis.hypothesis_id
    )
    assert child.metadata["previous_execution_id"] == source_id
    assert child.metadata["executed"] is False
    assert child.metadata["network_activity"] is False

    payload = json.loads(Path(result.plan.evidence.path).read_text())
    assert payload["phase"] == "6B"
    assert payload["request"]["source_execution_id"] == source_id
    assert (
        payload["request"]["source_hypothesis_evidence_id"]
        == generated.evidence.evidence_id
    )
    assert (
        payload["request"]["source_hypothesis_id"]
        == hypothesis.hypothesis_id
    )
    assert payload["execution"] == {
        "executed": False,
        "network_activity": False,
        "payload_sent": False,
        "subprocess_started": False,
    }

    source_events = database.list_audit_events(source_id)
    assert any(
        event.event_type is AuditEventType.APPROVAL_RECORDED
        and event.details.get("validation_execution_id")
        == child.execution_id
        for event in source_events
    )


def test_identical_route_reuses_validation_execution_and_plan(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    source_id = create_source(database)
    generated = generate_hypotheses(database, source_id, tmp_path)
    hypothesis = next(
        item
        for item in generated.hypothesis_set.hypotheses
        if item.family is AttackHypothesisFamily.INJECTION
    )
    request = route_request(
        source_id,
        generated.evidence.evidence_id,
        hypothesis.hypothesis_id,
    )

    first = route_hypothesis_to_controlled_validation(
        database,
        request,
        evidence_root=tmp_path / "plans",
    )
    second = route_hypothesis_to_controlled_validation(
        database,
        request,
        evidence_root=tmp_path / "plans",
    )

    assert second.reused_validation_execution is True
    assert (
        second.validation_execution.execution_id
        == first.validation_execution.execution_id
    )
    assert second.plan.evidence.evidence_id == first.plan.evidence.evidence_id


def test_tampered_hypothesis_evidence_fails_before_child_creation(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    source_id = create_source(database)
    generated = generate_hypotheses(database, source_id, tmp_path)
    hypothesis = generated.hypothesis_set.hypotheses[0]
    Path(generated.evidence.path).write_text("{}")
    before = len(database.list_executions())

    with pytest.raises(
        HypothesisRoutingWorkflowError,
        match="size verification failed",
    ):
        route_hypothesis_to_controlled_validation(
            database,
            route_request(
                source_id,
                generated.evidence.evidence_id,
                hypothesis.hypothesis_id,
            ),
            evidence_root=tmp_path / "plans",
        )

    assert len(database.list_executions()) == before


def test_manual_review_hypothesis_fails_closed(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    source_id = create_source(database)
    generated = generate_hypotheses(database, source_id, tmp_path)
    hypothesis = next(
        item
        for item in generated.hypothesis_set.hypotheses
        if item.family is AttackHypothesisFamily.SENSITIVE_DATA_EXPOSURE
    )

    with pytest.raises(
        HypothesisRoutingWorkflowError,
        match="requires manual review",
    ):
        route_hypothesis_to_controlled_validation(
            database,
            route_request(
                source_id,
                generated.evidence.evidence_id,
                hypothesis.hypothesis_id,
            ),
            evidence_root=tmp_path / "plans",
        )


def test_fresh_approval_and_active_testing_are_required(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    source_id = create_source(database)
    generated = generate_hypotheses(database, source_id, tmp_path)
    hypothesis = generated.hypothesis_set.hypotheses[0]

    with pytest.raises(
        HypothesisRoutingWorkflowError,
        match="Fresh explicit approval",
    ):
        route_hypothesis_to_controlled_validation(
            database,
            route_request(
                source_id,
                generated.evidence.evidence_id,
                hypothesis.hypothesis_id,
                explicitly_approved=False,
            ),
            evidence_root=tmp_path / "plans",
        )

    inactive = database.create_execution(
        ExecutionCreate(
            assessment_name="Inactive source",
            asset_types=["web"],
            targets=["example.com"],
            authorization_confirmed=True,
            active_testing_allowed=False,
        )
    ).execution_id
    inactive_generated = generate_hypotheses(
        database,
        inactive,
        tmp_path / "inactive",
    )

    with pytest.raises(
        HypothesisRoutingWorkflowError,
        match="does not permit active testing",
    ):
        route_hypothesis_to_controlled_validation(
            database,
            route_request(
                inactive,
                inactive_generated.evidence.evidence_id,
                inactive_generated.hypothesis_set.hypotheses[
                    0
                ].hypothesis_id,
            ),
            evidence_root=tmp_path / "inactive-plans",
        )
