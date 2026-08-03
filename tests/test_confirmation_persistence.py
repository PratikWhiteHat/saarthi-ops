from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from saarthi_ai.confirmation.models import (
    ConfirmationCandidate,
    ConfirmationStatus,
)
from saarthi_ai.persistence.confirmation_workflow import (
    run_confirmation_workflow,
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
    repository = SaarthiDatabase(tmp_path / "confirmation.db")
    repository.initialize()
    return repository


def create_execution(
    database: SaarthiDatabase,
    *,
    authorized: bool = True,
) -> str:
    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Phase 4D Confirmation",
            asset_types=["web"],
            targets=["example.com"],
            authorization_confirmed=authorized,
            active_testing_allowed=True,
            intrusive_testing_allowed=False,
        )
    )

    return execution.execution_id


def create_oast_evidence(
    database: SaarthiDatabase,
    execution_id: str,
):
    return database.add_evidence(
        execution_id,
        EvidenceCreate(
            evidence_type=EvidenceType.OAST_OBSERVATION,
            source="test-oast",
            path="evidence/oast.json",
            sha256="a" * 64,
            size_bytes=100,
            content_type="application/json",
            metadata={
                "observation_id": "observation-001",
                "token_id": "blind-token-001",
                "status": "observed",
                "request_path": "/v1/oast/callback/[REDACTED]",
            },
        ),
        actor="test",
    )


def make_candidate(
    execution_id: str,
) -> ConfirmationCandidate:
    return ConfirmationCandidate(
        candidate_id="candidate-001",
        execution_id=execution_id,
        title="Potential blind server-side interaction",
        candidate_type="blind-interaction",
        expected_token_id="blind-token-001",
    )


def test_confirmed_decision_is_persisted_with_finding_event(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    supporting = create_oast_evidence(database, execution_id)

    decision, evidence = run_confirmation_workflow(
        database,
        make_candidate(execution_id),
        [supporting],
        evidence_root=tmp_path / "confirmation-evidence",
    )

    assert decision.status is ConfirmationStatus.CONFIRMED
    assert evidence.evidence_type is EvidenceType.CONFIRMATION_RESULT
    assert evidence.metadata["status"] == "confirmed"
    assert evidence.metadata["supporting_evidence_ids"] == [
        supporting.evidence_id
    ]

    evidence_path = Path(evidence.path)
    payload_bytes = evidence_path.read_bytes()
    payload = json.loads(payload_bytes)

    assert hashlib.sha256(payload_bytes).hexdigest() == evidence.sha256
    assert payload["phase"] == "4D"
    assert payload["decision"]["status"] == "confirmed"
    assert payload["candidate"]["candidate_id"] == "candidate-001"

    events = database.list_audit_events(execution_id)

    assert any(
        event.event_type is AuditEventType.FINDING_CREATED
        for event in events
    )


def test_unconfirmed_decision_does_not_create_finding_event(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)

    decision, evidence = run_confirmation_workflow(
        database,
        make_candidate(execution_id),
        [],
        evidence_root=tmp_path / "confirmation-evidence",
    )

    assert decision.status is ConfirmationStatus.UNCONFIRMED
    assert evidence.metadata["status"] == "unconfirmed"

    events = database.list_audit_events(execution_id)

    assert not any(
        event.event_type is AuditEventType.FINDING_CREATED
        for event in events
    )


def test_supported_decision_does_not_create_finding_event(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)

    partial = database.add_evidence(
        execution_id,
        EvidenceCreate(
            evidence_type=EvidenceType.OAST_OBSERVATION,
            source="test-oast",
            path="evidence/partial.json",
            metadata={
                "token_id": "blind-token-001",
                "status": "registered",
            },
        ),
        actor="test",
    )

    decision, _ = run_confirmation_workflow(
        database,
        make_candidate(execution_id),
        [partial],
        evidence_root=tmp_path / "confirmation-evidence",
    )

    assert decision.status is ConfirmationStatus.SUPPORTED

    events = database.list_audit_events(execution_id)

    assert not any(
        event.event_type is AuditEventType.FINDING_CREATED
        for event in events
    )


def test_confirmation_requires_authorized_execution(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)

    with database.connect() as connection:
        connection.execute(
            """
            UPDATE executions
            SET authorization_confirmed = 0
            WHERE execution_id = ?
            """,
            (execution_id,),
        )

    with pytest.raises(
        InvalidStateTransitionError,
        match="confirmed authorization",
    ):
        run_confirmation_workflow(
            database,
            make_candidate(execution_id),
            [],
            evidence_root=tmp_path,
        )


def test_confirmation_evidence_contains_no_raw_callback_token(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)
    supporting = create_oast_evidence(database, execution_id)

    raw_token = "raw-callback-token-must-not-be-persisted"

    _, evidence = run_confirmation_workflow(
        database,
        make_candidate(execution_id),
        [supporting],
        evidence_root=tmp_path / "confirmation-evidence",
    )

    rendered = Path(evidence.path).read_text(encoding="utf-8")
    metadata_rendered = json.dumps(evidence.metadata)

    assert raw_token not in rendered
    assert raw_token not in metadata_rendered


def test_rejected_decision_does_not_create_finding_event(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = create_execution(database)

    rejecting = database.add_evidence(
        execution_id,
        EvidenceCreate(
            evidence_type=EvidenceType.NOTE,
            source="manual-validation",
            path="evidence/rejection-note.json",
            metadata={
                "candidate_id": "candidate-001",
                "validation_outcome": "rejected",
            },
        ),
        actor="test",
    )

    decision, evidence = run_confirmation_workflow(
        database,
        make_candidate(execution_id),
        [rejecting],
        evidence_root=tmp_path / "confirmation-evidence",
    )

    assert decision.status is ConfirmationStatus.REJECTED
    assert evidence.metadata["status"] == "rejected"
    assert evidence.metadata["rejected_evidence_ids"] == [
        rejecting.evidence_id
    ]

    events = database.list_audit_events(execution_id)

    assert not any(
        event.event_type is AuditEventType.FINDING_CREATED
        for event in events
    )
