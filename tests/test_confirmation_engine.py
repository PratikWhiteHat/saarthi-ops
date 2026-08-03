from __future__ import annotations

from datetime import UTC, datetime

from saarthi_ai.confirmation.engine import evaluate_confirmation
from saarthi_ai.confirmation.models import (
    ConfirmationCandidate,
    ConfirmationStatus,
)
from saarthi_ai.persistence.models import (
    EvidenceRecord,
    EvidenceType,
)


def make_candidate() -> ConfirmationCandidate:
    return ConfirmationCandidate(
        candidate_id="candidate-001",
        execution_id="execution-001",
        title="Potential blind server-side interaction",
        candidate_type="blind-interaction",
        expected_token_id="blind-token-001",
    )


def make_evidence(
    *,
    evidence_id: str = "evidence-001",
    execution_id: str = "execution-001",
    evidence_type: EvidenceType = EvidenceType.OAST_OBSERVATION,
    metadata: dict[str, object] | None = None,
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=evidence_id,
        execution_id=execution_id,
        evidence_type=evidence_type,
        source="test",
        path="evidence/test.json",
        sha256="a" * 64,
        size_bytes=100,
        content_type="application/json",
        step_id="test-step",
        tool_name="test-tool",
        metadata=metadata or {},
        created_at=datetime(2026, 8, 3, 10, 0, tzinfo=UTC),
    )


def test_candidate_without_evidence_is_unconfirmed() -> None:
    decision = evaluate_confirmation(
        make_candidate(),
        [],
    )

    assert decision.status is ConfirmationStatus.UNCONFIRMED
    assert decision.supporting_evidence_ids == ()


def test_matching_observed_oast_evidence_confirms_candidate() -> None:
    evidence = make_evidence(
        metadata={
            "observation_id": "observation-001",
            "token_id": "blind-token-001",
            "status": "observed",
            "request_path": "/v1/oast/callback/[REDACTED]",
        }
    )

    decision = evaluate_confirmation(
        make_candidate(),
        [evidence],
    )

    assert decision.status is ConfirmationStatus.CONFIRMED
    assert decision.supporting_evidence_ids == (
        evidence.evidence_id,
    )


def test_incomplete_matching_oast_evidence_only_supports() -> None:
    evidence = make_evidence(
        metadata={
            "token_id": "blind-token-001",
            "status": "registered",
        }
    )

    decision = evaluate_confirmation(
        make_candidate(),
        [evidence],
    )

    assert decision.status is ConfirmationStatus.SUPPORTED


def test_different_token_does_not_support_candidate() -> None:
    evidence = make_evidence(
        metadata={
            "observation_id": "observation-001",
            "token_id": "blind-token-different",
            "status": "observed",
            "request_path": "/v1/oast/callback/[REDACTED]",
        }
    )

    decision = evaluate_confirmation(
        make_candidate(),
        [evidence],
    )

    assert decision.status is ConfirmationStatus.UNCONFIRMED


def test_evidence_from_another_execution_is_ignored() -> None:
    evidence = make_evidence(
        execution_id="execution-different",
        metadata={
            "observation_id": "observation-001",
            "token_id": "blind-token-001",
            "status": "observed",
            "request_path": "/v1/oast/callback/[REDACTED]",
        },
    )

    decision = evaluate_confirmation(
        make_candidate(),
        [evidence],
    )

    assert decision.status is ConfirmationStatus.UNCONFIRMED


def test_explicit_rejection_takes_precedence() -> None:
    confirming = make_evidence(
        evidence_id="evidence-confirming",
        metadata={
            "observation_id": "observation-001",
            "token_id": "blind-token-001",
            "status": "observed",
            "request_path": "/v1/oast/callback/[REDACTED]",
        },
    )

    rejecting = make_evidence(
        evidence_id="evidence-rejecting",
        evidence_type=EvidenceType.NOTE,
        metadata={
            "candidate_id": "candidate-001",
            "validation_outcome": "rejected",
        },
    )

    decision = evaluate_confirmation(
        make_candidate(),
        [confirming, rejecting],
    )

    assert decision.status is ConfirmationStatus.REJECTED
    assert decision.rejected_evidence_ids == (
        rejecting.evidence_id,
    )


def test_missing_headers_do_not_confirm_exploitability() -> None:
    evidence = make_evidence(
        evidence_type=EvidenceType.DIRECT_CHECK_RESULT,
        metadata={
            "finding_type": "missing-security-header",
            "severity": "medium",
        },
    )

    decision = evaluate_confirmation(
        make_candidate(),
        [evidence],
    )

    assert decision.status is ConfirmationStatus.UNCONFIRMED
