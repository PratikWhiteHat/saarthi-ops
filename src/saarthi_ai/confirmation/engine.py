"""Deterministic Phase 4D evidence evaluation."""

from __future__ import annotations

from collections.abc import Iterable

from saarthi_ai.confirmation.models import (
    ConfirmationCandidate,
    ConfirmationDecision,
    ConfirmationStatus,
)
from saarthi_ai.persistence.models import (
    EvidenceRecord,
    EvidenceType,
)


def evaluate_confirmation(
    candidate: ConfirmationCandidate,
    evidence_records: Iterable[EvidenceRecord],
) -> ConfirmationDecision:
    """Evaluate one candidate without inferring unsupported exploitability."""

    relevant_evidence = tuple(
        evidence
        for evidence in evidence_records
        if evidence.execution_id == candidate.execution_id
    )

    rejected = tuple(
        evidence
        for evidence in relevant_evidence
        if _explicitly_rejects_candidate(evidence, candidate)
    )

    if rejected:
        return ConfirmationDecision(
            candidate_id=candidate.candidate_id,
            execution_id=candidate.execution_id,
            status=ConfirmationStatus.REJECTED,
            reason=(
                "Explicit validation evidence rejected this candidate."
            ),
            rejected_evidence_ids=tuple(
                evidence.evidence_id for evidence in rejected
            ),
        )

    matched_oast = tuple(
        evidence
        for evidence in relevant_evidence
        if _is_confirming_oast_observation(evidence, candidate)
    )

    if matched_oast:
        return ConfirmationDecision(
            candidate_id=candidate.candidate_id,
            execution_id=candidate.execution_id,
            status=ConfirmationStatus.CONFIRMED,
            reason=(
                "A correlated OAST observation explicitly confirmed "
                "the candidate."
            ),
            supporting_evidence_ids=tuple(
                evidence.evidence_id for evidence in matched_oast
            ),
        )

    partial_oast = tuple(
        evidence
        for evidence in relevant_evidence
        if _is_partial_oast_support(evidence, candidate)
    )

    if partial_oast:
        return ConfirmationDecision(
            candidate_id=candidate.candidate_id,
            execution_id=candidate.execution_id,
            status=ConfirmationStatus.SUPPORTED,
            reason=(
                "Related OAST evidence exists, but it does not contain "
                "all fields required for confirmation."
            ),
            supporting_evidence_ids=tuple(
                evidence.evidence_id for evidence in partial_oast
            ),
        )

    return ConfirmationDecision(
        candidate_id=candidate.candidate_id,
        execution_id=candidate.execution_id,
        status=ConfirmationStatus.UNCONFIRMED,
        reason=(
            "No explicit evidence confirms or rejects this candidate."
        ),
    )


def _explicitly_rejects_candidate(
    evidence: EvidenceRecord,
    candidate: ConfirmationCandidate,
) -> bool:
    metadata = evidence.metadata

    return (
        metadata.get("candidate_id") == candidate.candidate_id
        and metadata.get("validation_outcome") == "rejected"
    )


def _is_confirming_oast_observation(
    evidence: EvidenceRecord,
    candidate: ConfirmationCandidate,
) -> bool:
    if candidate.expected_token_id is None:
        return False

    if evidence.evidence_type is not EvidenceType.OAST_OBSERVATION:
        return False

    metadata = evidence.metadata

    return (
        metadata.get("token_id") == candidate.expected_token_id
        and metadata.get("status") == "observed"
        and bool(metadata.get("observation_id"))
        and metadata.get("request_path")
        == "/v1/oast/callback/[REDACTED]"
    )


def _is_partial_oast_support(
    evidence: EvidenceRecord,
    candidate: ConfirmationCandidate,
) -> bool:
    if candidate.expected_token_id is None:
        return False

    if evidence.evidence_type is not EvidenceType.OAST_OBSERVATION:
        return False

    return evidence.metadata.get(
        "token_id"
    ) == candidate.expected_token_id
