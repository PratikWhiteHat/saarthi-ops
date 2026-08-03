"""Models used by the Phase 4D confirmation engine."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class ConfirmationStatus(StrEnum):
    """Evidence-based confirmation states."""

    UNCONFIRMED = "unconfirmed"
    SUPPORTED = "supported"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class ConfirmationCandidate(BaseModel):
    """One candidate security finding awaiting validation."""

    candidate_id: str = Field(min_length=1, max_length=200)
    execution_id: str = Field(min_length=1, max_length=200)
    title: str = Field(min_length=1, max_length=300)
    candidate_type: str = Field(min_length=1, max_length=100)
    expected_token_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
    )


class ConfirmationDecision(BaseModel):
    """Deterministic outcome produced from registered evidence."""

    candidate_id: str
    execution_id: str
    status: ConfirmationStatus
    reason: str
    supporting_evidence_ids: tuple[str, ...] = ()
    rejected_evidence_ids: tuple[str, ...] = ()
