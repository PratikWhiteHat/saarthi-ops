"""Domain models for Phase 6A attack hypothesis and path generation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AttackHypothesisFamily(StrEnum):
    """Official Phase 6 validator-family routing categories."""

    INJECTION = "injection"
    BROWSER_SIDE = "browser_side"
    SERVER_SIDE_REQUEST = "server_side_request"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    FILE_EXECUTION = "file_execution"
    API_BUSINESS_LOGIC = "api_business_logic"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"


class AttackHypothesisConfidence(StrEnum):
    """Evidence-strength classification for one candidate hypothesis."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AttackHypothesisRisk(StrEnum):
    """Required validation risk, not confirmed vulnerability severity."""

    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    MANUAL_ONLY = "manual_only"


class AttackHypothesisValidationMethod(StrEnum):
    """Non-payload description of the recommended next validation method."""

    RESPONSE_DIFFERENTIAL = "response_differential"
    INPUT_HANDLING_OBSERVATION = "input_handling_observation"
    OAST_CORRELATION_REVIEW = "oast_correlation_review"
    EVIDENCE_REVIEW = "evidence_review"


@dataclass(frozen=True)
class AttackHypothesisEvidence:
    """Redacted metadata signals from one persisted evidence record."""

    evidence_id: str
    evidence_type: str
    target: str
    signals: frozenset[str] = frozenset()
    counts: tuple[tuple[str, int], ...] = ()

    def count(self, name: str) -> int:
        """Return one non-negative signal count or zero."""

        return next(
            (
                value
                for key, value in self.counts
                if key == name and value >= 0
            ),
            0,
        )


@dataclass(frozen=True)
class AttackHypothesisGenerationRequest:
    """Bounded, non-executing Phase 6A generation request."""

    execution_id: str
    target_url: str
    authorized: bool
    max_hypotheses: int = 20


@dataclass(frozen=True)
class AttackHypothesis:
    """One evidence-backed candidate attack path."""

    hypothesis_id: str
    family: AttackHypothesisFamily
    title: str
    target_url: str
    rationale: str
    preconditions: tuple[str, ...]
    validation_method: AttackHypothesisValidationMethod
    expected_evidence: tuple[str, ...]
    confidence: AttackHypothesisConfidence
    confidence_score: int
    validation_risk: AttackHypothesisRisk
    required_permissions: tuple[str, ...]
    supporting_evidence_ids: tuple[str, ...]
    executed: bool = False
    network_activity: bool = False
    payload_generated: bool = False
    subprocess_started: bool = False


@dataclass(frozen=True)
class AttackHypothesisSet:
    """Deterministic Phase 6A output for one target."""

    execution_id: str
    target_url: str
    hypotheses: tuple[AttackHypothesis, ...]
    considered_evidence_ids: tuple[str, ...]
    rejected_evidence_ids: tuple[str, ...]
    truncated: bool
