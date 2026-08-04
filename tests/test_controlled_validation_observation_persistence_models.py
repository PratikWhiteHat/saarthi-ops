"""Persistence-model tests for Phase 6F3 observation evidence."""

from saarthi_ai.persistence.models import EvidenceType


def test_controlled_validation_observation_evidence_type_exists() -> None:
    assert (
        EvidenceType.CONTROLLED_VALIDATION_OBSERVATION.value
        == "controlled_validation_observation"
    )


def test_plan_and_observation_evidence_types_are_distinct() -> None:
    assert (
        EvidenceType.CONTROLLED_VALIDATION_PLAN
        is not EvidenceType.CONTROLLED_VALIDATION_OBSERVATION
    )
