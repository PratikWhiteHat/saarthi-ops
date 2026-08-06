"""Tests for the non-executing Phase 6A hypothesis engine."""

from __future__ import annotations

import pytest

from saarthi_ai.attack_hypothesis import (
    AttackHypothesisConfidence,
    AttackHypothesisEvidence,
    AttackHypothesisFamily,
    AttackHypothesisGenerationError,
    AttackHypothesisGenerationRequest,
    AttackHypothesisRisk,
    generate_attack_hypotheses,
)


def request(**overrides: object) -> AttackHypothesisGenerationRequest:
    values: dict[str, object] = {
        "execution_id": "execution-test",
        "target_url": "https://example.com/",
        "authorized": True,
        "max_hypotheses": 20,
    }
    values.update(overrides)
    return AttackHypothesisGenerationRequest(
        **values,  # type: ignore[arg-type]
    )


def evidence(
    evidence_id: str,
    *,
    evidence_type: str = "crawl_result",
    target: str = "example.com",
    signals: frozenset[str] = frozenset(),
) -> AttackHypothesisEvidence:
    return AttackHypothesisEvidence(
        evidence_id=evidence_id,
        evidence_type=evidence_type,
        target=target,
        signals=signals,
    )


def test_parameterized_evidence_generates_bounded_injection_path() -> None:
    result = generate_attack_hypotheses(
        request(),
        [
            evidence(
                "evidence-crawl",
                signals=frozenset(
                    {"parameterized_routes", "forms"}
                ),
            ),
        ],
    )

    assert len(result.hypotheses) == 1
    hypothesis = result.hypotheses[0]

    assert hypothesis.family is AttackHypothesisFamily.INJECTION
    assert hypothesis.confidence is AttackHypothesisConfidence.MEDIUM
    assert hypothesis.validation_risk is AttackHypothesisRisk.LOW
    assert hypothesis.supporting_evidence_ids == ("evidence-crawl",)
    assert hypothesis.executed is False
    assert hypothesis.network_activity is False
    assert hypothesis.payload_generated is False
    assert hypothesis.subprocess_started is False


def test_multiple_signals_generate_deterministic_deduplicated_paths() -> None:
    items = [
        evidence(
            "evidence-js",
            evidence_type="javascript_intelligence_result",
            signals=frozenset(
                {
                    "api_endpoints",
                    "javascript_parameters",
                    "secret_candidates",
                }
            ),
        ),
        evidence(
            "evidence-crawl",
            signals=frozenset({"parameterized_routes"}),
        ),
    ]

    first = generate_attack_hypotheses(request(), items)
    second = generate_attack_hypotheses(
        request(),
        reversed(items),
    )

    assert first == second
    assert {
        item.family for item in first.hypotheses
    } == {
        AttackHypothesisFamily.INJECTION,
        AttackHypothesisFamily.API_BUSINESS_LOGIC,
        AttackHypothesisFamily.SENSITIVE_DATA_EXPOSURE,
    }
    assert len(
        {item.hypothesis_id for item in first.hypotheses}
    ) == 3


def test_oast_evidence_creates_high_confidence_review_path() -> None:
    result = generate_attack_hypotheses(
        request(),
        [
            evidence(
                "evidence-oast",
                evidence_type="oast_observation",
                signals=frozenset(
                    {"correlated_oast_observation"}
                ),
            ),
        ],
    )

    hypothesis = result.hypotheses[0]

    assert (
        hypothesis.family
        is AttackHypothesisFamily.SERVER_SIDE_REQUEST
    )
    assert hypothesis.confidence is AttackHypothesisConfidence.HIGH
    assert hypothesis.confidence_score == 85
    assert hypothesis.validation_risk is AttackHypothesisRisk.MODERATE


def test_out_of_scope_and_malformed_evidence_is_rejected() -> None:
    result = generate_attack_hypotheses(
        request(),
        [
            evidence(
                "evidence-other",
                target="other.example",
                signals=frozenset({"parameterized_routes"}),
            ),
            AttackHypothesisEvidence(
                evidence_id="evidence-empty-type",
                evidence_type="",
                target="example.com",
                signals=frozenset({"parameterized_routes"}),
            ),
        ],
    )

    assert result.hypotheses == ()
    assert result.considered_evidence_ids == ()
    assert result.rejected_evidence_ids == (
        "evidence-empty-type",
        "evidence-other",
    )


def test_empty_supported_evidence_produces_empty_safe_set() -> None:
    result = generate_attack_hypotheses(
        request(),
        [
            evidence(
                "evidence-http",
                evidence_type="http_intelligence_result",
            ),
        ],
    )

    assert result.hypotheses == ()
    assert result.considered_evidence_ids == ("evidence-http",)
    assert result.truncated is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"execution_id": " "},
        {"authorized": False},
        {"target_url": ""},
        {"target_url": "ftp://example.com/"},
        {"target_url": "https://user:password@example.com/"},
        {"max_hypotheses": 0},
        {"max_hypotheses": 51},
    ],
)
def test_invalid_requests_fail_closed(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(AttackHypothesisGenerationError):
        generate_attack_hypotheses(
            request(**overrides),
            [],
        )
