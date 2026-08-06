"""Deterministic, non-executing Phase 6A hypothesis engine."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from urllib.parse import urlparse

from saarthi_ai.attack_hypothesis.models import (
    AttackHypothesis,
    AttackHypothesisConfidence,
    AttackHypothesisEvidence,
    AttackHypothesisFamily,
    AttackHypothesisGenerationRequest,
    AttackHypothesisRisk,
    AttackHypothesisSet,
    AttackHypothesisValidationMethod,
)

MIN_HYPOTHESES = 1
MAX_HYPOTHESES = 50


class AttackHypothesisGenerationError(ValueError):
    """Raised when a Phase 6A generation request is invalid."""


def _valid_target(target_url: str) -> bool:
    try:
        parsed = urlparse(target_url)
    except ValueError:
        return False

    return (
        parsed.scheme.lower() in {"http", "https"}
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
    )


def _target_host(target: str) -> str:
    parsed = urlparse(target)

    if parsed.hostname:
        return parsed.hostname.lower().rstrip(".")

    return target.lower().strip().rstrip(".")


def _matches_target(
    evidence: AttackHypothesisEvidence,
    target_url: str,
) -> bool:
    evidence_host = _target_host(evidence.target)
    target_host = _target_host(target_url)

    return (
        bool(evidence_host)
        and bool(target_host)
        and (
            evidence_host == target_host
            or evidence_host.endswith(f".{target_host}")
            or target_host.endswith(f".{evidence_host}")
        )
    )


def _hypothesis_id(
    execution_id: str,
    target_url: str,
    family: AttackHypothesisFamily,
    evidence_ids: tuple[str, ...],
) -> str:
    material = "\n".join(
        (
            execution_id,
            target_url,
            family.value,
            *evidence_ids,
        )
    ).encode("utf-8")
    return f"hypothesis-{hashlib.sha256(material).hexdigest()[:20]}"


def _build_hypothesis(
    request: AttackHypothesisGenerationRequest,
    *,
    family: AttackHypothesisFamily,
    title: str,
    rationale: str,
    preconditions: tuple[str, ...],
    validation_method: AttackHypothesisValidationMethod,
    expected_evidence: tuple[str, ...],
    confidence: AttackHypothesisConfidence,
    confidence_score: int,
    validation_risk: AttackHypothesisRisk,
    required_permissions: tuple[str, ...],
    evidence: Iterable[AttackHypothesisEvidence],
) -> AttackHypothesis:
    evidence_ids = tuple(
        sorted({item.evidence_id for item in evidence})
    )

    return AttackHypothesis(
        hypothesis_id=_hypothesis_id(
            request.execution_id,
            request.target_url,
            family,
            evidence_ids,
        ),
        family=family,
        title=title,
        target_url=request.target_url,
        rationale=rationale,
        preconditions=preconditions,
        validation_method=validation_method,
        expected_evidence=expected_evidence,
        confidence=confidence,
        confidence_score=confidence_score,
        validation_risk=validation_risk,
        required_permissions=required_permissions,
        supporting_evidence_ids=evidence_ids,
    )


def generate_attack_hypotheses(
    request: AttackHypothesisGenerationRequest,
    evidence: Iterable[AttackHypothesisEvidence],
) -> AttackHypothesisSet:
    """Generate bounded candidate paths from redacted evidence metadata."""

    if not request.execution_id.strip():
        raise AttackHypothesisGenerationError(
            "A persistent execution identifier is required."
        )

    if request.authorized is not True:
        raise AttackHypothesisGenerationError(
            "Confirmed authorization is required."
        )

    if not _valid_target(request.target_url):
        raise AttackHypothesisGenerationError(
            "Target must be an absolute HTTP or HTTPS URL without credentials."
        )

    if not MIN_HYPOTHESES <= request.max_hypotheses <= MAX_HYPOTHESES:
        raise AttackHypothesisGenerationError(
            "Hypothesis generation is limited to between "
            f"{MIN_HYPOTHESES} and {MAX_HYPOTHESES} candidates."
        )

    accepted: list[AttackHypothesisEvidence] = []
    rejected_ids: list[str] = []

    for item in evidence:
        if (
            not item.evidence_id.strip()
            or not item.evidence_type.strip()
            or not _matches_target(item, request.target_url)
        ):
            if item.evidence_id.strip():
                rejected_ids.append(item.evidence_id)
            continue

        accepted.append(item)

    accepted.sort(key=lambda item: item.evidence_id)
    hypotheses: list[AttackHypothesis] = []

    input_evidence = [
        item
        for item in accepted
        if (
            "parameterized_routes" in item.signals
            or "forms" in item.signals
            or "javascript_parameters" in item.signals
        )
    ]

    if input_evidence:
        hypotheses.append(
            _build_hypothesis(
                request,
                family=AttackHypothesisFamily.INJECTION,
                title="Parameterized input handling requires validation",
                rationale=(
                    "Reconnaissance evidence identifies forms or parameters. "
                    "This supports a candidate input-handling path but does "
                    "not establish exploitability."
                ),
                preconditions=(
                    "Referenced endpoint evidence remains in scope",
                    "Phase 6B policy permits the proposed validation",
                ),
                validation_method=(
                    AttackHypothesisValidationMethod.INPUT_HANDLING_OBSERVATION
                ),
                expected_evidence=(
                    "A bounded, repeatable response observation",
                    "No material state change",
                ),
                confidence=AttackHypothesisConfidence.MEDIUM,
                confidence_score=60,
                validation_risk=AttackHypothesisRisk.LOW,
                required_permissions=(
                    "authorization_confirmed",
                    "active_testing_allowed",
                    "explicit_approval",
                ),
                evidence=input_evidence,
            )
        )

    api_evidence = [
        item
        for item in accepted
        if (
            "api_endpoints" in item.signals
            or "javascript_parameters" in item.signals
            or "websocket_endpoints" in item.signals
        )
    ]

    if api_evidence:
        hypotheses.append(
            _build_hypothesis(
                request,
                family=AttackHypothesisFamily.API_BUSINESS_LOGIC,
                title="Discovered application interfaces require trust review",
                rationale=(
                    "JavaScript or crawl evidence identifies application "
                    "interfaces. Authorization and business-rule assumptions "
                    "remain unverified."
                ),
                preconditions=(
                    "Interface remains associated with the in-scope target",
                    "Any authenticated context is separately approved",
                ),
                validation_method=(
                    AttackHypothesisValidationMethod.EVIDENCE_REVIEW
                ),
                expected_evidence=(
                    "Documented interface and trust-boundary mapping",
                    "A separately approved validation plan if needed",
                ),
                confidence=AttackHypothesisConfidence.MEDIUM,
                confidence_score=55,
                validation_risk=AttackHypothesisRisk.MODERATE,
                required_permissions=(
                    "authorization_confirmed",
                    "explicit_approval",
                ),
                evidence=api_evidence,
            )
        )

    exposure_evidence = [
        item
        for item in accepted
        if "secret_candidates" in item.signals
    ]

    if exposure_evidence:
        hypotheses.append(
            _build_hypothesis(
                request,
                family=AttackHypothesisFamily.SENSITIVE_DATA_EXPOSURE,
                title="Redacted client-side secret candidates need review",
                rationale=(
                    "JavaScript intelligence reports redacted secret "
                    "candidates. Values are not copied into the hypothesis "
                    "and must not be treated as confirmed credentials."
                ),
                preconditions=(
                    "Only redacted metadata is reviewed",
                    "No candidate value is used for authentication",
                ),
                validation_method=(
                    AttackHypothesisValidationMethod.EVIDENCE_REVIEW
                ),
                expected_evidence=(
                    "A false-positive or exposure classification",
                    "No credential use or account access",
                ),
                confidence=AttackHypothesisConfidence.LOW,
                confidence_score=35,
                validation_risk=AttackHypothesisRisk.MANUAL_ONLY,
                required_permissions=(
                    "authorization_confirmed",
                    "manual_review",
                ),
                evidence=exposure_evidence,
            )
        )

    oast_evidence = [
        item
        for item in accepted
        if "correlated_oast_observation" in item.signals
    ]

    if oast_evidence:
        hypotheses.append(
            _build_hypothesis(
                request,
                family=AttackHypothesisFamily.SERVER_SIDE_REQUEST,
                title="Correlated out-of-band behavior requires path review",
                rationale=(
                    "A correlated OAST observation supports a server-side "
                    "interaction path. Impact and root cause remain subject "
                    "to the Phase 6B approval gate."
                ),
                preconditions=(
                    "Correlation evidence is intact and target-associated",
                    "No additional callback is initiated by Phase 6A",
                ),
                validation_method=(
                    AttackHypothesisValidationMethod.OAST_CORRELATION_REVIEW
                ),
                expected_evidence=(
                    "Correlation and originating evidence remain linked",
                    "Any further validation is separately approved",
                ),
                confidence=AttackHypothesisConfidence.HIGH,
                confidence_score=85,
                validation_risk=AttackHypothesisRisk.MODERATE,
                required_permissions=(
                    "authorization_confirmed",
                    "active_testing_allowed",
                    "explicit_approval",
                ),
                evidence=oast_evidence,
            )
        )

    hypotheses.sort(
        key=lambda item: (
            -item.confidence_score,
            item.family.value,
            item.hypothesis_id,
        )
    )
    truncated = len(hypotheses) > request.max_hypotheses
    hypotheses = hypotheses[: request.max_hypotheses]

    return AttackHypothesisSet(
        execution_id=request.execution_id,
        target_url=request.target_url,
        hypotheses=tuple(hypotheses),
        considered_evidence_ids=tuple(
            item.evidence_id for item in accepted
        ),
        rejected_evidence_ids=tuple(sorted(set(rejected_ids))),
        truncated=truncated,
    )
