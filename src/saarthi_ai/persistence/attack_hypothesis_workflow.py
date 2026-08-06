"""Persistent, non-executing Phase 6A attack hypothesis workflow."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from saarthi_ai.attack_hypothesis import (
    AttackHypothesisEvidence,
    AttackHypothesisGenerationError,
    AttackHypothesisGenerationRequest,
    AttackHypothesisSet,
    generate_attack_hypotheses,
)
from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.http_intelligence_workflow import (
    _domain_in_execution_scope,
)
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceCreate,
    EvidenceRecord,
    EvidenceType,
    ExecutionRecord,
)

DEFAULT_EVIDENCE_ROOT = (
    Path("evidence") / "attack-hypothesis-sets"
)


class AttackHypothesisWorkflowError(RuntimeError):
    """Raised when Phase 6A hypotheses cannot be persisted safely."""


class TrackedAttackHypothesisSet:
    """Persisted Phase 6A output and execution context."""

    def __init__(
        self,
        *,
        execution: ExecutionRecord,
        hypothesis_set: AttackHypothesisSet,
        evidence: EvidenceRecord,
        reused_existing_evidence: bool,
    ) -> None:
        self.execution = execution
        self.hypothesis_set = hypothesis_set
        self.evidence = evidence
        self.reused_existing_evidence = reused_existing_evidence


def _validate_target_scope(
    target_url: str,
    execution: ExecutionRecord,
) -> None:
    parsed = urlparse(target_url)
    hostname = parsed.hostname

    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise InvalidStateTransitionError(
            "A valid HTTP or HTTPS target URL without credentials is required."
        )

    if not _domain_in_execution_scope(hostname, execution):
        raise InvalidStateTransitionError(
            f"Target '{hostname}' is not associated with this execution."
        )


def _safe_count(metadata: dict[str, Any], key: str) -> int:
    value = metadata.get(key)

    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
    ):
        return value

    return 0


def _evidence_target(
    evidence: EvidenceRecord,
) -> str:
    metadata = evidence.metadata

    for key in ("target_url", "domain", "target"):
        value = metadata.get(key)

        if isinstance(value, str) and value.strip():
            return value.strip()

    return ""


def _adapt_evidence(
    evidence_records: list[EvidenceRecord],
) -> list[AttackHypothesisEvidence]:
    adapted: list[AttackHypothesisEvidence] = []

    for evidence in evidence_records:
        metadata = evidence.metadata
        signals: set[str] = set()
        counts: list[tuple[str, int]] = []

        if evidence.evidence_type is EvidenceType.CRAWL_RESULT:
            parameter_count = _safe_count(
                metadata,
                "parameter_count",
            )
            form_count = _safe_count(metadata, "form_count")

            if parameter_count > 0:
                signals.add("parameterized_routes")
            if form_count > 0:
                signals.add("forms")

            counts.extend(
                (
                    ("parameter_count", parameter_count),
                    ("form_count", form_count),
                )
            )

        elif (
            evidence.evidence_type
            is EvidenceType.JAVASCRIPT_INTELLIGENCE_RESULT
        ):
            endpoint_count = _safe_count(
                metadata,
                "endpoint_count",
            )
            parameter_count = _safe_count(
                metadata,
                "parameter_count",
            )
            websocket_count = _safe_count(
                metadata,
                "websocket_count",
            )
            secret_candidate_count = _safe_count(
                metadata,
                "secret_candidate_count",
            )

            if endpoint_count > 0:
                signals.add("api_endpoints")
            if parameter_count > 0:
                signals.add("javascript_parameters")
            if websocket_count > 0:
                signals.add("websocket_endpoints")
            if secret_candidate_count > 0:
                signals.add("secret_candidates")

            counts.extend(
                (
                    ("endpoint_count", endpoint_count),
                    ("parameter_count", parameter_count),
                    ("websocket_count", websocket_count),
                    (
                        "secret_candidate_count",
                        secret_candidate_count,
                    ),
                )
            )

        elif evidence.evidence_type is EvidenceType.OAST_OBSERVATION:
            signals.add("correlated_oast_observation")

        else:
            continue

        adapted.append(
            AttackHypothesisEvidence(
                evidence_id=evidence.evidence_id,
                evidence_type=evidence.evidence_type.value,
                target=_evidence_target(evidence),
                signals=frozenset(signals),
                counts=tuple(counts),
            )
        )

    return adapted


def _serialize_hypothesis_set(
    request: AttackHypothesisGenerationRequest,
    hypothesis_set: AttackHypothesisSet,
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "phase": "6A",
        "evidence_type": EvidenceType.ATTACK_HYPOTHESIS_SET.value,
        "created_at": datetime.now(UTC).isoformat(),
        "request": {
            "execution_id": request.execution_id,
            "target_url": request.target_url,
            "authorized": request.authorized,
            "max_hypotheses": request.max_hypotheses,
        },
        "summary": {
            "hypothesis_count": len(hypothesis_set.hypotheses),
            "considered_evidence_ids": list(
                hypothesis_set.considered_evidence_ids
            ),
            "rejected_evidence_ids": list(
                hypothesis_set.rejected_evidence_ids
            ),
            "truncated": hypothesis_set.truncated,
        },
        "hypotheses": [
            {
                "hypothesis_id": item.hypothesis_id,
                "family": item.family.value,
                "title": item.title,
                "target_url": item.target_url,
                "rationale": item.rationale,
                "preconditions": list(item.preconditions),
                "validation_method": (
                    item.validation_method.value
                ),
                "expected_evidence": list(
                    item.expected_evidence
                ),
                "confidence": item.confidence.value,
                "confidence_score": item.confidence_score,
                "validation_risk": item.validation_risk.value,
                "required_permissions": list(
                    item.required_permissions
                ),
                "supporting_evidence_ids": list(
                    item.supporting_evidence_ids
                ),
                "executed": item.executed,
                "network_activity": item.network_activity,
                "payload_generated": item.payload_generated,
                "subprocess_started": item.subprocess_started,
            }
            for item in hypothesis_set.hypotheses
        ],
        "execution": {
            "executed": False,
            "network_activity": False,
            "payload_generated": False,
            "subprocess_started": False,
        },
    }


def _write_evidence_atomically(
    payload: dict[str, object],
    *,
    evidence_root: Path | None = None,
) -> tuple[str, str, int]:
    directory = evidence_root or DEFAULT_EVIDENCE_ROOT
    directory.mkdir(parents=True, exist_ok=True)

    evidence_id = f"attack-hypothesis-set-{uuid4()}"
    evidence_path = directory / f"{evidence_id}.json"
    serialized = json.dumps(
        payload,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")
    temporary_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=directory,
            prefix=".attack-hypothesis-",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_file.write(serialized)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
            temporary_path = Path(temporary_file.name)

        os.replace(temporary_path, evidence_path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()

    return (
        str(evidence_path),
        hashlib.sha256(serialized).hexdigest(),
        len(serialized),
    )


def _find_matching_evidence(
    database: SaarthiDatabase,
    request: AttackHypothesisGenerationRequest,
    hypothesis_set: AttackHypothesisSet,
) -> EvidenceRecord | None:
    hypothesis_ids = [
        item.hypothesis_id
        for item in hypothesis_set.hypotheses
    ]
    considered_ids = list(
        hypothesis_set.considered_evidence_ids
    )

    for evidence in database.list_evidence(
        request.execution_id,
        evidence_type=EvidenceType.ATTACK_HYPOTHESIS_SET,
    ):
        metadata = evidence.metadata

        if (
            metadata.get("target_url") == request.target_url
            and metadata.get("hypothesis_ids") == hypothesis_ids
            and metadata.get("considered_evidence_ids")
            == considered_ids
            and metadata.get("executed") is False
            and metadata.get("network_activity") is False
        ):
            return evidence

    return None


def create_tracked_attack_hypotheses(
    database: SaarthiDatabase,
    request: AttackHypothesisGenerationRequest,
    *,
    actor: str = "attack-hypothesis-engine",
    evidence_root: Path | None = None,
    source_execution_ids: tuple[str, ...] = (),
) -> TrackedAttackHypothesisSet:
    """Generate and persist one non-executed Phase 6A hypothesis set."""

    execution = database.get_execution(request.execution_id)

    if not execution.authorization_confirmed:
        raise InvalidStateTransitionError(
            "Execution does not have confirmed authorization."
        )

    if request.authorized is not True:
        raise InvalidStateTransitionError(
            "Hypothesis request does not confirm authorization."
        )

    _validate_target_scope(request.target_url, execution)
    evidence_records = database.list_evidence(request.execution_id)
    orchestration_id = execution.metadata.get("orchestration_id")

    for source_execution_id in dict.fromkeys(source_execution_ids):
        source = database.get_execution(source_execution_id)
        if not source.authorization_confirmed:
            raise InvalidStateTransitionError(
                "Hypothesis source execution is not authorized."
            )
        if (
            not isinstance(orchestration_id, str)
            or not orchestration_id
            or source.metadata.get("orchestration_id")
            != orchestration_id
        ):
            raise InvalidStateTransitionError(
                "Hypothesis source execution is outside this orchestration."
            )
        evidence_records.extend(
            database.list_evidence(source_execution_id)
        )

    try:
        hypothesis_set = generate_attack_hypotheses(
            request,
            _adapt_evidence(evidence_records),
        )
    except AttackHypothesisGenerationError as exc:
        raise AttackHypothesisWorkflowError(str(exc)) from exc

    existing_evidence = _find_matching_evidence(
        database,
        request,
        hypothesis_set,
    )

    if existing_evidence is not None:
        database.add_audit_event(
            request.execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message=(
                "[6A][attack-hypothesis] Existing hypothesis set reused."
            ),
            details={
                "phase_code": "6A",
                "evidence_id": existing_evidence.evidence_id,
                "hypothesis_count": len(
                    hypothesis_set.hypotheses
                ),
                "idempotent_reuse": True,
                "executed": False,
                "network_activity": False,
            },
        )

        return TrackedAttackHypothesisSet(
            execution=execution,
            hypothesis_set=hypothesis_set,
            evidence=existing_evidence,
            reused_existing_evidence=True,
        )

    database.add_audit_event(
        request.execution_id,
        event_type=AuditEventType.TOOL_PREPARED,
        actor=actor,
        message=(
            "[6A][attack-hypothesis] Evidence metadata prepared "
            "for deterministic hypothesis generation."
        ),
        details={
            "phase_code": "6A",
            "tool": "saarthi-attack-hypothesis-engine",
            "considered_evidence_count": len(
                hypothesis_set.considered_evidence_ids
            ),
            "hypothesis_count": len(
                hypothesis_set.hypotheses
            ),
            "executed": False,
            "network_activity": False,
            "payload_generated": False,
            "subprocess_started": False,
        },
    )

    payload = _serialize_hypothesis_set(
        request,
        hypothesis_set,
    )
    evidence_path: str | None = None
    evidence_registered = False

    try:
        evidence_path, evidence_sha256, evidence_size = (
            _write_evidence_atomically(
                payload,
                evidence_root=evidence_root,
            )
        )

        hypothesis_ids = [
            item.hypothesis_id
            for item in hypothesis_set.hypotheses
        ]
        families = sorted(
            {item.family.value for item in hypothesis_set.hypotheses}
        )

        evidence = database.add_evidence(
            request.execution_id,
            EvidenceCreate(
                evidence_type=EvidenceType.ATTACK_HYPOTHESIS_SET,
                source="saarthi-attack-hypothesis-engine",
                path=evidence_path,
                sha256=evidence_sha256,
                size_bytes=evidence_size,
                content_type="application/json",
                step_id="attack-hypothesis-generation-001",
                tool_name="saarthi-attack-hypothesis-engine",
                metadata={
                    "phase": "6A",
                    "target_url": request.target_url,
                    "hypothesis_count": len(hypothesis_ids),
                    "hypothesis_ids": hypothesis_ids,
                    "families": families,
                    "considered_evidence_ids": list(
                        hypothesis_set.considered_evidence_ids
                    ),
                    "rejected_evidence_ids": list(
                        hypothesis_set.rejected_evidence_ids
                    ),
                    "truncated": hypothesis_set.truncated,
                    "executed": False,
                    "network_activity": False,
                    "payload_generated": False,
                    "subprocess_started": False,
                },
            ),
            actor=actor,
        )
        evidence_registered = True
    except (OSError, RuntimeError, ValueError) as exc:
        if evidence_path is not None and not evidence_registered:
            try:
                Path(evidence_path).unlink(missing_ok=True)
            except OSError:
                pass

        database.add_audit_event(
            request.execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message=(
                "[6A][attack-hypothesis] Hypothesis persistence "
                "failed safely."
            ),
            details={
                "phase_code": "6A",
                "error_type": type(exc).__name__,
                "evidence_registered": False,
                "executed": False,
                "network_activity": False,
                "orphan_file_removed": (
                    evidence_path is not None
                    and not Path(evidence_path).exists()
                ),
            },
        )
        raise AttackHypothesisWorkflowError(
            "Attack hypotheses could not be persisted safely."
        ) from exc

    database.add_audit_event(
        request.execution_id,
        event_type=AuditEventType.TOOL_COMPLETED,
        actor=actor,
        message=(
            "[6A][attack-hypothesis] Evidence-backed hypothesis "
            "set persisted."
        ),
        details={
            "phase_code": "6A",
            "evidence_id": evidence.evidence_id,
            "evidence_sha256": evidence.sha256,
            "hypothesis_count": len(
                hypothesis_set.hypotheses
            ),
            "executed": False,
            "network_activity": False,
            "payload_generated": False,
            "subprocess_started": False,
        },
    )

    return TrackedAttackHypothesisSet(
        execution=execution,
        hypothesis_set=hypothesis_set,
        evidence=evidence,
        reused_existing_evidence=False,
    )
