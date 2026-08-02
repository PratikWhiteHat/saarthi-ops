"""Persistent Phase 3C HTTP intelligence workflow."""

from __future__ import annotations

from pathlib import Path

from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.http_workflow import (
    advance_execution_to_running,
    fail_execution_safely,
)
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceCreate,
    EvidenceRecord,
    EvidenceType,
    ExecutionRecord,
    ExecutionState,
)
from saarthi_ai.recon.http_intelligence_collector import (
    HttpIntelligenceCollectionError,
    collect_http_intelligence,
)
from saarthi_ai.recon.http_intelligence_models import (
    HttpIntelligenceCollectionResult,
)


class TrackedHttpIntelligenceResult:
    """Combined persistent Phase 3C workflow result."""

    def __init__(
        self,
        *,
        execution: ExecutionRecord,
        collection: HttpIntelligenceCollectionResult,
        evidence: EvidenceRecord,
    ) -> None:
        self.execution = execution
        self.collection = collection
        self.evidence = evidence


def _domain_in_execution_scope(
    domain: str,
    execution: ExecutionRecord,
) -> bool:
    """Check whether a domain belongs to the execution target scope."""

    normalized_domain = domain.strip().lower().rstrip(".")

    for target in execution.targets:
        normalized_target = target.strip().lower().rstrip("/.")

        if "://" in normalized_target:
            normalized_target = normalized_target.split("://", 1)[1]
            normalized_target = normalized_target.split("/", 1)[0]
            normalized_target = normalized_target.split(":", 1)[0]

        if normalized_target == normalized_domain:
            return True

        if normalized_target.endswith(f".{normalized_domain}"):
            return True

        if normalized_domain.endswith(f".{normalized_target}"):
            return True

    return False


def run_tracked_http_intelligence(
    database: SaarthiDatabase,
    execution_id: str,
    source_evidence_path: Path,
    *,
    actor: str = "http-intelligence-collector",
    evidence_root: Path | None = None,
) -> TrackedHttpIntelligenceResult:
    """Run Phase 3C collection with persistence and auditing."""

    execution = database.get_execution(execution_id)

    if not execution.authorization_confirmed:
        raise InvalidStateTransitionError(
            "Execution does not have confirmed authorization."
        )

    execution = advance_execution_to_running(
        database,
        execution,
        actor=actor,
    )

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_STARTED,
        actor=actor,
        message="ProjectDiscovery httpx intelligence collector started.",
        details={
            "tool": "projectdiscovery-httpx",
            "source_evidence_path": str(source_evidence_path),
            "mode": "active-low-risk",
        },
    )

    try:
        collection = collect_http_intelligence(
            source_evidence_path,
            evidence_root=evidence_root,
        )

        if not _domain_in_execution_scope(
            collection.domain,
            execution,
        ):
            raise InvalidStateTransitionError(
                f"Domain '{collection.domain}' is not associated with this execution."
            )

        evidence = database.add_evidence(
            execution_id,
            EvidenceCreate(
                evidence_type=EvidenceType.HTTP_INTELLIGENCE_RESULT,
                source="projectdiscovery-httpx",
                path=collection.evidence_path,
                sha256=collection.evidence_sha256,
                size_bytes=collection.evidence_size_bytes,
                content_type="application/json",
                step_id="recon-http-intelligence-001",
                tool_name="projectdiscovery-httpx",
                metadata={
                    "domain": collection.domain,
                    "input_count": collection.input_count,
                    "live_service_count": collection.live_service_count,
                    "malformed_line_count": collection.malformed_line_count,
                    "rejected_input_count": len(collection.rejected_inputs),
                    "rejected_result_count": len(collection.rejected_results),
                    "collector_execution_id": collection.collector_execution_id,
                    "collector_evidence_id": collection.collector_evidence_id,
                    "source_collector_execution_id": (
                        collection.source_collector_execution_id
                    ),
                    "source_collector_evidence_id": (
                        collection.source_collector_evidence_id
                    ),
                },
            ),
            actor=actor,
        )

        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message="ProjectDiscovery httpx intelligence collector completed.",
            details={
                "tool": "projectdiscovery-httpx",
                "domain": collection.domain,
                "live_service_count": collection.live_service_count,
                "evidence_id": evidence.evidence_id,
            },
        )

        execution = database.transition_execution(
            execution_id,
            ExecutionState.ANALYZING,
            actor=actor,
            reason="HTTP intelligence evidence is ready for analysis.",
        )

        execution = database.transition_execution(
            execution_id,
            ExecutionState.COMPLETED,
            actor=actor,
            reason="Phase 3C HTTP intelligence workflow completed.",
        )

        return TrackedHttpIntelligenceResult(
            execution=execution,
            collection=collection,
            evidence=evidence,
        )

    except (
        HttpIntelligenceCollectionError,
        InvalidStateTransitionError,
    ) as exc:
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message="ProjectDiscovery httpx intelligence collector failed.",
            details={
                "tool": "projectdiscovery-httpx",
                "error": str(exc),
            },
        )

        fail_execution_safely(
            database,
            execution_id,
            actor=actor,
            reason=str(exc),
        )

        raise
