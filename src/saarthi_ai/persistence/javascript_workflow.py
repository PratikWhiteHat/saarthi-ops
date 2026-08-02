"""Persistent Phase 3E JavaScript intelligence workflow."""

from __future__ import annotations

import asyncio
from pathlib import Path

from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.http_intelligence_workflow import (
    _domain_in_execution_scope,
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
from saarthi_ai.recon.javascript_collector import (
    JavaScriptCollectionError,
    collect_javascript_intelligence,
)
from saarthi_ai.recon.javascript_models import (
    JavaScriptCollectionResult,
)


class TrackedJavaScriptResult:
    """Combined persistent Phase 3E JavaScript workflow result."""

    def __init__(
        self,
        *,
        execution: ExecutionRecord,
        collection: JavaScriptCollectionResult,
        evidence: EvidenceRecord,
    ) -> None:
        self.execution = execution
        self.collection = collection
        self.evidence = evidence


def run_tracked_javascript_intelligence(
    database: SaarthiDatabase,
    execution_id: str,
    source_evidence_path: Path,
    *,
    actor: str = "javascript-intelligence-collector",
    evidence_root: Path | None = None,
) -> TrackedJavaScriptResult:
    """Run Phase 3E JavaScript intelligence with persistence and auditing."""

    execution = database.get_execution(execution_id)

    if not execution.authorization_confirmed:
        raise InvalidStateTransitionError("Execution does not have confirmed authorization.")

    if not execution.active_testing_allowed:
        raise InvalidStateTransitionError("Execution does not allow active testing.")

    execution = advance_execution_to_running(
        database,
        execution,
        actor=actor,
    )

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_STARTED,
        actor=actor,
        message="Saarthi JavaScript intelligence collector started.",
        details={
            "tool": "saarthi-javascript-intelligence",
            "source_evidence_path": str(source_evidence_path),
            "mode": "active-low-risk",
            "max_javascript_assets": 100,
            "max_body_bytes": 524_288,
            "fetch_concurrency": 3,
            "fetch_timeout_seconds": 10.0,
            "stores_full_javascript_source": False,
        },
    )

    try:
        collection = asyncio.run(
            collect_javascript_intelligence(
                source_evidence_path,
                evidence_root=evidence_root,
            )
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
                evidence_type=(EvidenceType.JAVASCRIPT_INTELLIGENCE_RESULT),
                source="saarthi-javascript-intelligence",
                path=collection.evidence_path,
                sha256=collection.evidence_sha256,
                size_bytes=collection.evidence_size_bytes,
                content_type="application/json",
                step_id="recon-javascript-001",
                tool_name="saarthi-javascript-intelligence",
                metadata={
                    "domain": collection.domain,
                    "input_javascript_count": (collection.input_javascript_count),
                    "fetched_javascript_count": (collection.fetched_javascript_count),
                    "failed_fetch_count": (collection.failed_fetch_count),
                    "endpoint_count": collection.endpoint_count,
                    "parameter_count": collection.parameter_count,
                    "websocket_count": collection.websocket_count,
                    "source_map_count": collection.source_map_count,
                    "secret_candidate_count": (collection.secret_candidate_count),
                    "rejected_input_count": len(collection.rejected_inputs),
                    "collector_execution_id": (collection.collector_execution_id),
                    "collector_evidence_id": (collection.collector_evidence_id),
                    "source_collector_execution_id": (collection.source_collector_execution_id),
                    "source_collector_evidence_id": (collection.source_collector_evidence_id),
                    "stores_full_javascript_source": False,
                },
            ),
            actor=actor,
        )

        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message="Saarthi JavaScript intelligence collector completed.",
            details={
                "tool": "saarthi-javascript-intelligence",
                "domain": collection.domain,
                "fetched_javascript_count": (collection.fetched_javascript_count),
                "endpoint_count": collection.endpoint_count,
                "source_map_count": collection.source_map_count,
                "secret_candidate_count": (collection.secret_candidate_count),
                "evidence_id": evidence.evidence_id,
            },
        )

        execution = database.transition_execution(
            execution_id,
            ExecutionState.ANALYZING,
            actor=actor,
            reason=("JavaScript intelligence evidence is ready for analysis."),
        )

        execution = database.transition_execution(
            execution_id,
            ExecutionState.COMPLETED,
            actor=actor,
            reason=("Phase 3E JavaScript intelligence workflow completed."),
        )

        return TrackedJavaScriptResult(
            execution=execution,
            collection=collection,
            evidence=evidence,
        )

    except (
        JavaScriptCollectionError,
        InvalidStateTransitionError,
    ) as exc:
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message="Saarthi JavaScript intelligence collector failed.",
            details={
                "tool": "saarthi-javascript-intelligence",
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
