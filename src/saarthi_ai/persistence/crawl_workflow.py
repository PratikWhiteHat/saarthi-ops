"""Persistent Phase 3D crawling and URL intelligence workflow."""

from __future__ import annotations

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
from saarthi_ai.recon.crawl_collector import (
    CrawlCollectionError,
    collect_crawl_intelligence,
)
from saarthi_ai.recon.crawl_models import CrawlCollectionResult


class TrackedCrawlResult:
    """Combined persistent Phase 3D crawl workflow result."""

    def __init__(
        self,
        *,
        execution: ExecutionRecord,
        collection: CrawlCollectionResult,
        evidence: EvidenceRecord,
    ) -> None:
        self.execution = execution
        self.collection = collection
        self.evidence = evidence


def run_tracked_crawl(
    database: SaarthiDatabase,
    execution_id: str,
    source_evidence_path: Path,
    *,
    actor: str = "crawl-collector",
    evidence_root: Path | None = None,
) -> TrackedCrawlResult:
    """Run Phase 3D crawling with persistence and auditing."""

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
        message="ProjectDiscovery Katana crawl collector started.",
        details={
            "tool": "projectdiscovery-katana",
            "source_evidence_path": str(source_evidence_path),
            "mode": "active-low-risk",
            "depth": 2,
            "rate_limit": 2,
        },
    )

    try:
        collection = collect_crawl_intelligence(
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
                evidence_type=EvidenceType.CRAWL_RESULT,
                source="projectdiscovery-katana",
                path=collection.evidence_path,
                sha256=collection.evidence_sha256,
                size_bytes=collection.evidence_size_bytes,
                content_type="application/json",
                step_id="recon-crawl-001",
                tool_name="projectdiscovery-katana",
                metadata={
                    "domain": collection.domain,
                    "input_service_count": collection.input_service_count,
                    "crawled_service_count": collection.crawled_service_count,
                    "discovered_url_count": collection.discovered_url_count,
                    "form_count": collection.form_count,
                    "parameter_count": collection.parameter_count,
                    "javascript_url_count": collection.javascript_url_count,
                    "websocket_url_count": collection.websocket_url_count,
                    "malformed_line_count": collection.malformed_line_count,
                    "rejected_input_count": len(collection.rejected_inputs),
                    "rejected_result_count": len(collection.rejected_results),
                    "collector_execution_id": collection.collector_execution_id,
                    "collector_evidence_id": collection.collector_evidence_id,
                    "source_collector_execution_id": (collection.source_collector_execution_id),
                    "source_collector_evidence_id": (collection.source_collector_evidence_id),
                },
            ),
            actor=actor,
        )

        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message="ProjectDiscovery Katana crawl collector completed.",
            details={
                "tool": "projectdiscovery-katana",
                "domain": collection.domain,
                "discovered_url_count": collection.discovered_url_count,
                "form_count": collection.form_count,
                "evidence_id": evidence.evidence_id,
            },
        )

        execution = database.transition_execution(
            execution_id,
            ExecutionState.ANALYZING,
            actor=actor,
            reason="Crawl and URL intelligence evidence is ready for analysis.",
        )

        execution = database.transition_execution(
            execution_id,
            ExecutionState.COMPLETED,
            actor=actor,
            reason="Phase 3D crawling and URL intelligence workflow completed.",
        )

        return TrackedCrawlResult(
            execution=execution,
            collection=collection,
            evidence=evidence,
        )

    except (
        CrawlCollectionError,
        InvalidStateTransitionError,
    ) as exc:
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message="ProjectDiscovery Katana crawl collector failed.",
            details={
                "tool": "projectdiscovery-katana",
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
