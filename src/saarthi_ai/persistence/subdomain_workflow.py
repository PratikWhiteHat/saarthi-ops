from __future__ import annotations

import threading
from pathlib import Path

from saarthi_ai.execution.tool_runner import ToolOutputEvent
from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.dns_workflow import (
    _domain_is_in_execution_scope,
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
from saarthi_ai.recon.dns_collector import (
    DnsCollectionError,
    normalize_domain,
)
from saarthi_ai.recon.subdomain_collector import (
    SubdomainCollectionError,
    SubdomainCollectionResult,
    collect_subdomains,
)


class TrackedSubdomainCollectionResult:
    """Combined persistent subdomain workflow result."""

    def __init__(
        self,
        *,
        execution: ExecutionRecord,
        collection: SubdomainCollectionResult,
        evidence: EvidenceRecord,
    ) -> None:
        self.execution = execution
        self.collection = collection
        self.evidence = evidence


def run_tracked_subdomain_collection(
    database: SaarthiDatabase,
    execution_id: str,
    domain: str,
    *,
    actor: str = "subdomain-collector",
    evidence_root: Path | None = None,
) -> TrackedSubdomainCollectionResult:
    """Run passive subdomain discovery with persistence and auditing."""

    execution = database.get_execution(execution_id)

    if not execution.authorization_confirmed:
        raise InvalidStateTransitionError("Execution does not have confirmed authorization.")

    if not _domain_is_in_execution_scope(
        domain,
        execution,
    ):
        raise InvalidStateTransitionError(
            f"Domain '{domain}' is not associated with this execution."
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
        message="Passive subdomain collector started.",
        details={
            "tool": "internal-passive-subdomain-collector",
            "domain": domain,
            "mode": "passive",
        },
    )

    progress_lock = threading.Lock()
    progress_event_count = 0
    maximum_progress_events = 200

    def record_progress(event: ToolOutputEvent) -> None:
        """Persist bounded, in-scope hostname output from passive tools."""

        nonlocal progress_event_count

        if event.stream != "stdout":
            return

        raw_value = event.line.strip().lower()

        if raw_value.startswith("*."):
            raw_value = raw_value[2:]

        try:
            hostname = normalize_domain(raw_value)
        except DnsCollectionError:
            return

        if not _domain_is_in_execution_scope(
            hostname,
            execution,
        ):
            return

        with progress_lock:
            if progress_event_count >= maximum_progress_events:
                return

            progress_event_count += 1

            database.add_audit_event(
                execution_id,
                event_type=AuditEventType.TOOL_OUTPUT,
                actor=actor,
                message=f"[3B][{event.tool_name}] {hostname}",
                details={
                    "phase_code": "3B",
                    "tool": event.tool_name,
                    "stream": event.stream,
                    "hostname": hostname,
                    "sequence": progress_event_count,
                },
            )

    try:
        collection = collect_subdomains(
            domain,
            evidence_root=evidence_root,
            progress_callback=record_progress,
        )

        evidence = database.add_evidence(
            execution_id,
            EvidenceCreate(
                evidence_type=EvidenceType.SUBDOMAIN_RESULT,
                source="internal-passive-subdomain-collector",
                path=collection.evidence_path,
                sha256=collection.evidence_sha256,
                size_bytes=collection.evidence_size_bytes,
                content_type="application/json",
                step_id="recon-subdomains-001",
                tool_name="internal-passive-subdomain-collector",
                metadata={
                    "domain": collection.domain,
                    "source": collection.source,
                    "candidate_count": len(collection.candidates),
                    "raw_entry_count": (collection.raw_entry_count),
                    "rejected_name_count": len(collection.rejected_names),
                    "collector_execution_id": (collection.collector_execution_id),
                    "collector_evidence_id": (collection.collector_evidence_id),
                },
            ),
            actor=actor,
        )

        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message="Passive subdomain collector completed.",
            details={
                "tool": "internal-passive-subdomain-collector",
                "domain": collection.domain,
                "candidate_count": len(collection.candidates),
                "evidence_id": evidence.evidence_id,
            },
        )

        execution = database.transition_execution(
            execution_id,
            ExecutionState.ANALYZING,
            actor=actor,
            reason="Passive subdomain evidence is ready for analysis.",
        )

        execution = database.transition_execution(
            execution_id,
            ExecutionState.COMPLETED,
            actor=actor,
            reason="Passive subdomain collection workflow completed.",
        )

        return TrackedSubdomainCollectionResult(
            execution=execution,
            collection=collection,
            evidence=evidence,
        )

    except SubdomainCollectionError as exc:
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message="Passive subdomain collector failed.",
            details={
                "tool": "internal-passive-subdomain-collector",
                "domain": domain,
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
