from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

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
from saarthi_ai.recon.dns_collector import (
    DnsCollectionError,
    DnsCollectionResult,
    collect_dns_records,
)


def _target_hostname(target: str) -> str:
    """Extract a normalized hostname from an execution target."""

    value = target.strip().lower()

    if "://" in value:
        hostname = urlparse(value).hostname
    else:
        hostname = value.split("/", maxsplit=1)[0].split(":", maxsplit=1)[0]

    return (hostname or "").rstrip(".")


def _domain_is_in_execution_scope(
    domain: str,
    execution: ExecutionRecord,
) -> bool:
    """Return whether the requested DNS domain belongs to execution scope."""

    normalized_domain = domain.lower().rstrip(".")

    for target in execution.targets:
        target_hostname = _target_hostname(target)

        if not target_hostname:
            continue

        if normalized_domain == target_hostname:
            return True

        if normalized_domain.endswith(f".{target_hostname}"):
            return True

    return False


class TrackedDnsCollectionResult:
    """Combined persistent DNS workflow result."""

    def __init__(
        self,
        *,
        execution: ExecutionRecord,
        collection: DnsCollectionResult,
        evidence: EvidenceRecord,
    ) -> None:
        self.execution = execution
        self.collection = collection
        self.evidence = evidence


def run_tracked_dns_collection(
    database: SaarthiDatabase,
    execution_id: str,
    domain: str,
    *,
    actor: str = "dns-collector",
    evidence_root: Path | None = None,
) -> TrackedDnsCollectionResult:
    """Run controlled DNS collection with persistence and auditing."""

    execution = database.get_execution(execution_id)

    if not execution.authorization_confirmed:
        raise InvalidStateTransitionError("Execution does not have confirmed authorization.")

    if not _domain_is_in_execution_scope(domain, execution):
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
        message="Controlled DNS collector started.",
        details={
            "tool": "internal-dns-collector",
            "domain": domain,
        },
    )

    try:
        collection = collect_dns_records(
            domain,
            evidence_root=evidence_root,
        )

        total_records = sum(len(record_items) for record_items in collection.records.values())

        evidence = database.add_evidence(
            execution_id,
            EvidenceCreate(
                evidence_type=EvidenceType.DNS_RESULT,
                source="internal-dns-collector",
                path=collection.evidence_path,
                sha256=collection.evidence_sha256,
                size_bytes=collection.evidence_size_bytes,
                content_type="application/json",
                step_id="recon-dns-001",
                tool_name="internal-dns-collector",
                metadata={
                    "domain": collection.domain,
                    "nameserver": collection.nameserver,
                    "record_count": total_records,
                    "record_types": list(collection.records),
                    "errors": collection.errors,
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
            message="Controlled DNS collector completed.",
            details={
                "tool": "internal-dns-collector",
                "domain": collection.domain,
                "record_count": total_records,
                "evidence_id": evidence.evidence_id,
            },
        )

        execution = database.transition_execution(
            execution_id,
            ExecutionState.ANALYZING,
            actor=actor,
            reason="DNS evidence is ready for analysis.",
        )

        execution = database.transition_execution(
            execution_id,
            ExecutionState.COMPLETED,
            actor=actor,
            reason="DNS collection workflow completed.",
        )

        return TrackedDnsCollectionResult(
            execution=execution,
            collection=collection,
            evidence=evidence,
        )

    except DnsCollectionError as exc:
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message="Controlled DNS collector failed.",
            details={
                "tool": "internal-dns-collector",
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
