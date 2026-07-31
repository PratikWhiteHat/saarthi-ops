from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from saarthi_ai.execution.http_collector import (
    HttpCollectionError,
    collect_http_metadata,
)
from saarthi_ai.execution.http_models import (
    HttpMetadataCollectionRequest,
    HttpMetadataCollectionResponse,
)
from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceCreate,
    EvidenceRecord,
    EvidenceType,
    ExecutionRecord,
    ExecutionState,
)


class TrackedHttpCollectionResponse(BaseModel):
    """Persistent execution result for HTTP metadata collection."""

    execution: ExecutionRecord
    collection: HttpMetadataCollectionResponse
    evidence: EvidenceRecord


def advance_execution_to_running(
    database: SaarthiDatabase,
    execution: ExecutionRecord,
    *,
    actor: str,
) -> ExecutionRecord:
    """Advance an execution through required pre-run states."""

    current = execution

    if current.state is ExecutionState.CREATED:
        current = database.transition_execution(
            current.execution_id,
            ExecutionState.VALIDATED,
            actor=actor,
            reason="Authorized execution accepted for HTTP collection.",
        )

    if current.state is ExecutionState.VALIDATED:
        current = database.transition_execution(
            current.execution_id,
            ExecutionState.PLANNED,
            actor=actor,
            reason="HTTP metadata collection step prepared.",
        )

    if current.state is ExecutionState.PLANNED:
        current = database.transition_execution(
            current.execution_id,
            ExecutionState.RUNNING,
            actor=actor,
            reason="Controlled HTTP metadata collection started.",
        )

    if current.state is ExecutionState.AWAITING_APPROVAL:
        raise InvalidStateTransitionError("Execution is awaiting approval and cannot run.")

    if current.state is not ExecutionState.RUNNING:
        raise InvalidStateTransitionError(
            "HTTP metadata collection requires an execution in "
            f"'running' state; current state is '{current.state.value}'."
        )

    return current


def fail_execution_safely(
    database: SaarthiDatabase,
    execution_id: str,
    *,
    actor: str,
    reason: str,
) -> None:
    """Move a non-terminal execution to failed without masking errors."""

    try:
        current = database.get_execution(execution_id)

        if current.state in {
            ExecutionState.COMPLETED,
            ExecutionState.FAILED,
            ExecutionState.CANCELLED,
        }:
            return

        database.transition_execution(
            execution_id,
            ExecutionState.FAILED,
            actor=actor,
            reason=reason,
        )
    except (
        InvalidStateTransitionError,
        RuntimeError,
    ):
        return


async def run_tracked_http_collection(
    database: SaarthiDatabase,
    execution_id: str,
    request: HttpMetadataCollectionRequest,
    *,
    actor: str = "http-collector",
    evidence_root: Path | None = None,
) -> TrackedHttpCollectionResponse:
    """Run controlled HTTP collection with persistence and auditing."""

    execution = database.get_execution(execution_id)

    if not execution.authorization_confirmed:
        raise InvalidStateTransitionError("Execution does not have confirmed authorization.")

    request_targets = {target.value for target in request.assessment.targets}

    execution_targets = set(execution.targets)

    if not request_targets & execution_targets:
        normalized_request_targets = {value.rstrip("/") for value in request_targets}
        normalized_execution_targets = {value.rstrip("/") for value in execution_targets}

        if not normalized_request_targets & normalized_execution_targets:
            raise InvalidStateTransitionError(
                "HTTP collection target is not associated with this execution."
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
        message="Controlled HTTP metadata collector started.",
        details={
            "tool": "internal-http-collector",
            "target": request.target,
        },
    )

    try:
        collection = await collect_http_metadata(
            request,
            evidence_root=evidence_root,
        )

        evidence = database.add_evidence(
            execution_id,
            EvidenceCreate(
                evidence_type=EvidenceType.HTTP_METADATA,
                source="internal-http-collector",
                path=collection.evidence_path,
                sha256=collection.body_sha256,
                size_bytes=collection.body_bytes_captured,
                content_type="application/json",
                step_id="recon-001",
                tool_name="internal-http-collector",
                metadata={
                    "target": collection.target,
                    "final_url": collection.final_url,
                    "status_code": collection.status_code,
                    "http_version": collection.http_version,
                    "body_truncated": collection.body_truncated,
                    "collector_execution_id": collection.execution_id,
                    "collector_evidence_id": collection.evidence_id,
                },
            ),
            actor=actor,
        )

        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message="Controlled HTTP metadata collector completed.",
            details={
                "tool": "internal-http-collector",
                "status_code": collection.status_code,
                "evidence_id": evidence.evidence_id,
            },
        )

        execution = database.transition_execution(
            execution_id,
            ExecutionState.ANALYZING,
            actor=actor,
            reason="HTTP metadata evidence is ready for analysis.",
        )

        execution = database.transition_execution(
            execution_id,
            ExecutionState.COMPLETED,
            actor=actor,
            reason="HTTP metadata collection workflow completed.",
        )

        return TrackedHttpCollectionResponse(
            execution=execution,
            collection=collection,
            evidence=evidence,
        )

    except HttpCollectionError as exc:
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message="Controlled HTTP metadata collector failed.",
            details={
                "tool": "internal-http-collector",
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
