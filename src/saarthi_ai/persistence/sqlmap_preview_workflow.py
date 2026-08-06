"""Persistent non-executing Phase 6C.1 SQLmap preview workflow."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from saarthi_ai.execution.sqlmap_adapter import (
    SqlmapInvocationPreview,
    SqlmapPreviewRequest,
    build_sqlmap_invocation_preview,
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
    ExecutionState,
)

DEFAULT_EVIDENCE_ROOT = Path("evidence") / "controlled-sqlmap-previews"


class SqlmapPreviewWorkflowError(RuntimeError):
    """Raised when a SQLmap preview cannot be persisted safely."""


@dataclass(frozen=True)
class TrackedSqlmapPreview:
    """Persistent result for one redacted non-executed preview."""

    execution: ExecutionRecord
    preview: SqlmapInvocationPreview
    evidence: EvidenceRecord
    reused_existing_evidence: bool = False


def _validate_execution_permissions(
    execution: ExecutionRecord,
    request: SqlmapPreviewRequest,
) -> None:
    if not execution.authorization_confirmed:
        raise InvalidStateTransitionError(
            "Execution does not have confirmed authorization."
        )
    if not execution.active_testing_allowed:
        raise InvalidStateTransitionError(
            "Execution does not allow active testing."
        )
    if not execution.intrusive_testing_allowed:
        raise InvalidStateTransitionError(
            "Execution does not allow intrusive testing."
        )

    hostname = urlsplit(request.target_url).hostname
    if hostname is None or not _domain_in_execution_scope(
        hostname,
        execution,
    ):
        raise InvalidStateTransitionError(
            f"Target '{hostname or '<invalid>'}' is not associated "
            "with this execution."
        )


def _advance_to_planned(
    database: SaarthiDatabase,
    execution: ExecutionRecord,
    *,
    actor: str,
) -> ExecutionRecord:
    current = execution
    if current.state is ExecutionState.CREATED:
        current = database.transition_execution(
            current.execution_id,
            ExecutionState.VALIDATED,
            actor=actor,
            reason="Authorized SQLmap preview request accepted.",
        )
    if current.state is ExecutionState.VALIDATED:
        current = database.transition_execution(
            current.execution_id,
            ExecutionState.PLANNED,
            actor=actor,
            reason="Non-executed SQLmap preview prepared.",
        )
    if current.state is not ExecutionState.PLANNED:
        raise InvalidStateTransitionError(
            "SQLmap preview requires an execution in 'planned' state; "
            f"current state is '{current.state.value}'."
        )
    return current


def _preview_payload(
    execution_id: str,
    preview: SqlmapInvocationPreview,
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "phase": "6C.1",
        "evidence_type": EvidenceType.CONTROLLED_SQLMAP_PREVIEW.value,
        "created_at": datetime.now(UTC).isoformat(),
        "execution_id": execution_id,
        "tool": {
            "name": preview.tool_name,
            "method": preview.method.value,
            "target_display_url": preview.target_display_url,
            "target_url_sha256": preview.target_url_sha256,
            "parameter_name": preview.parameter_name,
            "post_parameter_names": list(
                preview.post_parameter_names
            ),
            "post_content_type": (
                preview.post_content_type.value
                if preview.post_content_type is not None
                else None
            ),
            "redacted_arguments": list(preview.redacted_arguments),
            "timeout_seconds": preview.timeout_seconds,
            "level": preview.level,
            "risk": preview.risk,
            "threads": preview.threads,
            "retries": preview.retries,
            "techniques": preview.techniques,
            "prohibited_capabilities": list(
                preview.prohibited_capabilities
            ),
        },
        "safety": {
            "request_values_stored": preview.request_values_stored,
            "executable_arguments_built": (
                preview.executable_arguments_built
            ),
            "executed": preview.executed,
            "network_activity": preview.network_activity,
            "subprocess_started": preview.subprocess_started,
        },
    }


def _write_evidence_atomically(
    payload: dict[str, object],
    *,
    evidence_root: Path,
) -> tuple[str, str, int]:
    evidence_root.mkdir(parents=True, exist_ok=True)
    evidence_id = f"controlled-sqlmap-preview-{uuid4()}"
    path = evidence_root / f"{evidence_id}.json"
    serialized = (
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=evidence_root,
            prefix=".controlled-sqlmap-preview-",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_file.write(serialized)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
            temporary_path = Path(temporary_file.name)
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()

    return (
        str(path),
        hashlib.sha256(serialized).hexdigest(),
        len(serialized),
    )


def _find_existing(
    database: SaarthiDatabase,
    execution_id: str,
    preview: SqlmapInvocationPreview,
) -> EvidenceRecord | None:
    for evidence in database.list_evidence(
        execution_id,
        evidence_type=EvidenceType.CONTROLLED_SQLMAP_PREVIEW,
    ):
        metadata = evidence.metadata
        if (
            metadata.get("target_url_sha256")
            == preview.target_url_sha256
            and metadata.get("method") == preview.method.value
            and metadata.get("parameter_name")
            == preview.parameter_name
            and metadata.get("redacted_arguments")
            == list(preview.redacted_arguments)
            and metadata.get("executed") is False
            and metadata.get("network_activity") is False
            and metadata.get("subprocess_started") is False
        ):
            return evidence
    return None


def create_tracked_sqlmap_preview(
    database: SaarthiDatabase,
    execution_id: str,
    request: SqlmapPreviewRequest,
    *,
    actor: str = "controlled-sqlmap-preview",
    evidence_root: Path | None = None,
) -> TrackedSqlmapPreview:
    """Persist one redacted preview without running SQLmap."""

    execution = database.get_execution(execution_id)
    _validate_execution_permissions(execution, request)
    preview = build_sqlmap_invocation_preview(request)
    execution = _advance_to_planned(
        database,
        execution,
        actor=actor,
    )

    existing = _find_existing(
        database,
        execution_id,
        preview,
    )
    if existing is not None:
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message=(
                "[6C.1][sqlmap] Existing non-executed preview reused."
            ),
            details={
                "phase_code": "6C.1",
                "tool": "sqlmap",
                "evidence_id": existing.evidence_id,
                "idempotent_reuse": True,
                "executed": False,
                "network_activity": False,
                "subprocess_started": False,
            },
        )
        return TrackedSqlmapPreview(
            execution=execution,
            preview=preview,
            evidence=existing,
            reused_existing_evidence=True,
        )

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.APPROVAL_RECORDED,
        actor=actor,
        message="[6C.1][sqlmap] Preview approval recorded.",
        details={
            "phase_code": "6C.1",
            "tool": "sqlmap",
            "method": preview.method.value,
            "target_url_sha256": preview.target_url_sha256,
            "parameter_name": preview.parameter_name,
            "executed": False,
        },
    )
    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_PREPARED,
        actor=actor,
        message="[6C.1][sqlmap] Redacted preview prepared.",
        details={
            "phase_code": "6C.1",
            "tool": "sqlmap",
            "redacted_arguments": list(preview.redacted_arguments),
            "executed": False,
            "network_activity": False,
            "subprocess_started": False,
        },
    )
    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_OUTPUT,
        actor=actor,
        message=(
            "[6C.1][sqlmap] Detection-only safety policy verified."
        ),
        details={
            "phase_code": "6C.1",
            "tool": "sqlmap",
            "method": preview.method.value,
            "parameter_name": preview.parameter_name,
            "level": preview.level,
            "risk": preview.risk,
            "threads": preview.threads,
            "retries": preview.retries,
            "techniques": preview.techniques,
            "request_values_stored": False,
            "executable_arguments_built": False,
            "prohibited_capabilities": list(
                preview.prohibited_capabilities
            ),
            "executed": False,
            "network_activity": False,
            "subprocess_started": False,
        },
    )

    root = evidence_root or DEFAULT_EVIDENCE_ROOT
    evidence_path: str | None = None
    registered = False
    try:
        evidence_path, evidence_sha256, evidence_size = (
            _write_evidence_atomically(
                _preview_payload(execution_id, preview),
                evidence_root=root,
            )
        )
        evidence = database.add_evidence(
            execution_id,
            EvidenceCreate(
                evidence_type=EvidenceType.CONTROLLED_SQLMAP_PREVIEW,
                source="saarthi-controlled-sqlmap-preview",
                path=evidence_path,
                sha256=evidence_sha256,
                size_bytes=evidence_size,
                content_type="application/json",
                step_id="6C.1-sqlmap-preview-001",
                tool_name="sqlmap",
                metadata={
                    "phase": "6C.1",
                    "method": preview.method.value,
                    "target_display_url": (
                        preview.target_display_url
                    ),
                    "target_url_sha256": preview.target_url_sha256,
                    "parameter_name": preview.parameter_name,
                    "post_parameter_names": list(
                        preview.post_parameter_names
                    ),
                    "post_content_type": (
                        preview.post_content_type.value
                        if preview.post_content_type is not None
                        else None
                    ),
                    "redacted_arguments": list(
                        preview.redacted_arguments
                    ),
                    "request_values_stored": False,
                    "executable_arguments_built": False,
                    "executed": False,
                    "network_activity": False,
                    "subprocess_started": False,
                },
            ),
            actor=actor,
        )
        registered = True
    except (OSError, RuntimeError, ValueError) as exc:
        if evidence_path is not None and not registered:
            try:
                Path(evidence_path).unlink(missing_ok=True)
            except OSError:
                pass
        raise SqlmapPreviewWorkflowError(
            "SQLmap preview could not be persisted safely."
        ) from exc

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_COMPLETED,
        actor=actor,
        message="[6C.1][sqlmap] Non-executed preview persisted.",
        details={
            "phase_code": "6C.1",
            "tool": "sqlmap",
            "evidence_id": evidence.evidence_id,
            "evidence_sha256": evidence.sha256,
            "executed": False,
            "network_activity": False,
            "subprocess_started": False,
        },
    )
    return TrackedSqlmapPreview(
        execution=execution,
        preview=preview,
        evidence=evidence,
    )
