"""Persistent non-executing Nuclei preview workflow."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from saarthi_ai.execution.nuclei_adapter import (
    NucleiDryRunRequest,
    NucleiInvocationPreview,
    build_nuclei_invocation_preview,
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

DEFAULT_EVIDENCE_ROOT = (
    Path("evidence") / "controlled-nuclei-previews"
)


class NucleiPreviewWorkflowError(RuntimeError):
    """Raised when a Nuclei preview cannot be persisted safely."""


class TrackedNucleiPreview:
    """Persistent result for one non-executed Nuclei preview."""

    def __init__(
        self,
        *,
        execution: ExecutionRecord,
        preview: NucleiInvocationPreview,
        evidence: EvidenceRecord,
        reused_existing_evidence: bool = False,
    ) -> None:
        self.execution = execution
        self.preview = preview
        self.evidence = evidence
        self.reused_existing_evidence = reused_existing_evidence


def _validate_execution_permissions(
    execution: ExecutionRecord,
    request: NucleiDryRunRequest,
) -> None:
    """Enforce stored authorization before building a preview."""

    if not execution.authorization_confirmed:
        raise InvalidStateTransitionError(
            "Execution does not have confirmed authorization."
        )

    if not execution.active_testing_allowed:
        raise InvalidStateTransitionError(
            "Execution does not allow active testing."
        )

    parsed = urlsplit(request.target_url)
    hostname = parsed.hostname

    if hostname is None or not _domain_in_execution_scope(
        hostname,
        execution,
    ):
        raise InvalidStateTransitionError(
            f"Target '{hostname or request.target_url}' is not "
            "associated with this execution."
        )


def _advance_execution_to_planned(
    database: SaarthiDatabase,
    execution: ExecutionRecord,
    *,
    actor: str,
) -> ExecutionRecord:
    """Move a reusable execution to planned state without executing."""

    current = execution

    if current.state is ExecutionState.CREATED:
        current = database.transition_execution(
            current.execution_id,
            ExecutionState.VALIDATED,
            actor=actor,
            reason="Authorized Nuclei dry-run preview accepted.",
        )

    if current.state is ExecutionState.VALIDATED:
        current = database.transition_execution(
            current.execution_id,
            ExecutionState.PLANNED,
            actor=actor,
            reason="Non-executed Nuclei invocation preview prepared.",
        )

    if current.state is not ExecutionState.PLANNED:
        raise InvalidStateTransitionError(
            "Nuclei preview persistence requires an execution in "
            f"'planned' state; current state is '{current.state.value}'."
        )

    return current


def _serialize_preview(
    execution_id: str,
    preview: NucleiInvocationPreview,
) -> dict[str, object]:
    """Build deterministic JSON evidence for a dry-run preview."""

    return {
        "schema_version": "1.0",
        "phase": "6C",
        "evidence_type": (
            EvidenceType.CONTROLLED_NUCLEI_PREVIEW.value
        ),
        "created_at": datetime.now(UTC).isoformat(),
        "execution_id": execution_id,
        "tool": {
            "name": preview.tool_name,
            "target_url": preview.target_url,
            "arguments": list(preview.arguments),
            "timeout_seconds": preview.timeout_seconds,
            "rate_limit_per_second": (
                preview.rate_limit_per_second
            ),
            "concurrency": preview.concurrency,
            "allowed_tags": list(preview.allowed_tags),
            "excluded_tags": list(preview.excluded_tags),
        },
        "execution": {
            "executed": False,
            "network_activity": False,
            "subprocess_started": False,
            "automatic_retry": False,
        },
    }


def _write_evidence_atomically(
    payload: dict[str, object],
    *,
    evidence_root: Path | None = None,
) -> tuple[str, str, int]:
    """Write one preview file atomically."""

    evidence_directory = evidence_root or DEFAULT_EVIDENCE_ROOT
    evidence_directory.mkdir(parents=True, exist_ok=True)

    evidence_id = f"controlled-nuclei-preview-{uuid4()}"
    evidence_path = evidence_directory / f"{evidence_id}.json"

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
            dir=evidence_directory,
            prefix=".controlled-nuclei-preview-",
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


def _find_matching_preview(
    database: SaarthiDatabase,
    execution_id: str,
    preview: NucleiInvocationPreview,
) -> EvidenceRecord | None:
    """Return an equivalent persisted preview when available."""

    evidence_items = database.list_evidence(
        execution_id,
        evidence_type=EvidenceType.CONTROLLED_NUCLEI_PREVIEW,
    )

    for evidence in evidence_items:
        metadata = evidence.metadata

        if (
            metadata.get("target_url") == preview.target_url
            and metadata.get("arguments")
            == list(preview.arguments)
            and metadata.get("executed") is False
            and metadata.get("network_activity") is False
            and metadata.get("subprocess_started") is False
        ):
            return evidence

    return None


def create_tracked_nuclei_preview(
    database: SaarthiDatabase,
    execution_id: str,
    request: NucleiDryRunRequest,
    *,
    actor: str = "controlled-nuclei-preview",
    evidence_root: Path | None = None,
) -> TrackedNucleiPreview:
    """Persist one approved Nuclei preview without running Nuclei."""

    execution = database.get_execution(execution_id)

    _validate_execution_permissions(
        execution,
        request,
    )

    preview = build_nuclei_invocation_preview(request)

    execution = _advance_execution_to_planned(
        database,
        execution,
        actor=actor,
    )

    existing = _find_matching_preview(
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
                "[6C][nuclei] Existing non-executed "
                "Nuclei preview reused."
            ),
            details={
                "phase_code": "6C",
                "tool": "nuclei",
                "evidence_id": existing.evidence_id,
                "evidence_sha256": existing.sha256,
                "executed": False,
                "network_activity": False,
                "subprocess_started": False,
                "idempotent_reuse": True,
            },
        )

        return TrackedNucleiPreview(
            execution=execution,
            preview=preview,
            evidence=existing,
            reused_existing_evidence=True,
        )

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.APPROVAL_RECORDED,
        actor=actor,
        message=(
            "[6C][nuclei] Explicit operator approval recorded "
            "for a non-executed preview."
        ),
        details={
            "phase_code": "6C",
            "tool": "nuclei",
            "target_url": preview.target_url,
            "executed": False,
        },
    )

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_PREPARED,
        actor=actor,
        message=(
            "[6C][nuclei] Non-executed Nuclei preview prepared."
        ),
        details={
            "phase_code": "6C",
            "tool": "nuclei",
            "arguments": list(preview.arguments),
            "executed": False,
            "network_activity": False,
            "subprocess_started": False,
        },
    )

    payload = _serialize_preview(
        execution_id,
        preview,
    )

    evidence_path: str | None = None
    evidence_registered = False

    try:
        (
            evidence_path,
            evidence_sha256,
            evidence_size,
        ) = _write_evidence_atomically(
            payload,
            evidence_root=evidence_root,
        )

        evidence = database.add_evidence(
            execution_id,
            EvidenceCreate(
                evidence_type=(
                    EvidenceType.CONTROLLED_NUCLEI_PREVIEW
                ),
                source="saarthi-controlled-nuclei-preview",
                path=evidence_path,
                sha256=evidence_sha256,
                size_bytes=evidence_size,
                content_type="application/json",
                step_id="controlled-nuclei-preview-001",
                tool_name="nuclei",
                metadata={
                    "phase": "6C",
                    "target_url": preview.target_url,
                    "arguments": list(preview.arguments),
                    "rate_limit_per_second": (
                        preview.rate_limit_per_second
                    ),
                    "concurrency": preview.concurrency,
                    "timeout_seconds": (
                        preview.timeout_seconds
                    ),
                    "executed": False,
                    "network_activity": False,
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
            execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message=(
                "[6C][nuclei] Preview persistence failed."
            ),
            details={
                "phase_code": "6C",
                "tool": "nuclei",
                "error_type": type(exc).__name__,
                "retry_allowed": True,
                "evidence_registered": False,
                "orphan_file_removed": (
                    evidence_path is not None
                    and not Path(evidence_path).exists()
                ),
                "executed": False,
                "network_activity": False,
                "subprocess_started": False,
            },
        )

        raise NucleiPreviewWorkflowError(
            "Nuclei preview could not be persisted safely."
        ) from exc

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_COMPLETED,
        actor=actor,
        message=(
            "[6C][nuclei] Non-executed Nuclei preview persisted."
        ),
        details={
            "phase_code": "6C",
            "tool": "nuclei",
            "evidence_id": evidence.evidence_id,
            "evidence_sha256": evidence.sha256,
            "executed": False,
            "network_activity": False,
            "subprocess_started": False,
        },
    )

    return TrackedNucleiPreview(
        execution=execution,
        preview=preview,
        evidence=evidence,
    )
