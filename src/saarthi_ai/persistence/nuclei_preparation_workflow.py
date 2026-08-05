"""Persistent non-executing Nuclei preparation workflow."""

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

from saarthi_ai.execution.nuclei_adapter import (
    NucleiExecutionPlan,
    NucleiExecutionRequest,
    NucleiRunnerBinding,
    build_nuclei_execution_plan,
    build_nuclei_runner_binding,
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
    Path("evidence") / "controlled-nuclei-preparations"
)


class NucleiPreparationWorkflowError(RuntimeError):
    """Raised when Nuclei preparation cannot be persisted safely."""


@dataclass(frozen=True)
class TrackedNucleiPreparation:
    """Persistent non-executed Nuclei preparation result."""

    execution: ExecutionRecord
    plan: NucleiExecutionPlan
    binding: NucleiRunnerBinding
    preview_evidence: EvidenceRecord
    evidence: EvidenceRecord
    reused_existing_evidence: bool = False


def _validate_execution(
    execution: ExecutionRecord,
    request: NucleiExecutionRequest,
) -> None:
    """Enforce stored permissions and exact execution scope."""

    if not execution.authorization_confirmed:
        raise InvalidStateTransitionError(
            "Execution does not have confirmed authorization."
        )

    if not execution.active_testing_allowed:
        raise InvalidStateTransitionError(
            "Execution does not allow active testing."
        )

    if request.authorization_confirmed is not True:
        raise InvalidStateTransitionError(
            "Nuclei preparation does not confirm authorization."
        )

    if request.active_testing_allowed is not True:
        raise InvalidStateTransitionError(
            "Nuclei preparation does not confirm active-testing permission."
        )

    if request.explicitly_approved is not True:
        raise InvalidStateTransitionError(
            "Explicit operator approval is required for Nuclei preparation."
        )

    parsed = urlsplit(request.preview.target_url)
    hostname = parsed.hostname

    if hostname is None or not _domain_in_execution_scope(
        hostname,
        execution,
    ):
        raise InvalidStateTransitionError(
            f"Target '{hostname or request.preview.target_url}' is not "
            "associated with this execution."
        )

    if execution.state is not ExecutionState.PLANNED:
        raise InvalidStateTransitionError(
            "Nuclei preparation requires an execution in "
            f"'planned' state; current state is '{execution.state.value}'."
        )


def _find_matching_preview(
    database: SaarthiDatabase,
    execution_id: str,
    request: NucleiExecutionRequest,
) -> EvidenceRecord | None:
    """Find the exact persisted preview required by preparation."""

    previews = database.list_evidence(
        execution_id,
        evidence_type=EvidenceType.CONTROLLED_NUCLEI_PREVIEW,
    )

    for evidence in previews:
        metadata = evidence.metadata

        if (
            metadata.get("target_url")
            == request.preview.target_url
            and metadata.get("arguments")
            == list(request.preview.arguments)
            and metadata.get("executed") is False
            and metadata.get("network_activity") is False
            and metadata.get("subprocess_started") is False
        ):
            return evidence

    return None


def _find_matching_preparation(
    database: SaarthiDatabase,
    execution_id: str,
    *,
    plan: NucleiExecutionPlan,
    preview_evidence: EvidenceRecord,
) -> EvidenceRecord | None:
    """Return an equivalent persisted preparation when available."""

    preparations = database.list_evidence(
        execution_id,
        evidence_type=(
            EvidenceType.CONTROLLED_NUCLEI_PREPARATION
        ),
    )

    for evidence in preparations:
        metadata = evidence.metadata

        if (
            metadata.get("preview_evidence_id")
            == preview_evidence.evidence_id
            and metadata.get("target_url") == plan.target_url
            and metadata.get("arguments") == list(plan.arguments)
            and metadata.get("request_timeout_seconds")
            == plan.request_timeout_seconds
            and metadata.get("process_timeout_seconds")
            == plan.process_timeout_seconds
            and metadata.get("max_output_bytes")
            == plan.max_output_bytes
            and metadata.get("executed") is False
            and metadata.get("network_activity") is False
            and metadata.get("subprocess_started") is False
            and metadata.get("runner_invoked") is False
        ):
            return evidence

    return None


def _serialize_preparation(
    execution_id: str,
    *,
    request: NucleiExecutionRequest,
    plan: NucleiExecutionPlan,
    binding: NucleiRunnerBinding,
    preview_evidence: EvidenceRecord,
) -> dict[str, object]:
    """Create preparation evidence without executing Nuclei."""

    return {
        "schema_version": "1.0",
        "phase": "6J.2",
        "evidence_type": (
            EvidenceType.CONTROLLED_NUCLEI_PREPARATION.value
        ),
        "created_at": datetime.now(UTC).isoformat(),
        "execution_id": execution_id,
        "preview": {
            "evidence_id": preview_evidence.evidence_id,
            "sha256": preview_evidence.sha256,
        },
        "approval": {
            "authorization_confirmed": (
                request.authorization_confirmed
            ),
            "active_testing_allowed": (
                request.active_testing_allowed
            ),
            "explicitly_approved": request.explicitly_approved,
        },
        "tool": {
            "name": plan.tool_name,
            "target_url": plan.target_url,
            "arguments": list(plan.arguments),
            "rate_limit_per_second": (
                plan.rate_limit_per_second
            ),
            "concurrency": plan.concurrency,
            "request_timeout_seconds": (
                plan.request_timeout_seconds
            ),
            "process_timeout_seconds": (
                binding.profile.timeout_seconds
            ),
            "max_output_bytes_per_stream": (
                binding.profile.max_output_bytes
            ),
            "max_arguments": binding.profile.max_arguments,
            "max_argument_length": (
                binding.profile.max_argument_length
            ),
        },
        "execution": {
            "executed": False,
            "network_activity": False,
            "subprocess_started": False,
            "runner_invoked": False,
            "executable_resolved": False,
            "automatic_retry": False,
        },
    }


def _write_evidence_atomically(
    payload: dict[str, object],
    *,
    evidence_root: Path | None = None,
) -> tuple[str, str, int]:
    """Write one preparation-evidence file atomically."""

    directory = evidence_root or DEFAULT_EVIDENCE_ROOT
    directory.mkdir(parents=True, exist_ok=True)

    evidence_id = f"controlled-nuclei-preparation-{uuid4()}"
    evidence_path = directory / f"{evidence_id}.json"

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
            dir=directory,
            prefix=".controlled-nuclei-preparation-",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_file.write(serialized)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
            temporary_path = Path(temporary_file.name)

        os.replace(temporary_path, evidence_path)
    finally:
        if (
            temporary_path is not None
            and temporary_path.exists()
        ):
            temporary_path.unlink()

    return (
        str(evidence_path),
        hashlib.sha256(serialized).hexdigest(),
        len(serialized),
    )


def create_tracked_nuclei_preparation(
    database: SaarthiDatabase,
    execution_id: str,
    request: NucleiExecutionRequest,
    *,
    actor: str = "controlled-nuclei-preparation",
    evidence_root: Path | None = None,
) -> TrackedNucleiPreparation:
    """Persist a bounded Nuclei runner binding without execution."""

    execution = database.get_execution(execution_id)
    _validate_execution(execution, request)

    preview_evidence = _find_matching_preview(
        database,
        execution_id,
        request,
    )

    if preview_evidence is None:
        raise NucleiPreparationWorkflowError(
            "A matching persisted Nuclei preview is required "
            "before execution preparation."
        )

    plan = build_nuclei_execution_plan(request)
    binding = build_nuclei_runner_binding(plan)

    existing = _find_matching_preparation(
        database,
        execution_id,
        plan=plan,
        preview_evidence=preview_evidence,
    )

    if existing is not None:
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message=(
                "[6J.2][nuclei] Existing non-executed "
                "Nuclei preparation reused."
            ),
            details={
                "phase_code": "6J.2",
                "tool": "nuclei",
                "evidence_id": existing.evidence_id,
                "evidence_sha256": existing.sha256,
                "preview_evidence_id": (
                    preview_evidence.evidence_id
                ),
                "executed": False,
                "network_activity": False,
                "subprocess_started": False,
                "runner_invoked": False,
                "idempotent_reuse": True,
            },
        )

        return TrackedNucleiPreparation(
            execution=execution,
            plan=plan,
            binding=binding,
            preview_evidence=preview_evidence,
            evidence=existing,
            reused_existing_evidence=True,
        )

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.APPROVAL_RECORDED,
        actor=actor,
        message=(
            "[6J.2][nuclei] Explicit operator approval recorded "
            "for non-executed Nuclei preparation."
        ),
        details={
            "phase_code": "6J.2",
            "tool": "nuclei",
            "target_url": plan.target_url,
            "preview_evidence_id": preview_evidence.evidence_id,
            "explicitly_approved": True,
        },
    )

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_PREPARED,
        actor=actor,
        message=(
            "[6J.2][nuclei] Bounded Nuclei runner binding prepared."
        ),
        details={
            "phase_code": "6J.2",
            "tool": "nuclei",
            "target_url": plan.target_url,
            "arguments": list(plan.arguments),
            "process_timeout_seconds": (
                binding.profile.timeout_seconds
            ),
            "max_output_bytes": (
                binding.profile.max_output_bytes
            ),
            "executed": False,
            "network_activity": False,
            "subprocess_started": False,
            "runner_invoked": False,
        },
    )

    payload = _serialize_preparation(
        execution_id,
        request=request,
        plan=plan,
        binding=binding,
        preview_evidence=preview_evidence,
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
                    EvidenceType.CONTROLLED_NUCLEI_PREPARATION
                ),
                source="saarthi-controlled-nuclei-preparation",
                path=evidence_path,
                sha256=evidence_sha256,
                size_bytes=evidence_size,
                content_type="application/json",
                step_id="controlled-nuclei-preparation-001",
                tool_name="nuclei",
                metadata={
                    "phase": "6J.2",
                    "preview_evidence_id": (
                        preview_evidence.evidence_id
                    ),
                    "target_url": plan.target_url,
                    "arguments": list(plan.arguments),
                    "rate_limit_per_second": (
                        plan.rate_limit_per_second
                    ),
                    "concurrency": plan.concurrency,
                    "request_timeout_seconds": (
                        plan.request_timeout_seconds
                    ),
                    "process_timeout_seconds": (
                        plan.process_timeout_seconds
                    ),
                    "max_output_bytes": (
                        plan.max_output_bytes
                    ),
                    "authorization_confirmed": True,
                    "active_testing_allowed": True,
                    "explicitly_approved": True,
                    "executed": False,
                    "network_activity": False,
                    "subprocess_started": False,
                    "runner_invoked": False,
                    "executable_resolved": False,
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
                "[6J.2][nuclei] Preparation persistence failed."
            ),
            details={
                "phase_code": "6J.2",
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
                "runner_invoked": False,
            },
        )

        raise NucleiPreparationWorkflowError(
            "Nuclei preparation could not be persisted safely."
        ) from exc

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_COMPLETED,
        actor=actor,
        message=(
            "[6J.2][nuclei] Non-executed Nuclei "
            "preparation persisted."
        ),
        details={
            "phase_code": "6J.2",
            "tool": "nuclei",
            "evidence_id": evidence.evidence_id,
            "evidence_sha256": evidence.sha256,
            "preview_evidence_id": preview_evidence.evidence_id,
            "executed": False,
            "network_activity": False,
            "subprocess_started": False,
            "runner_invoked": False,
        },
    )

    return TrackedNucleiPreparation(
        execution=execution,
        plan=plan,
        binding=binding,
        preview_evidence=preview_evidence,
        evidence=evidence,
    )
