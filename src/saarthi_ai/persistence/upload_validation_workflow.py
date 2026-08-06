"""Manual-only file-upload validation plans and external-result import."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceCreate,
    EvidenceRecord,
    EvidenceType,
    ExecutionRecord,
    ExecutionState,
)

MAX_RESULT_BYTES = 1024 * 1024
PLAN_SCHEMA = "saarthi.upload.manual-plan.v1"
RESULT_SCHEMA = "saarthi.upload.external-result.v1"


class UploadValidationWorkflowError(RuntimeError):
    """Raised when a manual upload plan or result fails closed."""


class UploadValidationKind(StrEnum):
    """Supported manual-only upload validation categories."""

    EXTENSION_BYPASS = "extension_bypass_validation"
    MIME_CONTENT_CONSISTENCY = "mime_content_consistency_validation"


class UploadValidationOutcome(StrEnum):
    """Operator-reported external validation outcome."""

    REJECTED = "rejected"
    ACCEPTED = "accepted"
    INCONCLUSIVE = "inconclusive"


class UploadCleanupStatus(StrEnum):
    """Cleanup status for an externally tested upload artifact."""

    NOT_REQUIRED = "not_required"
    REQUIRED = "required"
    VERIFIED = "verified"


@dataclass(frozen=True)
class UploadValidationPlan:
    execution: ExecutionRecord
    evidence: EvidenceRecord
    plan_id: str


@dataclass(frozen=True)
class ImportedUploadValidationResult:
    execution: ExecutionRecord
    plan_evidence: EvidenceRecord
    result_evidence: EvidenceRecord
    outcome: UploadValidationOutcome
    cleanup_status: UploadCleanupStatus


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)
        + "\n"
    ).encode()


def _write_atomic(path: Path, payload: bytes) -> tuple[str, str, int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return str(path), hashlib.sha256(payload).hexdigest(), len(payload)


def create_upload_validation_plan(
    database: SaarthiDatabase,
    execution_id: str,
    *,
    target_url: str,
    kind: UploadValidationKind,
    explicitly_approved: bool,
    actor: str = "upload-manual-validation-planner",
    evidence_root: Path = Path("evidence/upload-validation-plans"),
) -> UploadValidationPlan:
    """Persist a non-executing, approval-bound manual validation plan."""

    execution = database.get_execution(execution_id)
    parsed = urlsplit(target_url)
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise UploadValidationWorkflowError(
            "A credential-free absolute HTTP or HTTPS target is required."
        )
    if not execution.authorization_confirmed:
        raise UploadValidationWorkflowError(
            "Written authorization must be confirmed."
        )
    if not execution.active_testing_allowed:
        raise UploadValidationWorkflowError(
            "Active-testing permission must be confirmed."
        )
    if not explicitly_approved:
        raise UploadValidationWorkflowError(
            "Explicit operator approval is required."
        )
    if execution.state is not ExecutionState.CREATED:
        raise UploadValidationWorkflowError(
            "Upload validation planning requires a created execution."
        )

    plan_id = f"upload-plan-{uuid4()}"
    payload = {
        "schema": PLAN_SCHEMA,
        "plan_id": plan_id,
        "execution_id": execution_id,
        "validation_kind": kind.value,
        "target": {
            "display_url": target_url,
            "sha256": hashlib.sha256(target_url.encode()).hexdigest(),
        },
        "execution": {
            "manual_only": True,
            "file_created_by_saarthi": False,
            "file_uploaded_by_saarthi": False,
            "network_activity": False,
            "executable_instructions_included": False,
        },
        "result_contract": {
            "schema": RESULT_SCHEMA,
            "outcomes": [item.value for item in UploadValidationOutcome],
            "cleanup_statuses": [
                item.value for item in UploadCleanupStatus
            ],
            "submitted_file_content_allowed": False,
            "payload_allowed": False,
        },
    }
    encoded = _canonical_json(payload)
    path, digest, size = _write_atomic(
        evidence_root / f"{plan_id}.json",
        encoded,
    )
    evidence = database.add_evidence(
        execution_id,
        EvidenceCreate(
            evidence_type=EvidenceType.UPLOAD_VALIDATION_PLAN,
            source="saarthi-upload-manual-validation-planner",
            path=path,
            sha256=digest,
            size_bytes=size,
            content_type="application/json",
            step_id="6C.6-upload-manual-plan",
            tool_name="saarthi-upload-validator",
            metadata={
                "phase": "6C.6",
                "plan_id": plan_id,
                "validation_kind": kind.value,
                "manual_only": True,
                "executed": False,
                "network_activity": False,
            },
        ),
        actor=actor,
    )
    database.transition_execution(
        execution_id,
        ExecutionState.VALIDATED,
        actor=actor,
        reason="Upload validation scope and approval verified.",
    )
    execution = database.transition_execution(
        execution_id,
        ExecutionState.PLANNED,
        actor=actor,
        reason="Manual-only upload validation plan persisted.",
    )
    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.APPROVAL_RECORDED,
        actor=actor,
        message="[6C.6][upload] Manual validation approval recorded.",
        details={
            "phase_code": "6C.6",
            "plan_id": plan_id,
            "validation_kind": kind.value,
            "manual_only": True,
            "network_activity": False,
        },
    )
    return UploadValidationPlan(
        execution=execution,
        evidence=evidence,
        plan_id=plan_id,
    )


def _load_plan(
    database: SaarthiDatabase,
    execution_id: str,
) -> tuple[EvidenceRecord, dict[str, Any]]:
    plans = database.list_evidence(
        execution_id,
        evidence_type=EvidenceType.UPLOAD_VALIDATION_PLAN,
    )
    if not plans:
        raise UploadValidationWorkflowError(
            "No upload validation plan exists for this execution."
        )
    evidence = plans[-1]
    try:
        content = Path(evidence.path).read_bytes()
        payload = json.loads(content)
    except (OSError, json.JSONDecodeError) as exc:
        raise UploadValidationWorkflowError(
            "Upload validation plan could not be verified."
        ) from exc
    if (
        evidence.sha256 is None
        or hashlib.sha256(content).hexdigest() != evidence.sha256
    ):
        raise UploadValidationWorkflowError(
            "Upload validation plan hash does not match."
        )
    return evidence, payload


def import_upload_validation_result(
    database: SaarthiDatabase,
    execution_id: str,
    result_path: Path,
    *,
    actor: str = "upload-external-result-importer",
    evidence_root: Path = Path("evidence/upload-external-results"),
) -> ImportedUploadValidationResult:
    """Import a structured operator result without handling submitted files."""

    execution = database.get_execution(execution_id)
    if execution.state is not ExecutionState.PLANNED:
        raise UploadValidationWorkflowError(
            "Upload result import requires a planned execution."
        )
    plan_evidence, plan = _load_plan(database, execution_id)
    candidate = result_path.expanduser()
    if candidate.is_symlink():
        raise UploadValidationWorkflowError(
            "Upload result must not be a symbolic link."
        )
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise UploadValidationWorkflowError(
            "Upload result file does not exist."
        ) from exc
    if (
        not resolved.is_file()
        or resolved.suffix.lower() != ".json"
        or not 1 <= resolved.stat().st_size <= MAX_RESULT_BYTES
    ):
        raise UploadValidationWorkflowError(
            "Upload result must be a JSON file between 1 byte and 1 MiB."
        )
    try:
        content = resolved.read_bytes()
        result = json.loads(content)
    except (OSError, json.JSONDecodeError) as exc:
        raise UploadValidationWorkflowError(
            "Upload result is not valid JSON."
        ) from exc
    if not isinstance(result, dict):
        raise UploadValidationWorkflowError(
            "Upload result must be a JSON object."
        )
    if (
        result.get("schema") != RESULT_SCHEMA
        or result.get("execution_id") != execution_id
        or result.get("plan_sha256") != plan_evidence.sha256
        or result.get("validation_kind") != plan.get("validation_kind")
    ):
        raise UploadValidationWorkflowError(
            "Upload result does not match the approved plan."
        )
    prohibited = {
        "payload",
        "file_content",
        "submitted_file",
        "command",
        "executable",
    }
    if prohibited.intersection(result):
        raise UploadValidationWorkflowError(
            "Upload result contains prohibited submitted-file content."
        )
    try:
        outcome = UploadValidationOutcome(str(result["outcome"]))
        cleanup = UploadCleanupStatus(str(result["cleanup_status"]))
    except (KeyError, ValueError) as exc:
        raise UploadValidationWorkflowError(
            "Upload result outcome or cleanup status is invalid."
        ) from exc
    if outcome is UploadValidationOutcome.ACCEPTED and (
        cleanup is UploadCleanupStatus.NOT_REQUIRED
    ):
        raise UploadValidationWorkflowError(
            "An accepted external upload requires cleanup tracking."
        )

    digest = hashlib.sha256(content).hexdigest()
    destination = evidence_root / execution_id / f"result-{uuid4()}.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(resolved, destination)
    result_evidence = database.add_evidence(
        execution_id,
        EvidenceCreate(
            evidence_type=EvidenceType.UPLOAD_EXTERNAL_RESULT,
            source="operator-supplied-upload-validation-result",
            path=str(destination),
            sha256=digest,
            size_bytes=len(content),
            content_type="application/json",
            step_id="6C.6-upload-external-result",
            tool_name="saarthi-upload-validator",
            metadata={
                "phase": "6C.6",
                "plan_evidence_id": plan_evidence.evidence_id,
                "validation_kind": result["validation_kind"],
                "outcome": outcome.value,
                "cleanup_status": cleanup.value,
                "imported_locally": True,
                "file_uploaded_by_saarthi": False,
                "network_activity_by_saarthi": False,
            },
        ),
        actor=actor,
    )
    database.transition_execution(
        execution_id,
        ExecutionState.RUNNING,
        actor=actor,
        reason="External upload validation result import started.",
    )
    database.transition_execution(
        execution_id,
        ExecutionState.ANALYZING,
        actor=actor,
        reason="External upload validation result is ready for analysis.",
    )
    execution = database.transition_execution(
        execution_id,
        ExecutionState.COMPLETED,
        actor=actor,
        reason="External upload validation result import completed.",
    )
    if outcome is UploadValidationOutcome.ACCEPTED:
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.FINDING_CREATED,
            actor=actor,
            message=(
                "[6C.6][upload] Operator-reported upload control "
                "acceptance registered for review."
            ),
            details={
                "phase_code": "6C.6",
                "validation_kind": result["validation_kind"],
                "outcome": outcome.value,
                "cleanup_status": cleanup.value,
                "result_evidence_id": result_evidence.evidence_id,
                "confirmed_by_saarthi": False,
                "submitted_file_content_stored": False,
            },
        )
    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_COMPLETED,
        actor=actor,
        message="[6C.6][upload] External result imported and analyzed.",
        details={
            "phase_code": "6C.6",
            "validation_kind": result["validation_kind"],
            "outcome": outcome.value,
            "cleanup_status": cleanup.value,
            "result_evidence_id": result_evidence.evidence_id,
            "network_activity": False,
        },
    )
    return ImportedUploadValidationResult(
        execution=execution,
        plan_evidence=plan_evidence,
        result_evidence=result_evidence,
        outcome=outcome,
        cleanup_status=cleanup,
    )
