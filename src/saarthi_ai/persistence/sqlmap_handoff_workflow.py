"""Asynchronous, non-executing SQLmap handoff and result import."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.http_workflow import fail_execution_safely
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceCreate,
    EvidenceRecord,
    EvidenceType,
    ExecutionRecord,
    ExecutionState,
)
from saarthi_ai.persistence.sqlmap_preview_workflow import (
    TrackedSqlmapPreview,
)

DEFAULT_HANDOFF_ROOT = Path("evidence") / "sqlmap-handoffs"
DEFAULT_IMPORT_ROOT = Path("evidence") / "sqlmap-external-results"
MAX_EXTERNAL_RESULT_BYTES = 16 * 1024 * 1024
SUPPORTED_RESULT_SUFFIXES = frozenset(
    {".json", ".jsonl", ".log", ".txt", ".csv"}
)
NORMALIZED_RESULT_SCHEMA = "saarthi.sqlmap.external-result.v1"
MAX_NORMALIZED_FINDINGS = 50
_ALLOWED_CONFIDENCE = frozenset({"low", "medium", "high"})


class SqlmapHandoffWorkflowError(RuntimeError):
    """Raised when a handoff or local result import fails closed."""


@dataclass(frozen=True)
class SqlmapHandoff:
    """Persisted non-executable handoff manifest."""

    execution: ExecutionRecord
    preview_evidence: EvidenceRecord
    manifest_evidence: EvidenceRecord
    handoff_id: str
    result_inbox: str
    reused_existing_evidence: bool = False


@dataclass(frozen=True)
class ImportedSqlmapResult:
    """Locally imported external result associated with one handoff."""

    execution: ExecutionRecord
    manifest_evidence: EvidenceRecord
    result_evidence: EvidenceRecord
    reused_existing_evidence: bool = False


@dataclass(frozen=True)
class AnalyzedSqlmapResult:
    """Sanitized offline analysis of one imported result."""

    execution: ExecutionRecord
    manifest_evidence: EvidenceRecord
    result_evidence: EvidenceRecord
    finding_count: int
    reused_existing_findings: bool = False


@dataclass(frozen=True)
class FinalizedSqlmapResult:
    """One-step local import and sanitized offline analysis result."""

    imported: ImportedSqlmapResult
    analyzed: AnalyzedSqlmapResult
    selected_result_path: str


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def _write_bytes_atomically(
    payload: bytes,
    *,
    destination: Path,
) -> tuple[str, str, int]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, destination)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise

    digest = hashlib.sha256(payload).hexdigest()
    return str(destination), digest, len(payload)


def _existing_handoff(
    database: SaarthiDatabase,
    execution_id: str,
) -> EvidenceRecord | None:
    evidence = database.list_evidence(
        execution_id,
        evidence_type=EvidenceType.SQLMAP_HANDOFF_MANIFEST,
    )
    return evidence[-1] if evidence else None


def _load_manifest(evidence: EvidenceRecord) -> dict[str, Any]:
    try:
        manifest_bytes = Path(evidence.path).read_bytes()
        payload = json.loads(manifest_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SqlmapHandoffWorkflowError(
            "Persisted SQLmap handoff manifest could not be verified."
        ) from exc
    if (
        evidence.sha256 is None
        or hashlib.sha256(manifest_bytes).hexdigest()
        != evidence.sha256
    ):
        raise SqlmapHandoffWorkflowError(
            "Persisted SQLmap handoff manifest hash does not match."
        )
    if not isinstance(payload, dict):
        raise SqlmapHandoffWorkflowError(
            "Persisted SQLmap handoff manifest has an invalid shape."
        )
    return payload


def create_sqlmap_handoff(
    database: SaarthiDatabase,
    tracked_preview: TrackedSqlmapPreview,
    *,
    actor: str = "sqlmap-external-handoff",
    evidence_root: Path | None = None,
) -> SqlmapHandoff:
    """Create one signed, non-executable external-result handoff."""

    execution_id = tracked_preview.execution.execution_id
    execution = database.get_execution(execution_id)
    if execution.state is not ExecutionState.PLANNED:
        raise SqlmapHandoffWorkflowError(
            "SQLmap handoff requires a planned preview execution."
        )

    existing = _existing_handoff(database, execution_id)
    if existing is not None:
        payload = _load_manifest(existing)
        return SqlmapHandoff(
            execution=execution,
            preview_evidence=tracked_preview.evidence,
            manifest_evidence=existing,
            handoff_id=str(payload["handoff_id"]),
            result_inbox=str(payload["result_contract"]["inbox"]),
            reused_existing_evidence=True,
        )

    root = evidence_root or DEFAULT_HANDOFF_ROOT
    handoff_id = f"sqlmap-handoff-{uuid4()}"
    result_inbox = root / "inbox" / f"{handoff_id}.result.json"
    preview = tracked_preview.preview
    payload = {
        "schema_version": "1.0",
        "handoff_id": handoff_id,
        "execution_id": execution_id,
        "tool": "sqlmap",
        "mode": "external-manual-result-import",
        "executable_command_included": False,
        "network_activity_performed": False,
        "preview_evidence": {
            "evidence_id": tracked_preview.evidence.evidence_id,
            "sha256": tracked_preview.evidence.sha256,
        },
        "candidate": {
            "method": preview.method.value,
            "target_display_url": preview.target_display_url,
            "target_url_sha256": preview.target_url_sha256,
            "parameter_name": preview.parameter_name,
            "post_parameter_names": list(preview.post_parameter_names),
            "post_content_type": (
                preview.post_content_type.value
                if preview.post_content_type is not None
                else None
            ),
        },
        "scope_controls": {
            "single_candidate": True,
            "request_values_stored": False,
            "automatic_execution": False,
            "automatic_retry": False,
            "prohibited_capabilities": list(
                preview.prohibited_capabilities
            ),
        },
        "result_contract": {
            "inbox": str(result_inbox),
            "accepted_suffixes": sorted(SUPPORTED_RESULT_SUFFIXES),
            "maximum_bytes": MAX_EXTERNAL_RESULT_BYTES,
            "association": "operator_selected_execution_and_manifest",
            "normalized_json_schema": NORMALIZED_RESULT_SCHEMA,
        },
    }
    manifest_bytes = _canonical_json(payload)
    destination = root / "manifests" / f"{handoff_id}.json"

    try:
        path, digest, size = _write_bytes_atomically(
            manifest_bytes,
            destination=destination,
        )
        manifest_evidence = database.add_evidence(
            execution_id,
            EvidenceCreate(
                evidence_type=EvidenceType.SQLMAP_HANDOFF_MANIFEST,
                source="saarthi-sqlmap-external-handoff",
                path=path,
                sha256=digest,
                size_bytes=size,
                content_type="application/json",
                step_id="6C.1-sqlmap-handoff-001",
                tool_name="sqlmap",
                metadata={
                    "phase": "6C.1",
                    "handoff_id": handoff_id,
                    "preview_evidence_id": (
                        tracked_preview.evidence.evidence_id
                    ),
                    "result_inbox": str(result_inbox),
                    "status": "awaiting_external_result",
                    "executable_command_included": False,
                    "executed": False,
                    "network_activity": False,
                },
            ),
            actor=actor,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        destination.unlink(missing_ok=True)
        raise SqlmapHandoffWorkflowError(
            "SQLmap handoff manifest could not be persisted safely."
        ) from exc

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_PREPARED,
        actor=actor,
        message=(
            "[6C.1][sqlmap] External-result handoff created; "
            "workflow will continue asynchronously."
        ),
        details={
            "phase_code": "6C.1",
            "tool": "sqlmap",
            "handoff_id": handoff_id,
            "manifest_evidence_id": manifest_evidence.evidence_id,
            "manifest_sha256": manifest_evidence.sha256,
            "result_inbox": str(result_inbox),
            "status": "awaiting_external_result",
            "executed": False,
            "network_activity": False,
            "subprocess_started": False,
        },
    )

    return SqlmapHandoff(
        execution=execution,
        preview_evidence=tracked_preview.evidence,
        manifest_evidence=manifest_evidence,
        handoff_id=handoff_id,
        result_inbox=str(result_inbox),
    )


def _result_suffix(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix:
        return suffix
    if path.name.lower() == "log":
        return ".log"
    return ""


def select_sqlmap_result_file(result_path: Path) -> Path:
    """Resolve a supported result file from a file or SQLmap output directory."""

    candidate = result_path.expanduser()
    if candidate.is_symlink():
        raise SqlmapHandoffWorkflowError(
            "SQLmap external result path must not be a symbolic link."
        )
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise SqlmapHandoffWorkflowError(
            "SQLmap external result path does not exist."
        ) from exc
    if resolved.is_file():
        return resolved
    if not resolved.is_dir():
        raise SqlmapHandoffWorkflowError(
            "SQLmap external result must be a file or directory."
        )

    raw_log = resolved / "log"
    if raw_log.is_file() and not raw_log.is_symlink():
        return raw_log

    supported = sorted(
        path
        for path in resolved.rglob("*")
        if (
            path.is_file()
            and not path.is_symlink()
            and _result_suffix(path) in SUPPORTED_RESULT_SUFFIXES
        )
    )
    if not supported:
        raise SqlmapHandoffWorkflowError(
            "SQLmap result directory contains no supported result file."
        )
    if len(supported) > 1:
        raise SqlmapHandoffWorkflowError(
            "SQLmap result directory is ambiguous; supply one result file."
        )
    return supported[0]


def _validate_result_path(result_path: Path) -> tuple[Path, int, str]:
    candidate = result_path.expanduser()
    if candidate.is_symlink():
        raise SqlmapHandoffWorkflowError(
            "SQLmap external result must not be a symbolic link."
        )
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise SqlmapHandoffWorkflowError(
            "SQLmap external result file does not exist."
        ) from exc
    if not resolved.is_file():
        raise SqlmapHandoffWorkflowError(
            "SQLmap external result must be a regular file."
        )
    if _result_suffix(resolved) not in SUPPORTED_RESULT_SUFFIXES:
        raise SqlmapHandoffWorkflowError(
            "SQLmap external result has an unsupported file type."
        )
    size = resolved.stat().st_size
    if not 1 <= size <= MAX_EXTERNAL_RESULT_BYTES:
        raise SqlmapHandoffWorkflowError(
            "SQLmap external result must be between 1 byte and 16 MiB."
        )
    digest = hashlib.sha256()
    with resolved.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return resolved, size, digest.hexdigest()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bounded_result_text(
    value: object,
    *,
    field: str,
    maximum: int,
) -> str:
    candidate = str(value or "").strip()
    if (
        not candidate
        or len(candidate) > maximum
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in candidate
        )
    ):
        raise SqlmapHandoffWorkflowError(
            f"Normalized SQLmap finding has an invalid {field}."
        )
    return candidate


def _load_normalized_findings(
    result_path: Path,
    *,
    execution_id: str,
    manifest: dict[str, Any],
    manifest_evidence: EvidenceRecord,
) -> tuple[dict[str, str], ...]:
    if result_path.suffix.lower() != ".json":
        return ()
    try:
        payload = json.loads(result_path.read_text("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return ()
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != NORMALIZED_RESULT_SCHEMA
    ):
        return ()
    if payload.get("execution_id") != execution_id:
        raise SqlmapHandoffWorkflowError(
            "Normalized SQLmap result belongs to another execution."
        )
    if payload.get("manifest_sha256") != manifest_evidence.sha256:
        raise SqlmapHandoffWorkflowError(
            "Normalized SQLmap result manifest hash does not match."
        )

    raw_findings = payload.get("findings")
    if not isinstance(raw_findings, list):
        raise SqlmapHandoffWorkflowError(
            "Normalized SQLmap result findings must be a list."
        )
    if len(raw_findings) > MAX_NORMALIZED_FINDINGS:
        raise SqlmapHandoffWorkflowError(
            "Normalized SQLmap result exceeds the 50-finding limit."
        )

    candidate = manifest.get("candidate")
    if not isinstance(candidate, dict):
        raise SqlmapHandoffWorkflowError(
            "SQLmap handoff candidate metadata is invalid."
        )
    allowed_parameters = {
        str(candidate.get("parameter_name") or "")
    }
    post_names = candidate.get("post_parameter_names")
    if isinstance(post_names, list):
        allowed_parameters.update(str(item) for item in post_names)

    findings: list[dict[str, str]] = []
    for raw in raw_findings:
        if not isinstance(raw, dict):
            raise SqlmapHandoffWorkflowError(
                "Normalized SQLmap finding must be an object."
            )
        parameter = _bounded_result_text(
            raw.get("parameter"),
            field="parameter",
            maximum=128,
        )
        if parameter not in allowed_parameters:
            raise SqlmapHandoffWorkflowError(
                "Normalized SQLmap finding is outside the approved "
                "parameter set."
            )
        confidence = _bounded_result_text(
            raw.get("confidence"),
            field="confidence",
            maximum=16,
        ).lower()
        if confidence not in _ALLOWED_CONFIDENCE:
            raise SqlmapHandoffWorkflowError(
                "Normalized SQLmap finding confidence is invalid."
            )
        findings.append(
            {
                "parameter": parameter,
                "technique": _bounded_result_text(
                    raw.get("technique"),
                    field="technique",
                    maximum=80,
                ),
                "dbms": _bounded_result_text(
                    raw.get("dbms", "unknown"),
                    field="dbms",
                    maximum=80,
                ),
                "confidence": confidence,
            }
        )
    return tuple(findings)


_LOG_PARAMETER = re.compile(
    r"^Parameter:\s+([A-Za-z0-9_.\[\]-]{1,128})\s+\((GET|POST)\)\s*$"
)
_LOG_TECHNIQUE = re.compile(r"^\s+Type:\s+(.{1,80})\s*$")
_LOG_DBMS = re.compile(r"^back-end DBMS:\s+(.{1,80})\s*$")


def _allowed_manifest_parameters(
    manifest: dict[str, Any],
) -> set[str]:
    candidate = manifest.get("candidate")
    if not isinstance(candidate, dict):
        raise SqlmapHandoffWorkflowError(
            "SQLmap handoff candidate metadata is invalid."
        )
    allowed = {str(candidate.get("parameter_name") or "")}
    post_names = candidate.get("post_parameter_names")
    if isinstance(post_names, list):
        allowed.update(str(item) for item in post_names)
    return {item for item in allowed if item}


def _load_sanitized_log_findings(
    result_path: Path,
    *,
    manifest: dict[str, Any],
) -> tuple[dict[str, str], ...]:
    if _result_suffix(result_path) not in {".log", ".txt"}:
        return ()
    try:
        lines = result_path.read_text(
            "utf-8",
            errors="replace",
        ).splitlines()
    except OSError as exc:
        raise SqlmapHandoffWorkflowError(
            "Imported SQLmap text result could not be analyzed."
        ) from exc

    allowed_parameters = _allowed_manifest_parameters(manifest)
    current_parameter: str | None = None
    current_method: str | None = None
    pending: list[dict[str, str]] = []
    dbms = "unknown"

    for line in lines:
        parameter_match = _LOG_PARAMETER.match(line)
        if parameter_match is not None:
            parameter = parameter_match.group(1)
            if parameter in allowed_parameters:
                current_parameter = parameter
                current_method = parameter_match.group(2)
            else:
                current_parameter = None
                current_method = None
            continue

        technique_match = _LOG_TECHNIQUE.match(line)
        if (
            technique_match is not None
            and current_parameter is not None
            and current_method is not None
        ):
            pending.append(
                {
                    "parameter": current_parameter,
                    "method": current_method,
                    "technique": _bounded_result_text(
                        technique_match.group(1),
                        field="technique",
                        maximum=80,
                    ),
                    "dbms": "unknown",
                    "confidence": "medium",
                }
            )
            continue

        dbms_match = _LOG_DBMS.match(line)
        if dbms_match is not None:
            dbms = _bounded_result_text(
                dbms_match.group(1),
                field="dbms",
                maximum=80,
            )

    unique: dict[tuple[str, str, str], dict[str, str]] = {}
    for finding in pending[:MAX_NORMALIZED_FINDINGS]:
        finding["dbms"] = dbms
        key = (
            finding["parameter"],
            finding["method"],
            finding["technique"],
        )
        unique[key] = finding
    return tuple(unique.values())


def _external_findings(
    result_path: Path,
    *,
    execution_id: str,
    manifest: dict[str, Any],
    manifest_evidence: EvidenceRecord,
) -> tuple[dict[str, str], ...]:
    normalized = _load_normalized_findings(
        result_path,
        execution_id=execution_id,
        manifest=manifest,
        manifest_evidence=manifest_evidence,
    )
    if normalized:
        return tuple(
            {
                **finding,
                "method": str(
                    manifest["candidate"].get("method") or "unknown"
                ),
            }
            for finding in normalized
        )
    return _load_sanitized_log_findings(
        result_path,
        manifest=manifest,
    )


def _register_external_findings(
    database: SaarthiDatabase,
    execution_id: str,
    *,
    actor: str,
    result_evidence: EvidenceRecord,
    findings: tuple[dict[str, str], ...],
) -> int:
    for finding in findings:
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.FINDING_CREATED,
            actor=actor,
            message=(
                "[6C.1][sqlmap] Sanitized external finding "
                "registered for review."
            ),
            details={
                "phase_code": "6C.1",
                "tool": "sqlmap",
                "result_evidence_id": result_evidence.evidence_id,
                "parameter": finding["parameter"],
                "method": finding.get("method", "unknown"),
                "technique": finding["technique"],
                "dbms": finding["dbms"],
                "confidence": finding["confidence"],
                "source": "operator_supplied_external_result",
                "confirmed_by_saarthi": False,
                "payload_stored_in_finding": False,
            },
        )
    return len(findings)


def import_sqlmap_external_result(
    database: SaarthiDatabase,
    execution_id: str,
    result_path: Path,
    *,
    actor: str = "sqlmap-external-result-importer",
    evidence_root: Path | None = None,
) -> ImportedSqlmapResult:
    """Import one operator-produced result without launching SQLmap."""

    execution = database.get_execution(execution_id)
    manifest_evidence = _existing_handoff(database, execution_id)
    if manifest_evidence is None:
        raise SqlmapHandoffWorkflowError(
            "No SQLmap handoff manifest exists for this execution."
        )
    manifest = _load_manifest(manifest_evidence)
    if manifest.get("execution_id") != execution_id:
        raise SqlmapHandoffWorkflowError(
            "SQLmap handoff manifest belongs to another execution."
        )

    resolved, size, digest = _validate_result_path(result_path)
    normalized_findings = _external_findings(
        resolved,
        execution_id=execution_id,
        manifest=manifest,
        manifest_evidence=manifest_evidence,
    )
    existing_results = database.list_evidence(
        execution_id,
        evidence_type=EvidenceType.SQLMAP_EXTERNAL_RESULT,
    )
    for existing in existing_results:
        if existing.sha256 == digest:
            return ImportedSqlmapResult(
                execution=execution,
                manifest_evidence=manifest_evidence,
                result_evidence=existing,
                reused_existing_evidence=True,
            )

    if execution.state is not ExecutionState.PLANNED:
        raise SqlmapHandoffWorkflowError(
            "SQLmap result import requires an awaiting planned execution."
        )

    execution = database.transition_execution(
        execution_id,
        ExecutionState.RUNNING,
        actor=actor,
        reason="Local SQLmap external-result import started.",
    )
    destination_root = evidence_root or DEFAULT_IMPORT_ROOT
    destination = (
        destination_root
        / execution_id
        / f"external-result-{uuid4()}{_result_suffix(resolved)}"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)

    registered = False
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".sqlmap-result-",
            suffix=".tmp",
            dir=destination.parent,
        )
        os.close(descriptor)
        temporary_path = Path(temporary_name)
        try:
            shutil.copyfile(resolved, temporary_path)
            with temporary_path.open("rb") as handle:
                os.fsync(handle.fileno())
            if (
                temporary_path.stat().st_size != size
                or _sha256_path(temporary_path) != digest
            ):
                raise SqlmapHandoffWorkflowError(
                    "SQLmap external result changed during import."
                )
            os.replace(temporary_path, destination)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise

        content_type = (
            "application/json"
            if resolved.suffix.lower() in {".json", ".jsonl"}
            else "text/plain"
        )
        result_evidence = database.add_evidence(
            execution_id,
            EvidenceCreate(
                evidence_type=EvidenceType.SQLMAP_EXTERNAL_RESULT,
                source="operator-supplied-sqlmap-result",
                path=str(destination),
                sha256=digest,
                size_bytes=size,
                content_type=content_type,
                step_id="6C.1-sqlmap-external-result-001",
                tool_name="sqlmap",
                metadata={
                    "phase": "6C.1",
                    "manifest_evidence_id": (
                        manifest_evidence.evidence_id
                    ),
                    "manifest_sha256": manifest_evidence.sha256,
                    "source_filename": resolved.name,
                    "imported_locally": True,
                    "tool_launched_by_saarthi": False,
                    "network_activity_by_saarthi": False,
                    "status": "imported",
                    "normalized_finding_count": len(
                        normalized_findings
                    ),
                },
            ),
            actor=actor,
        )
        registered = True

        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_OUTPUT,
            actor=actor,
            message=(
                "[6C.1][sqlmap] Operator-supplied result imported "
                "and associated with the handoff manifest."
            ),
            details={
                "phase_code": "6C.1",
                "tool": "sqlmap",
                "manifest_evidence_id": manifest_evidence.evidence_id,
                "result_evidence_id": result_evidence.evidence_id,
                "result_sha256": digest,
                "result_size_bytes": size,
                "tool_launched_by_saarthi": False,
                "network_activity_by_saarthi": False,
            },
        )
        _register_external_findings(
            database,
            execution_id,
            actor=actor,
            result_evidence=result_evidence,
            findings=normalized_findings,
        )
        execution = database.transition_execution(
            execution_id,
            ExecutionState.ANALYZING,
            actor=actor,
            reason="Imported SQLmap evidence is ready for analysis.",
        )
        execution = database.transition_execution(
            execution_id,
            ExecutionState.COMPLETED,
            actor=actor,
            reason="SQLmap external-result import completed.",
        )
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message=(
                "[6C.1][sqlmap] External-result import completed; "
                "no SQLmap subprocess was launched by Saarthi."
            ),
            details={
                "phase_code": "6C.1",
                "tool": "sqlmap",
                "result_evidence_id": result_evidence.evidence_id,
                "status": "imported",
                "normalized_finding_count": len(
                    normalized_findings
                ),
                "executed_by_saarthi": False,
                "network_activity_by_saarthi": False,
            },
        )
    except (OSError, RuntimeError, ValueError) as exc:
        if not registered:
            destination.unlink(missing_ok=True)
        fail_execution_safely(
            database,
            execution_id,
            actor=actor,
            reason="SQLmap external-result import failed safely.",
        )
        raise SqlmapHandoffWorkflowError(
            "SQLmap external result could not be imported safely."
        ) from exc

    return ImportedSqlmapResult(
        execution=execution,
        manifest_evidence=manifest_evidence,
        result_evidence=result_evidence,
    )


def analyze_imported_sqlmap_result(
    database: SaarthiDatabase,
    execution_id: str,
    *,
    actor: str = "sqlmap-offline-result-analyzer",
) -> AnalyzedSqlmapResult:
    """Backfill sanitized findings from already-imported evidence."""

    execution = database.get_execution(execution_id)
    manifest_evidence = _existing_handoff(database, execution_id)
    if manifest_evidence is None:
        raise SqlmapHandoffWorkflowError(
            "No SQLmap handoff manifest exists for this execution."
        )
    manifest = _load_manifest(manifest_evidence)
    if manifest.get("execution_id") != execution_id:
        raise SqlmapHandoffWorkflowError(
            "SQLmap handoff manifest belongs to another execution."
        )

    results = database.list_evidence(
        execution_id,
        evidence_type=EvidenceType.SQLMAP_EXTERNAL_RESULT,
    )
    if not results:
        raise SqlmapHandoffWorkflowError(
            "No imported SQLmap result exists for this execution."
        )
    result_evidence = results[-1]
    result_path = Path(result_evidence.path)
    if (
        result_evidence.sha256 is None
        or not result_path.is_file()
        or _sha256_path(result_path) != result_evidence.sha256
    ):
        raise SqlmapHandoffWorkflowError(
            "Imported SQLmap result evidence hash does not match."
        )

    existing = [
        event
        for event in database.list_audit_events(execution_id)
        if (
            event.event_type is AuditEventType.FINDING_CREATED
            and event.details.get("result_evidence_id")
            == result_evidence.evidence_id
        )
    ]
    if existing:
        return AnalyzedSqlmapResult(
            execution=execution,
            manifest_evidence=manifest_evidence,
            result_evidence=result_evidence,
            finding_count=len(existing),
            reused_existing_findings=True,
        )

    findings = _external_findings(
        result_path,
        execution_id=execution_id,
        manifest=manifest,
        manifest_evidence=manifest_evidence,
    )
    finding_count = _register_external_findings(
        database,
        execution_id,
        actor=actor,
        result_evidence=result_evidence,
        findings=findings,
    )
    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_COMPLETED,
        actor=actor,
        message=(
            "[6C.1][sqlmap] Offline sanitized result analysis completed."
        ),
        details={
            "phase_code": "6C.1",
            "tool": "sqlmap",
            "result_evidence_id": result_evidence.evidence_id,
            "finding_count": finding_count,
            "payloads_parsed": False,
            "database_contents_parsed": False,
            "network_activity": False,
        },
    )
    return AnalyzedSqlmapResult(
        execution=execution,
        manifest_evidence=manifest_evidence,
        result_evidence=result_evidence,
        finding_count=finding_count,
    )


def finalize_sqlmap_external_result(
    database: SaarthiDatabase,
    execution_id: str,
    result_path: Path,
    *,
    actor: str = "sqlmap-external-result-finalizer",
    evidence_root: Path | None = None,
) -> FinalizedSqlmapResult:
    """Select, import, hash, and analyze one local SQLmap result."""

    selected = select_sqlmap_result_file(result_path)
    imported = import_sqlmap_external_result(
        database,
        execution_id,
        selected,
        actor=actor,
        evidence_root=evidence_root,
    )
    analyzed = analyze_imported_sqlmap_result(
        database,
        execution_id,
        actor=actor,
    )
    return FinalizedSqlmapResult(
        imported=imported,
        analyzed=analyzed,
        selected_result_path=str(selected),
    )
