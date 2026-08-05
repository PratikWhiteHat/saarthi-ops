"""Tracked controlled Nuclei execution using an injected bounded runner."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from saarthi_ai.execution.nuclei_execution_models import (
    NucleiExecutionResult,
    NucleiExecutionResultError,
)
from saarthi_ai.execution.tool_runner import (
    ToolOutputEvent,
    ToolRunnerError,
    ToolRunResult,
)
from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.http_workflow import (
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
from saarthi_ai.persistence.nuclei_execution_verification import (
    NucleiExecutionVerificationError,
    NucleiExecutionVerificationRequest,
    VerifiedNucleiPreparation,
    verify_persisted_nuclei_preparation,
)

DEFAULT_EVIDENCE_ROOT = (
    Path("evidence") / "controlled-nuclei-executions"
)

RunnerCallable = Callable[..., ToolRunResult]


class NucleiExecutionWorkflowError(RuntimeError):
    """Raised when controlled Nuclei execution fails safely."""


@dataclass(frozen=True)
class TrackedNucleiExecution:
    """Persisted successful controlled Nuclei execution."""

    execution: ExecutionRecord
    verified_preparation: VerifiedNucleiPreparation
    result: NucleiExecutionResult
    evidence: EvidenceRecord


def _write_evidence_atomically(
    payload: dict[str, object],
    *,
    evidence_root: Path | None = None,
) -> tuple[str, str, int]:
    """Write one bounded Nuclei execution evidence file atomically."""

    directory = evidence_root or DEFAULT_EVIDENCE_ROOT
    directory.mkdir(parents=True, exist_ok=True)

    evidence_id = f"controlled-nuclei-execution-{uuid4()}"
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
            prefix=".controlled-nuclei-execution-",
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


def _validate_runner_result(
    verified: VerifiedNucleiPreparation,
    result: ToolRunResult,
    *,
    started_at: datetime,
    completed_at: datetime,
) -> NucleiExecutionResult:
    """Bind runner output to the exact verified preparation."""

    if result.tool_name != verified.binding.profile.name:
        raise NucleiExecutionWorkflowError(
            "Runner result tool identity does not match Nuclei."
        )

    if result.arguments != verified.binding.arguments:
        raise NucleiExecutionWorkflowError(
            "Runner result arguments do not match verified preparation."
        )

    stdout_bytes = len(result.stdout.encode("utf-8"))
    stderr_bytes = len(result.stderr.encode("utf-8"))

    if stdout_bytes > verified.binding.profile.max_output_bytes:
        raise NucleiExecutionWorkflowError(
            "Runner stdout exceeds the approved output limit."
        )

    if stderr_bytes > verified.binding.profile.max_output_bytes:
        raise NucleiExecutionWorkflowError(
            "Runner stderr exceeds the approved output limit."
        )

    try:
        return NucleiExecutionResult(
            tool_name=result.tool_name,
            target_url=verified.plan.target_url,
            preparation_evidence_id=(
                verified.evidence.evidence_id
            ),
            executable=result.executable,
            arguments=result.arguments,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            stdout=result.stdout,
            stderr=result.stderr,
            stdout_sha256=result.stdout_sha256,
            stderr_sha256=result.stderr_sha256,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
            stdout_truncated=result.stdout_truncated,
            stderr_truncated=result.stderr_truncated,
            started_at=started_at,
            completed_at=completed_at,
            automatic_retry=False,
        )
    except NucleiExecutionResultError as exc:
        raise NucleiExecutionWorkflowError(
            "Runner result violates the bounded Nuclei contract."
        ) from exc


def _serialize_execution(
    execution_id: str,
    *,
    verified: VerifiedNucleiPreparation,
    result: NucleiExecutionResult,
) -> dict[str, object]:
    """Serialize bounded execution output into an evidence file."""

    return {
        "schema_version": "1.0",
        "phase": "6J.3",
        "evidence_type": (
            EvidenceType.CONTROLLED_NUCLEI_EXECUTION.value
        ),
        "execution_id": execution_id,
        "preparation": {
            "evidence_id": verified.evidence.evidence_id,
            "sha256": verified.evidence.sha256,
        },
        "tool": {
            "name": result.tool_name,
            "target_url": result.target_url,
            "executable": result.executable,
            "arguments": list(result.arguments),
        },
        "runtime": {
            "started_at": result.started_at.isoformat(),
            "completed_at": result.completed_at.isoformat(),
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "automatic_retry": result.automatic_retry,
        },
        "stdout": {
            "content": result.stdout,
            "sha256": result.stdout_sha256,
            "size_bytes": result.stdout_bytes,
            "truncated": result.stdout_truncated,
        },
        "stderr": {
            "content": result.stderr,
            "sha256": result.stderr_sha256,
            "size_bytes": result.stderr_bytes,
            "truncated": result.stderr_truncated,
        },
        "execution": {
            "executed": True,
            "network_activity": True,
            "subprocess_started": True,
            "runner_invoked": True,
            "executable_resolved": True,
            "automatic_retry": False,
        },
    }


def _record_failure(
    database: SaarthiDatabase,
    execution_id: str,
    *,
    actor: str,
    error: Exception,
    runner_invoked: bool,
    evidence_path: str | None,
    evidence_registered: bool,
) -> None:
    """Record one bounded failure event without masking the cause."""

    orphan_removed = False

    if evidence_path is not None and not evidence_registered:
        try:
            Path(evidence_path).unlink(missing_ok=True)
            orphan_removed = not Path(evidence_path).exists()
        except OSError:
            orphan_removed = False

    try:
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message=(
                "[6J.3][nuclei] Controlled Nuclei execution "
                "failed safely."
            ),
            details={
                "phase_code": "6J.3",
                "tool": "nuclei",
                "error_type": type(error).__name__,
                "error": str(error),
                "runner_invoked": runner_invoked,
                "automatic_retry": False,
                "evidence_registered": evidence_registered,
                "orphan_file_removed": orphan_removed,
            },
        )
    except RuntimeError:
        pass


def run_tracked_nuclei_execution(
    database: SaarthiDatabase,
    execution_id: str,
    request: NucleiExecutionVerificationRequest,
    *,
    runner: RunnerCallable,
    actor: str = "controlled-nuclei-executor",
    evidence_root: Path | None = None,
) -> TrackedNucleiExecution:
    """Execute exactly one verified Nuclei preparation."""

    verified = verify_persisted_nuclei_preparation(
        database,
        execution_id,
        request,
    )

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.APPROVAL_RECORDED,
        actor=actor,
        message=(
            "[6J.3][nuclei] Fresh explicit operator approval "
            "recorded for controlled execution."
        ),
        details={
            "phase_code": "6J.3",
            "tool": "nuclei",
            "preparation_evidence_id": (
                verified.evidence.evidence_id
            ),
            "explicitly_approved": True,
            "automatic_retry": False,
        },
    )

    execution = database.transition_execution(
        execution_id,
        ExecutionState.RUNNING,
        actor=actor,
        reason="Verified controlled Nuclei execution started.",
    )

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_STARTED,
        actor=actor,
        message="[6J.3][nuclei] Bounded Nuclei runner invoked.",
        details={
            "phase_code": "6J.3",
            "tool": "nuclei",
            "target_url": verified.plan.target_url,
            "arguments": list(verified.binding.arguments),
            "preparation_evidence_id": (
                verified.evidence.evidence_id
            ),
            "process_timeout_seconds": (
                verified.binding.profile.timeout_seconds
            ),
            "max_output_bytes_per_stream": (
                verified.binding.profile.max_output_bytes
            ),
            "runner_invoked": True,
            "automatic_retry": False,
        },
    )

    output_sequence = 0
    maximum_output_events = 200

    def record_output(event: ToolOutputEvent) -> None:
        """Record bounded output metadata without copying lines to audit."""

        nonlocal output_sequence

        if output_sequence >= maximum_output_events:
            return

        output_sequence += 1

        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_OUTPUT,
            actor=actor,
            message=(
                f"[6J.3][nuclei][{event.stream}] "
                f"Bounded output event {output_sequence}."
            ),
            details={
                "phase_code": "6J.3",
                "tool": "nuclei",
                "stream": event.stream,
                "sequence": output_sequence,
                "line_length": len(event.line),
                "content_persisted_in_evidence": True,
            },
        )

    runner_invoked = False
    evidence_path: str | None = None
    evidence_registered = False

    try:
        started_at = datetime.now(UTC)
        runner_invoked = True

        tool_result = runner(
            verified.binding.profile,
            list(verified.binding.arguments),
            on_output=record_output,
        )

        completed_at = datetime.now(UTC)

        result = _validate_runner_result(
            verified,
            tool_result,
            started_at=started_at,
            completed_at=completed_at,
        )

        payload = _serialize_execution(
            execution_id,
            verified=verified,
            result=result,
        )

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
                    EvidenceType.CONTROLLED_NUCLEI_EXECUTION
                ),
                source="saarthi-controlled-nuclei-execution",
                path=evidence_path,
                sha256=evidence_sha256,
                size_bytes=evidence_size,
                content_type="application/json",
                step_id="controlled-nuclei-execution-001",
                tool_name="nuclei",
                metadata={
                    "phase": "6J.3",
                    "target_url": result.target_url,
                    "arguments": list(result.arguments),
                    "preparation_evidence_id": (
                        result.preparation_evidence_id
                    ),
                    "executable": result.executable,
                    "exit_code": result.exit_code,
                    "timed_out": result.timed_out,
                    "stdout_sha256": result.stdout_sha256,
                    "stderr_sha256": result.stderr_sha256,
                    "stdout_bytes": result.stdout_bytes,
                    "stderr_bytes": result.stderr_bytes,
                    "stdout_truncated": (
                        result.stdout_truncated
                    ),
                    "stderr_truncated": (
                        result.stderr_truncated
                    ),
                    "started_at": result.started_at.isoformat(),
                    "completed_at": (
                        result.completed_at.isoformat()
                    ),
                    "executed": True,
                    "network_activity": True,
                    "subprocess_started": True,
                    "runner_invoked": True,
                    "executable_resolved": True,
                    "automatic_retry": False,
                },
            ),
            actor=actor,
        )
        evidence_registered = True

        if result.timed_out:
            raise NucleiExecutionWorkflowError(
                "Controlled Nuclei execution timed out."
            )

        if result.exit_code != 0:
            raise NucleiExecutionWorkflowError(
                "Controlled Nuclei execution returned "
                f"exit code {result.exit_code}."
            )

        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message=(
                "[6J.3][nuclei] Controlled Nuclei execution "
                "completed and evidence was persisted."
            ),
            details={
                "phase_code": "6J.3",
                "tool": "nuclei",
                "evidence_id": evidence.evidence_id,
                "evidence_sha256": evidence.sha256,
                "preparation_evidence_id": (
                    verified.evidence.evidence_id
                ),
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "automatic_retry": False,
            },
        )

        execution = database.transition_execution(
            execution_id,
            ExecutionState.ANALYZING,
            actor=actor,
            reason="Controlled Nuclei evidence is ready for analysis.",
        )

        execution = database.transition_execution(
            execution_id,
            ExecutionState.COMPLETED,
            actor=actor,
            reason="Phase 6J.3 controlled Nuclei execution completed.",
        )

        return TrackedNucleiExecution(
            execution=execution,
            verified_preparation=verified,
            result=result,
            evidence=evidence,
        )

    except (
        InvalidStateTransitionError,
        NucleiExecutionVerificationError,
        NucleiExecutionWorkflowError,
        NucleiExecutionResultError,
        ToolRunnerError,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        _record_failure(
            database,
            execution_id,
            actor=actor,
            error=exc,
            runner_invoked=runner_invoked,
            evidence_path=evidence_path,
            evidence_registered=evidence_registered,
        )

        fail_execution_safely(
            database,
            execution_id,
            actor=actor,
            reason=str(exc),
        )

        if isinstance(exc, NucleiExecutionWorkflowError):
            raise

        raise NucleiExecutionWorkflowError(
            "Controlled Nuclei execution failed safely."
        ) from exc
