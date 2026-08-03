"""Persistent Phase 4A direct vulnerability-check workflow."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

from saarthi_ai.checks.executor import (
    DirectCheckExecutionResult,
    execute_direct_check,
)
from saarthi_ai.checks.models import (
    CheckDecision,
    DirectCheckRequest,
)
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

DEFAULT_EVIDENCE_ROOT = Path("evidence") / "direct-checks"


class DirectCheckWorkflowError(RuntimeError):
    """Raised when a tracked direct check cannot complete safely."""


class TrackedDirectCheckResult:
    """Combined Phase 4A execution, check, and evidence result."""

    def __init__(
        self,
        *,
        execution: ExecutionRecord,
        check: DirectCheckExecutionResult,
        evidence: EvidenceRecord,
    ) -> None:
        self.execution = execution
        self.check = check
        self.evidence = evidence


def _validate_target_scope(
    target_url: str,
    execution: ExecutionRecord,
) -> None:
    parsed = urlparse(target_url)
    hostname = parsed.hostname

    if parsed.scheme not in {"http", "https"} or not hostname:
        raise InvalidStateTransitionError(
            "A valid HTTP or HTTPS target URL is required."
        )

    if not _domain_in_execution_scope(hostname, execution):
        raise InvalidStateTransitionError(
            f"Target '{hostname}' is not associated with this execution."
        )


def _serialize_check_result(
    request: DirectCheckRequest,
    check: DirectCheckExecutionResult,
) -> dict[str, object]:
    result_payload: dict[str, object] | None = None

    if check.result is not None:
        result_payload = asdict(check.result)

    return {
        "schema_version": "1.0",
        "phase": "4A",
        "evidence_type": EvidenceType.DIRECT_CHECK_RESULT.value,
        "collected_at": datetime.now(UTC).isoformat(),
        "request": {
            "execution_id": request.execution_id,
            "target_url": request.target_url,
            "check_id": request.check_id,
            "requested_method": request.requested_method,
            "requested_requests": request.requested_requests,
            "authorized": request.authorized,
            "active_testing": request.active_testing,
            "explicitly_approved": request.explicitly_approved,
        },
        "policy": {
            "decision": check.policy.decision.value,
            "reason": check.policy.reason,
        },
        "execution": {
            "executed": check.executed,
            "error": check.error,
        },
        "result": result_payload,
    }


def _write_evidence_atomically(
    payload: dict[str, object],
    *,
    evidence_root: Path | None = None,
) -> tuple[str, str, int]:
    evidence_directory = evidence_root or DEFAULT_EVIDENCE_ROOT
    evidence_directory.mkdir(parents=True, exist_ok=True)

    evidence_id = f"direct-check-evidence-{uuid4()}"
    evidence_path = evidence_directory / f"{evidence_id}.json"

    serialized = json.dumps(
        payload,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")

    temporary_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=evidence_directory,
            prefix=".direct-check-",
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


def run_tracked_direct_check(
    database: SaarthiDatabase,
    request: DirectCheckRequest,
    *,
    actor: str = "direct-check-executor",
    evidence_root: Path | None = None,
) -> TrackedDirectCheckResult:
    """Run one Phase 4A direct check with persistence and auditing."""

    execution = database.get_execution(request.execution_id)

    if not execution.authorization_confirmed:
        raise InvalidStateTransitionError(
            "Execution does not have confirmed authorization."
        )

    if request.authorized is not True:
        raise InvalidStateTransitionError(
            "Direct-check request does not confirm authorization."
        )

    if request.active_testing and not execution.active_testing_allowed:
        raise InvalidStateTransitionError(
            "Execution does not allow active testing."
        )

    _validate_target_scope(request.target_url, execution)

    execution = advance_execution_to_running(
        database,
        execution,
        actor=actor,
    )

    database.add_audit_event(
        request.execution_id,
        event_type=AuditEventType.TOOL_STARTED,
        actor=actor,
        message="Saarthi Phase 4A direct check started.",
        details={
            "tool": "saarthi-direct-check",
            "check_id": request.check_id,
            "target_url": request.target_url,
            "requested_method": request.requested_method,
            "requested_requests": request.requested_requests,
            "explicitly_approved": request.explicitly_approved,
        },
    )

    try:
        check = asyncio.run(execute_direct_check(request))

        if check.policy.decision is not CheckDecision.ALLOW:
            raise DirectCheckWorkflowError(
                f"Direct check denied by policy: {check.policy.reason}"
            )

        if not check.executed:
            raise DirectCheckWorkflowError(
                check.error or "Direct check was not executed."
            )

        payload = _serialize_check_result(request, check)
        evidence_path, evidence_sha256, evidence_size = (
            _write_evidence_atomically(
                payload,
                evidence_root=evidence_root,
            )
        )

        evidence = database.add_evidence(
            request.execution_id,
            EvidenceCreate(
                evidence_type=EvidenceType.DIRECT_CHECK_RESULT,
                source="saarthi-direct-check",
                path=evidence_path,
                sha256=evidence_sha256,
                size_bytes=evidence_size,
                content_type="application/json",
                step_id="direct-check-001",
                tool_name="saarthi-direct-check",
                metadata={
                    "phase": "4A",
                    "check_id": request.check_id,
                    "target_url": request.target_url,
                    "policy_decision": check.policy.decision.value,
                    "executed": check.executed,
                    "result_error": check.error,
                },
            ),
            actor=actor,
        )

        database.add_audit_event(
            request.execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message="Saarthi Phase 4A direct check completed.",
            details={
                "tool": "saarthi-direct-check",
                "check_id": request.check_id,
                "target_url": request.target_url,
                "evidence_id": evidence.evidence_id,
                "evidence_sha256": evidence_sha256,
            },
        )

        execution = database.transition_execution(
            request.execution_id,
            ExecutionState.ANALYZING,
            actor=actor,
            reason="Phase 4A direct-check evidence is ready for analysis.",
        )

        execution = database.transition_execution(
            request.execution_id,
            ExecutionState.COMPLETED,
            actor=actor,
            reason="Phase 4A direct vulnerability-check workflow completed.",
        )

        return TrackedDirectCheckResult(
            execution=execution,
            check=check,
            evidence=evidence,
        )

    except (
        DirectCheckWorkflowError,
        InvalidStateTransitionError,
    ) as exc:
        database.add_audit_event(
            request.execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message="Saarthi Phase 4A direct check failed.",
            details={
                "tool": "saarthi-direct-check",
                "check_id": request.check_id,
                "target_url": request.target_url,
                "error": str(exc),
            },
        )

        fail_execution_safely(
            database,
            request.execution_id,
            actor=actor,
            reason=str(exc),
        )

        raise
