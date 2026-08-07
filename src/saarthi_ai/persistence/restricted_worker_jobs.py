"""Persistent control plane for non-executing restricted worker jobs."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from uuid import uuid4

from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import AuditEventType, utc_now

WORKER_JOB_SCHEMA = "saarthi.restricted-worker-job.v1"
ALLOWED_TOOLS = frozenset({"mock", "nuclei", "sqlmap", "ffuf", "callback"})


class WorkerJobError(RuntimeError):
    """Raised when a restricted worker job fails closed."""


class WorkerJobState(StrEnum):
    CREATED = "created"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    DISPATCHED = "dispatched"
    RUNNING = "running"
    RESULT_READY = "result_ready"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


TERMINAL_STATES = frozenset(
    {
        WorkerJobState.COMPLETED,
        WorkerJobState.FAILED,
        WorkerJobState.CANCELLED,
        WorkerJobState.EXPIRED,
    }
)

ALLOWED_TRANSITIONS: dict[WorkerJobState, frozenset[WorkerJobState]] = {
    WorkerJobState.CREATED: frozenset(
        {WorkerJobState.AWAITING_APPROVAL, WorkerJobState.CANCELLED}
    ),
    WorkerJobState.AWAITING_APPROVAL: frozenset(
        {
            WorkerJobState.APPROVED,
            WorkerJobState.CANCELLED,
            WorkerJobState.EXPIRED,
        }
    ),
    WorkerJobState.APPROVED: frozenset(
        {
            WorkerJobState.DISPATCHED,
            WorkerJobState.CANCELLED,
            WorkerJobState.EXPIRED,
        }
    ),
    WorkerJobState.DISPATCHED: frozenset(
        {WorkerJobState.RUNNING, WorkerJobState.FAILED, WorkerJobState.CANCELLED}
    ),
    WorkerJobState.RUNNING: frozenset(
        {
            WorkerJobState.RESULT_READY,
            WorkerJobState.FAILED,
            WorkerJobState.CANCELLED,
        }
    ),
    WorkerJobState.RESULT_READY: frozenset(
        {WorkerJobState.COMPLETED, WorkerJobState.FAILED}
    ),
    WorkerJobState.COMPLETED: frozenset(),
    WorkerJobState.FAILED: frozenset(),
    WorkerJobState.CANCELLED: frozenset(),
    WorkerJobState.EXPIRED: frozenset(),
}


@dataclass(frozen=True)
class WorkerJobRecord:
    job_id: str
    execution_id: str
    tool_name: str
    adapter_name: str
    state: WorkerJobState
    manifest: dict[str, Any]
    manifest_sha256: str
    approval_actor: str | None
    approval_reason: str | None
    result: dict[str, Any] | None
    created_at: str
    updated_at: str


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
    )


def initialize_worker_schema(database: SaarthiDatabase) -> None:
    """Create the additive restricted-worker control-plane table."""

    database.initialize()
    with database.connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS restricted_worker_jobs (
                job_id TEXT PRIMARY KEY,
                execution_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                adapter_name TEXT NOT NULL,
                state TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                manifest_sha256 TEXT NOT NULL,
                approval_actor TEXT,
                approval_reason TEXT,
                result_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (execution_id)
                    REFERENCES executions(execution_id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_worker_jobs_execution
                ON restricted_worker_jobs(execution_id);

            CREATE INDEX IF NOT EXISTS idx_worker_jobs_state
                ON restricted_worker_jobs(state);
            """
        )


def create_worker_job(
    database: SaarthiDatabase,
    execution_id: str,
    *,
    tool_name: str,
    target_display: str,
    purpose: str,
    timeout_seconds: int,
    rate_limit_per_second: int,
    adapter_name: str = "unbound",
    actor: str = "restricted-worker-control-plane",
) -> WorkerJobRecord:
    """Create an immutable descriptive job; never accept executable arguments."""

    initialize_worker_schema(database)
    execution = database.get_execution(execution_id)
    normalized_tool = tool_name.strip().lower()
    if normalized_tool not in ALLOWED_TOOLS:
        raise WorkerJobError("Worker tool is not registered.")
    if not 1 <= timeout_seconds <= 3_600:
        raise WorkerJobError("Worker timeout must be between 1 and 3600 seconds.")
    if not 1 <= rate_limit_per_second <= 100:
        raise WorkerJobError("Worker rate limit must be between 1 and 100 requests/second.")
    if not target_display.strip() or len(target_display) > 2_048:
        raise WorkerJobError("Worker target display value is invalid.")
    if not purpose.strip() or len(purpose) > 500:
        raise WorkerJobError("Worker purpose is invalid.")

    job_id = f"worker-job-{uuid4()}"
    timestamp = utc_now().isoformat()
    manifest = {
        "schema": WORKER_JOB_SCHEMA,
        "job_id": job_id,
        "execution_id": execution_id,
        "tool_name": normalized_tool,
        "adapter_name": adapter_name,
        "target_display": target_display.strip(),
        "purpose": purpose.strip(),
        "limits": {
            "timeout_seconds": timeout_seconds,
            "rate_limit_per_second": rate_limit_per_second,
        },
        "authorization": {
            "execution_authorized": execution.authorization_confirmed,
            "approval_required": True,
        },
        "execution_contract": {
            "command_included": False,
            "arguments_included": False,
            "raw_shell_allowed": False,
            "automatic_retry": False,
        },
    }
    manifest_json = _canonical_json(manifest)
    manifest_sha256 = hashlib.sha256(manifest_json.encode()).hexdigest()

    with database.connect() as connection:
        connection.execute(
            """
            INSERT INTO restricted_worker_jobs (
                job_id, execution_id, tool_name, adapter_name, state,
                manifest_json, manifest_sha256, approval_actor,
                approval_reason, result_json, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)
            """,
            (
                job_id,
                execution_id,
                normalized_tool,
                adapter_name,
                WorkerJobState.AWAITING_APPROVAL.value,
                manifest_json,
                manifest_sha256,
                timestamp,
                timestamp,
            ),
        )

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_PREPARED,
        actor=actor,
        message="Restricted worker job prepared; no tool was launched.",
        details={
            "job_id": job_id,
            "tool": normalized_tool,
            "state": WorkerJobState.AWAITING_APPROVAL.value,
            "manifest_sha256": manifest_sha256,
            "command_included": False,
        },
    )
    return get_worker_job(database, job_id)


def get_worker_job(
    database: SaarthiDatabase,
    job_id: str,
) -> WorkerJobRecord:
    initialize_worker_schema(database)
    with database.connect() as connection:
        row = connection.execute(
            "SELECT * FROM restricted_worker_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
    if row is None:
        raise WorkerJobError(f"Worker job '{job_id}' was not found.")
    return _record_from_row(row)


def list_worker_jobs(
    database: SaarthiDatabase,
    *,
    execution_id: str | None = None,
    limit: int = 100,
) -> list[WorkerJobRecord]:
    initialize_worker_schema(database)
    if not 1 <= limit <= 1_000:
        raise WorkerJobError("Worker job list limit must be between 1 and 1000.")
    query = "SELECT * FROM restricted_worker_jobs"
    parameters: list[object] = []
    if execution_id is not None:
        query += " WHERE execution_id = ?"
        parameters.append(execution_id)
    query += " ORDER BY created_at DESC LIMIT ?"
    parameters.append(limit)
    with database.connect() as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [_record_from_row(row) for row in rows]


def approve_worker_job(
    database: SaarthiDatabase,
    job_id: str,
    *,
    actor: str,
    reason: str,
) -> WorkerJobRecord:
    """Record one explicit approval without dispatching a tool."""

    if not actor.strip() or len(actor) > 100:
        raise WorkerJobError("Approval actor is invalid.")
    if not reason.strip() or len(reason) > 1_000:
        raise WorkerJobError("Approval reason is invalid.")
    current = get_worker_job(database, job_id)
    updated = _transition(
        database,
        current,
        WorkerJobState.APPROVED,
        approval_actor=actor.strip(),
        approval_reason=reason.strip(),
    )
    database.add_audit_event(
        updated.execution_id,
        event_type=AuditEventType.APPROVAL_RECORDED,
        actor=actor.strip(),
        message="Restricted worker job approval recorded.",
        details={
            "job_id": job_id,
            "tool": updated.tool_name,
            "manifest_sha256": updated.manifest_sha256,
            "dispatch_performed": False,
        },
    )
    return updated


def run_mock_worker(
    database: SaarthiDatabase,
    job_id: str,
    *,
    actor: str = "mock-restricted-worker",
) -> WorkerJobRecord:
    """Exercise the lifecycle using an inert adapter with no network activity."""

    current = get_worker_job(database, job_id)
    if current.adapter_name != "mock" or current.tool_name != "mock":
        raise WorkerJobError(
            "Only an inert mock job can be dispatched by this milestone."
        )
    current = _transition(database, current, WorkerJobState.DISPATCHED)
    current = _transition(database, current, WorkerJobState.RUNNING)
    result = {
        "schema": "saarthi.restricted-worker-result.v1",
        "job_id": job_id,
        "adapter": "mock",
        "status": "ok",
        "network_activity": False,
        "subprocess_started": False,
        "findings": [],
    }
    current = _transition(
        database,
        current,
        WorkerJobState.RESULT_READY,
        result=result,
    )
    current = _transition(database, current, WorkerJobState.COMPLETED)
    database.add_audit_event(
        current.execution_id,
        event_type=AuditEventType.TOOL_COMPLETED,
        actor=actor,
        message="Inert restricted-worker lifecycle completed.",
        details={
            "job_id": job_id,
            "tool": "mock",
            "network_activity": False,
            "subprocess_started": False,
        },
    )
    return current


def _transition(
    database: SaarthiDatabase,
    current: WorkerJobRecord,
    new_state: WorkerJobState,
    *,
    approval_actor: str | None = None,
    approval_reason: str | None = None,
    result: dict[str, Any] | None = None,
) -> WorkerJobRecord:
    if new_state not in ALLOWED_TRANSITIONS[current.state]:
        raise WorkerJobError(
            f"Worker job cannot transition from '{current.state}' to '{new_state}'."
        )
    timestamp = utc_now().isoformat()
    with database.connect() as connection:
        cursor = connection.execute(
            """
            UPDATE restricted_worker_jobs
            SET state = ?,
                approval_actor = COALESCE(?, approval_actor),
                approval_reason = COALESCE(?, approval_reason),
                result_json = COALESCE(?, result_json),
                updated_at = ?
            WHERE job_id = ? AND state = ?
            """,
            (
                new_state.value,
                approval_actor,
                approval_reason,
                _canonical_json(result) if result is not None else None,
                timestamp,
                current.job_id,
                current.state.value,
            ),
        )
        if cursor.rowcount != 1:
            raise WorkerJobError("Worker job state changed concurrently.")
    return get_worker_job(database, current.job_id)


def _record_from_row(row: sqlite3.Row) -> WorkerJobRecord:
    manifest_json = str(row["manifest_json"])
    manifest_sha256 = hashlib.sha256(manifest_json.encode()).hexdigest()
    if manifest_sha256 != row["manifest_sha256"]:
        raise WorkerJobError("Worker job manifest integrity check failed.")
    return WorkerJobRecord(
        job_id=str(row["job_id"]),
        execution_id=str(row["execution_id"]),
        tool_name=str(row["tool_name"]),
        adapter_name=str(row["adapter_name"]),
        state=WorkerJobState(str(row["state"])),
        manifest=json.loads(manifest_json),
        manifest_sha256=str(row["manifest_sha256"]),
        approval_actor=(
            str(row["approval_actor"])
            if row["approval_actor"] is not None
            else None
        ),
        approval_reason=(
            str(row["approval_reason"])
            if row["approval_reason"] is not None
            else None
        ),
        result=(
            json.loads(str(row["result_json"]))
            if row["result_json"] is not None
            else None
        ),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )
