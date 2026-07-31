from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from saarthi_ai.persistence.models import (
    AuditEventRecord,
    AuditEventType,
    EvidenceCreate,
    EvidenceRecord,
    EvidenceType,
    ExecutionCreate,
    ExecutionRecord,
    ExecutionState,
    utc_now,
)

SAARTHI_HOME = Path.home() / ".saarthi"
DEFAULT_DATABASE_PATH = SAARTHI_HOME / "saarthi.db"


class PersistenceError(RuntimeError):
    """Base error for Saarthi persistence operations."""


class ExecutionNotFoundError(PersistenceError):
    """Raised when an execution record does not exist."""


class InvalidStateTransitionError(PersistenceError):
    """Raised when an execution-state transition is not allowed."""


ALLOWED_STATE_TRANSITIONS: dict[ExecutionState, set[ExecutionState]] = {
    ExecutionState.CREATED: {
        ExecutionState.VALIDATED,
        ExecutionState.FAILED,
        ExecutionState.CANCELLED,
    },
    ExecutionState.VALIDATED: {
        ExecutionState.PLANNED,
        ExecutionState.FAILED,
        ExecutionState.CANCELLED,
    },
    ExecutionState.PLANNED: {
        ExecutionState.AWAITING_APPROVAL,
        ExecutionState.RUNNING,
        ExecutionState.FAILED,
        ExecutionState.CANCELLED,
    },
    ExecutionState.AWAITING_APPROVAL: {
        ExecutionState.RUNNING,
        ExecutionState.FAILED,
        ExecutionState.CANCELLED,
    },
    ExecutionState.RUNNING: {
        ExecutionState.ANALYZING,
        ExecutionState.COMPLETED,
        ExecutionState.FAILED,
        ExecutionState.CANCELLED,
    },
    ExecutionState.ANALYZING: {
        ExecutionState.COMPLETED,
        ExecutionState.FAILED,
        ExecutionState.CANCELLED,
    },
    ExecutionState.COMPLETED: set(),
    ExecutionState.FAILED: set(),
    ExecutionState.CANCELLED: set(),
}


class SaarthiDatabase:
    """SQLite repository for execution, audit, and evidence records."""

    def __init__(self, database_path: Path | str = DEFAULT_DATABASE_PATH) -> None:
        self.database_path = Path(database_path)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Open a configured SQLite connection."""

        self.database_path.parent.mkdir(parents=True, exist_ok=True)

        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")

        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        """Create all persistence tables and indexes."""

        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS executions (
                    execution_id TEXT PRIMARY KEY,
                    assessment_name TEXT NOT NULL,
                    plan_version TEXT NOT NULL,
                    state TEXT NOT NULL,
                    asset_types_json TEXT NOT NULL,
                    targets_json TEXT NOT NULL,
                    authorization_confirmed INTEGER NOT NULL,
                    active_testing_allowed INTEGER NOT NULL,
                    intrusive_testing_allowed INTEGER NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT,
                    failure_reason TEXT
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    execution_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    message TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (execution_id)
                        REFERENCES executions(execution_id)
                        ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    execution_id TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    path TEXT NOT NULL,
                    sha256 TEXT,
                    size_bytes INTEGER,
                    content_type TEXT,
                    step_id TEXT,
                    tool_name TEXT,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (execution_id)
                        REFERENCES executions(execution_id)
                        ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_executions_state
                    ON executions(state);

                CREATE INDEX IF NOT EXISTS idx_executions_created_at
                    ON executions(created_at);

                CREATE INDEX IF NOT EXISTS idx_audit_execution_id
                    ON audit_events(execution_id);

                CREATE INDEX IF NOT EXISTS idx_evidence_execution_id
                    ON evidence(execution_id);

                CREATE INDEX IF NOT EXISTS idx_evidence_type
                    ON evidence(evidence_type);
                """
            )

    def create_execution(self, request: ExecutionCreate) -> ExecutionRecord:
        """Create a persistent assessment execution."""

        if not request.authorization_confirmed:
            raise PersistenceError("Execution cannot be created without confirmed authorization.")

        execution_id = f"execution-{uuid4()}"
        timestamp = utc_now()

        record = ExecutionRecord(
            execution_id=execution_id,
            assessment_name=request.assessment_name,
            plan_version=request.plan_version,
            state=ExecutionState.CREATED,
            asset_types=request.asset_types,
            targets=request.targets,
            authorization_confirmed=request.authorization_confirmed,
            active_testing_allowed=request.active_testing_allowed,
            intrusive_testing_allowed=request.intrusive_testing_allowed,
            metadata=request.metadata,
            created_at=timestamp,
            updated_at=timestamp,
        )

        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO executions (
                    execution_id,
                    assessment_name,
                    plan_version,
                    state,
                    asset_types_json,
                    targets_json,
                    authorization_confirmed,
                    active_testing_allowed,
                    intrusive_testing_allowed,
                    metadata_json,
                    created_at,
                    updated_at,
                    completed_at,
                    failure_reason
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.execution_id,
                    record.assessment_name,
                    record.plan_version,
                    record.state.value,
                    json.dumps(record.asset_types),
                    json.dumps(record.targets),
                    int(record.authorization_confirmed),
                    int(record.active_testing_allowed),
                    int(record.intrusive_testing_allowed),
                    json.dumps(record.metadata),
                    record.created_at.isoformat(),
                    record.updated_at.isoformat(),
                    None,
                    None,
                ),
            )

            self._insert_audit_event(
                connection=connection,
                execution_id=execution_id,
                event_type=AuditEventType.EXECUTION_CREATED,
                actor="system",
                message="Assessment execution created.",
                details={
                    "assessment_name": request.assessment_name,
                    "targets": request.targets,
                },
            )

        return record

    def get_execution(self, execution_id: str) -> ExecutionRecord:
        """Retrieve one execution by identifier."""

        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM executions
                WHERE execution_id = ?
                """,
                (execution_id,),
            ).fetchone()

        if row is None:
            raise ExecutionNotFoundError(f"Execution '{execution_id}' was not found.")

        return self._execution_from_row(row)

    def list_executions(
        self,
        *,
        state: ExecutionState | None = None,
        limit: int = 100,
    ) -> list[ExecutionRecord]:
        """List recent assessment executions."""

        if limit < 1 or limit > 1_000:
            raise PersistenceError("Execution list limit must be between 1 and 1000.")

        query = """
            SELECT *
            FROM executions
        """
        parameters: list[object] = []

        if state is not None:
            query += " WHERE state = ?"
            parameters.append(state.value)

        query += " ORDER BY created_at DESC LIMIT ?"
        parameters.append(limit)

        with self.connect() as connection:
            rows = connection.execute(
                query,
                parameters,
            ).fetchall()

        return [self._execution_from_row(row) for row in rows]

    def transition_execution(
        self,
        execution_id: str,
        new_state: ExecutionState,
        *,
        actor: str,
        reason: str | None = None,
    ) -> ExecutionRecord:
        """Apply a validated execution-state transition."""

        current = self.get_execution(execution_id)

        if new_state == current.state:
            raise InvalidStateTransitionError(f"Execution is already in state '{new_state.value}'.")

        allowed_states = ALLOWED_STATE_TRANSITIONS[current.state]

        if new_state not in allowed_states:
            raise InvalidStateTransitionError(
                f"Invalid execution-state transition: {current.state.value} -> {new_state.value}."
            )

        timestamp = utc_now()
        completed_at: str | None = None
        failure_reason: str | None = current.failure_reason

        if new_state in {
            ExecutionState.COMPLETED,
            ExecutionState.FAILED,
            ExecutionState.CANCELLED,
        }:
            completed_at = timestamp.isoformat()

        if new_state is ExecutionState.FAILED:
            failure_reason = reason or "Execution failed."

        event_type = AuditEventType.STATE_CHANGED

        if new_state is ExecutionState.CANCELLED:
            event_type = AuditEventType.EXECUTION_CANCELLED

        with self.connect() as connection:
            connection.execute(
                """
                UPDATE executions
                SET state = ?,
                    updated_at = ?,
                    completed_at = ?,
                    failure_reason = ?
                WHERE execution_id = ?
                """,
                (
                    new_state.value,
                    timestamp.isoformat(),
                    completed_at,
                    failure_reason,
                    execution_id,
                ),
            )

            self._insert_audit_event(
                connection=connection,
                execution_id=execution_id,
                event_type=event_type,
                actor=actor,
                message=(
                    f"Execution state changed from '{current.state.value}' to '{new_state.value}'."
                ),
                details={
                    "previous_state": current.state.value,
                    "new_state": new_state.value,
                    "reason": reason,
                },
            )

        return self.get_execution(execution_id)

    def add_audit_event(
        self,
        execution_id: str,
        *,
        event_type: AuditEventType,
        actor: str,
        message: str,
        details: dict[str, object] | None = None,
    ) -> AuditEventRecord:
        """Add an immutable audit event."""

        self.get_execution(execution_id)

        with self.connect() as connection:
            return self._insert_audit_event(
                connection=connection,
                execution_id=execution_id,
                event_type=event_type,
                actor=actor,
                message=message,
                details=details or {},
            )

    def list_audit_events(
        self,
        execution_id: str,
    ) -> list[AuditEventRecord]:
        """Return all audit events for an execution."""

        self.get_execution(execution_id)

        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM audit_events
                WHERE execution_id = ?
                ORDER BY created_at ASC
                """,
                (execution_id,),
            ).fetchall()

        return [self._audit_from_row(row) for row in rows]

    def add_evidence(
        self,
        execution_id: str,
        request: EvidenceCreate,
        *,
        actor: str = "system",
    ) -> EvidenceRecord:
        """Register an evidence item in the evidence catalog."""

        self.get_execution(execution_id)

        evidence_id = f"evidence-{uuid4()}"
        timestamp = utc_now()

        record = EvidenceRecord(
            evidence_id=evidence_id,
            execution_id=execution_id,
            evidence_type=request.evidence_type,
            source=request.source,
            path=request.path,
            sha256=request.sha256,
            size_bytes=request.size_bytes,
            content_type=request.content_type,
            step_id=request.step_id,
            tool_name=request.tool_name,
            metadata=request.metadata,
            created_at=timestamp,
        )

        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO evidence (
                    evidence_id,
                    execution_id,
                    evidence_type,
                    source,
                    path,
                    sha256,
                    size_bytes,
                    content_type,
                    step_id,
                    tool_name,
                    metadata_json,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.evidence_id,
                    record.execution_id,
                    record.evidence_type.value,
                    record.source,
                    record.path,
                    record.sha256,
                    record.size_bytes,
                    record.content_type,
                    record.step_id,
                    record.tool_name,
                    json.dumps(record.metadata),
                    record.created_at.isoformat(),
                ),
            )

            self._insert_audit_event(
                connection=connection,
                execution_id=execution_id,
                event_type=AuditEventType.EVIDENCE_ADDED,
                actor=actor,
                message=f"Evidence '{evidence_id}' added.",
                details={
                    "evidence_id": evidence_id,
                    "evidence_type": request.evidence_type.value,
                    "path": request.path,
                    "step_id": request.step_id,
                },
            )

        return record

    def list_evidence(
        self,
        execution_id: str,
        *,
        evidence_type: EvidenceType | None = None,
    ) -> list[EvidenceRecord]:
        """List evidence registered for one execution."""

        self.get_execution(execution_id)

        query = """
            SELECT *
            FROM evidence
            WHERE execution_id = ?
        """
        parameters: list[object] = [execution_id]

        if evidence_type is not None:
            query += " AND evidence_type = ?"
            parameters.append(evidence_type.value)

        query += " ORDER BY created_at ASC"

        with self.connect() as connection:
            rows = connection.execute(
                query,
                parameters,
            ).fetchall()

        return [self._evidence_from_row(row) for row in rows]

    def _insert_audit_event(
        self,
        *,
        connection: sqlite3.Connection,
        execution_id: str,
        event_type: AuditEventType,
        actor: str,
        message: str,
        details: dict[str, object],
    ) -> AuditEventRecord:
        """Insert one audit event using an existing transaction."""

        record = AuditEventRecord(
            event_id=f"event-{uuid4()}",
            execution_id=execution_id,
            event_type=event_type,
            actor=actor,
            message=message,
            details=details,
            created_at=utc_now(),
        )

        connection.execute(
            """
            INSERT INTO audit_events (
                event_id,
                execution_id,
                event_type,
                actor,
                message,
                details_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.event_id,
                record.execution_id,
                record.event_type.value,
                record.actor,
                record.message,
                json.dumps(record.details),
                record.created_at.isoformat(),
            ),
        )

        return record

    @staticmethod
    def _execution_from_row(row: sqlite3.Row) -> ExecutionRecord:
        """Convert a SQLite execution row into a Pydantic model."""

        return ExecutionRecord(
            execution_id=row["execution_id"],
            assessment_name=row["assessment_name"],
            plan_version=row["plan_version"],
            state=ExecutionState(row["state"]),
            asset_types=json.loads(row["asset_types_json"]),
            targets=json.loads(row["targets_json"]),
            authorization_confirmed=bool(row["authorization_confirmed"]),
            active_testing_allowed=bool(row["active_testing_allowed"]),
            intrusive_testing_allowed=bool(row["intrusive_testing_allowed"]),
            metadata=json.loads(row["metadata_json"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            completed_at=(
                datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None
            ),
            failure_reason=row["failure_reason"],
        )

    @staticmethod
    def _audit_from_row(row: sqlite3.Row) -> AuditEventRecord:
        """Convert a SQLite audit row into a Pydantic model."""

        return AuditEventRecord(
            event_id=row["event_id"],
            execution_id=row["execution_id"],
            event_type=AuditEventType(row["event_type"]),
            actor=row["actor"],
            message=row["message"],
            details=json.loads(row["details_json"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    @staticmethod
    def _evidence_from_row(row: sqlite3.Row) -> EvidenceRecord:
        """Convert a SQLite evidence row into a Pydantic model."""

        return EvidenceRecord(
            evidence_id=row["evidence_id"],
            execution_id=row["execution_id"],
            evidence_type=EvidenceType(row["evidence_type"]),
            source=row["source"],
            path=row["path"],
            sha256=row["sha256"],
            size_bytes=row["size_bytes"],
            content_type=row["content_type"],
            step_id=row["step_id"],
            tool_name=row["tool_name"],
            metadata=json.loads(row["metadata_json"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )
