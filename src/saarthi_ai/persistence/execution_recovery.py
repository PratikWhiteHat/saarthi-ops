"""Recover execution records left active by an interrupted local process."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.models import AuditEventType, ExecutionState

DEFAULT_STALE_EXECUTION_AGE = timedelta(hours=6)
_ACTIVE_STATES = frozenset({ExecutionState.RUNNING, ExecutionState.ANALYZING})


@dataclass(frozen=True)
class StaleExecutionRecovery:
    recovered_execution_ids: tuple[str, ...] = ()
    skipped_execution_ids: tuple[str, ...] = ()

    @property
    def recovered_count(self) -> int:
        return len(self.recovered_execution_ids)


def recover_stale_executions(
    database: SaarthiDatabase,
    *,
    now: datetime | None = None,
    max_age: timedelta = DEFAULT_STALE_EXECUTION_AGE,
    actor: str = "saarthi-startup-recovery",
) -> StaleExecutionRecovery:
    """Fail abandoned active executions without touching recent work.

    Children are recovered before orchestration parents so the persisted audit
    trail follows the same direction as a normal workflow shutdown.
    """

    if max_age <= timedelta(0):
        raise ValueError("Stale execution age must be greater than zero.")
    observed_at = now or datetime.now(UTC)
    if observed_at.tzinfo is None:
        raise ValueError("Recovery time must be timezone-aware.")

    candidates = [
        execution
        for execution in database.list_executions(limit=1_000)
        if execution.state in _ACTIVE_STATES
        and observed_at - execution.updated_at >= max_age
    ]
    candidates.sort(
        key=lambda execution: (
            (execution.metadata or {}).get("execution_role")
            == "orchestration_parent",
            execution.updated_at,
        )
    )

    recovered: list[str] = []
    skipped: list[str] = []
    for execution in candidates:
        inactive_for = observed_at - execution.updated_at
        inactive_seconds = max(0, int(inactive_for.total_seconds()))
        reason = (
            "Startup recovery marked an interrupted execution as failed after "
            f"{inactive_seconds} seconds without a state update."
        )
        try:
            database.transition_execution(
                execution.execution_id,
                ExecutionState.FAILED,
                actor=actor,
                reason=reason,
            )
            database.add_audit_event(
                execution.execution_id,
                event_type=AuditEventType.TOOL_FAILED,
                actor=actor,
                message=(
                    "[RECOVERY] Stale active execution was closed after an "
                    "interrupted local run."
                ),
                details={
                    "previous_state": execution.state.value,
                    "inactive_seconds": inactive_seconds,
                    "stale_threshold_seconds": int(max_age.total_seconds()),
                    "automatic": True,
                },
            )
            recovered.append(execution.execution_id)
        except InvalidStateTransitionError:
            # Another process advanced the record after candidate selection.
            skipped.append(execution.execution_id)

    return StaleExecutionRecovery(
        recovered_execution_ids=tuple(recovered),
        skipped_execution_ids=tuple(skipped),
    )


__all__ = [
    "DEFAULT_STALE_EXECUTION_AGE",
    "StaleExecutionRecovery",
    "recover_stale_executions",
]
