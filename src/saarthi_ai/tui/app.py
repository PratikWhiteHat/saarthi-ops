from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.markup import escape as escape_markup
from textual.app import App, ComposeResult
from textual.containers import Grid, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Label, Log, ProgressBar, Static

DEFAULT_DB_PATH = Path.home() / ".saarthi" / "saarthi.db"


@dataclass(frozen=True)
class DashboardSnapshot:
    project_name: str
    execution_id: str
    target_scope: str
    authorization: str
    mode: str
    current_phase: str
    phase_progress: int
    evidence_count: int
    finding_count: int
    execution_state: str
    recent_executions: list[dict[str, str]]
    recent_activity: list[str]
    completed_phases: frozenset[str] = frozenset()
    orchestration_status: str = "unknown"
    outcome_counts: dict[str, int] = field(default_factory=dict)
    optional_failure_summary: str | None = None
    attack_hypothesis_set: dict[str, str] | None = None
    controlled_observation: dict[str, str] | None = None
    controlled_nuclei_execution: dict[str, str] | None = None
    controlled_nuclei_preparation: dict[str, str] | None = None
    controlled_nuclei_preview: dict[str, str] | None = None


class ReadOnlySaarthiRepository:
    """Read-only adapter for the existing Saarthi SQLite database."""

    def __init__(self, database_path: Path = DEFAULT_DB_PATH) -> None:
        self.database_path = database_path

    def _connect(self) -> sqlite3.Connection:
        uri = f"file:{self.database_path}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=2)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _tables(connection: sqlite3.Connection) -> set[str]:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        return {str(row["name"]) for row in rows}

    @staticmethod
    def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
        rows = connection.execute(f'PRAGMA table_info("{table}")').fetchall()
        return {str(row["name"]) for row in rows}

    @staticmethod
    def _pick(columns: set[str], *names: str) -> str | None:
        return next((name for name in names if name in columns), None)

    def load(self) -> DashboardSnapshot:
        if not self.database_path.exists():
            return demo_snapshot(
                [
                    f"[WRN] Database not found: {self.database_path}",
                    "[INF] Safe demo data loaded.",
                ]
            )

        try:
            with self._connect() as connection:
                return self._load_from_database(
                    connection,
                    self._tables(connection),
                )
        except (sqlite3.Error, OSError) as error:
            return demo_snapshot(
                [
                    f"[WRN] Read-only database connection failed: {error}",
                    "[INF] Safe demo data loaded.",
                ]
            )

    def _load_from_database(
        self,
        connection: sqlite3.Connection,
        tables: set[str],
    ) -> DashboardSnapshot:
        execution_table = next(
            (name for name in ("executions", "execution") if name in tables),
            None,
        )
        if execution_table is None:
            return demo_snapshot(["[WRN] No executions table detected."])

        columns = self._columns(connection, execution_table)
        id_column = self._pick(columns, "execution_id", "id")
        state_column = self._pick(columns, "state", "status")
        project_column = self._pick(
            columns,
            "project_name",
            "assessment_name",
            "project_id",
        )
        target_column = self._pick(columns, "target", "targets", "scope")
        created_column = self._pick(
            columns,
            "created_at",
            "started_at",
        )
        updated_column = self._pick(
            columns,
            "updated_at",
            "modified_at",
        )
        completed_column = self._pick(
            columns,
            "completed_at",
            "finished_at",
        )
        metadata_column = self._pick(
            columns,
            "metadata_json",
            "metadata",
        )

        order_sql = execution_order_sql(
            updated_column,
            completed_column,
            created_column,
        )

        rows = connection.execute(
            f'SELECT * FROM "{execution_table}" {order_sql} LIMIT 100'
        ).fetchall()
        if not rows:
            return demo_snapshot(["[INF] No executions are currently stored."])

        latest, display_rows, completed_phases = (
            select_dashboard_execution_rows(
                list(rows),
                metadata_column,
            )
        )

        orchestration_execution_ids = [
            str(row[id_column])
            for row in [latest, *display_rows]
            if id_column is not None and row[id_column] is not None
        ]

        def value(row: sqlite3.Row, column: str | None, default: str) -> str:
            if column is None or row[column] is None:
                return default
            return str(row[column])

        execution_id = value(latest, id_column, "unknown")
        execution_state = value(latest, state_column, "unknown")

        recent_executions: list[dict[str, str]] = []
        for row in display_rows:
            started = value(row, created_column, "—")
            completed = value(row, completed_column, "")
            row_execution_id = value(row, id_column, "unknown")
            row_evidence_types = self._evidence_types(
                connection,
                tables,
                row_execution_id,
            )

            recent_executions.append(
                {
                    "execution_id": row_execution_id,
                    "phase": str(
                        parse_execution_metadata(
                            row,
                            metadata_column,
                        ).get("phase_code")
                        or infer_phase_short(
                            value(row, state_column, "unknown"),
                            row_evidence_types,
                        )
                    ),
                    "target": value(row, target_column, "Authorized target"),
                    "status": value(
                        row,
                        state_column,
                        "unknown",
                    ).upper(),
                    "started": compact_timestamp(started),
                    "duration": calculate_duration(started, completed),
                    "evidence": "—",
                    "findings": "—",
                }
            )

        evidence_count = self._count_related(
            connection,
            tables,
            ("evidence", "evidence_items"),
            execution_id,
        )
        evidence_types = self._evidence_types(
            connection,
            tables,
            execution_id,
        )
        finding_count = self._count_related(
            connection,
            tables,
            ("findings", "finding"),
            execution_id,
        )

        recent_executions[0]["evidence"] = str(evidence_count)
        recent_executions[0]["findings"] = str(finding_count)

        (
            orchestration_status,
            outcome_counts,
            optional_failure_summary,
        ) = self._load_orchestration_outcome(
            connection,
            tables,
            execution_id,
        )

        attack_hypothesis_set = (
            self._load_attack_hypothesis_set(
                connection,
                tables,
                execution_id,
            )
        )

        controlled_observation = (
            self._load_controlled_validation_observation(
                connection,
                tables,
                execution_id,
            )
        )

        if controlled_observation is not None:
            reuse = self._load_controlled_observation_reuse(
                connection,
                tables,
                execution_id,
                controlled_observation["evidence_id"],
            )
            controlled_observation.update(reuse)

        controlled_nuclei_execution = (
            self._load_controlled_nuclei_execution(
                connection,
                tables,
                execution_id,
            )
        )

        controlled_nuclei_preparation = (
            self._load_controlled_nuclei_preparation(
                connection,
                tables,
                execution_id,
            )
        )

        if controlled_nuclei_preparation is not None:
            preparation_reuse = self._load_nuclei_preparation_reuse(
                connection,
                tables,
                execution_id,
                controlled_nuclei_preparation["evidence_id"],
            )
            controlled_nuclei_preparation.update(
                preparation_reuse
            )

        controlled_nuclei_preview = self._load_controlled_nuclei_preview(
            connection,
            tables,
            execution_id,
        )

        if controlled_nuclei_preview is not None:
            preview_reuse = self._load_nuclei_preview_reuse(
                connection,
                tables,
                execution_id,
                controlled_nuclei_preview["evidence_id"],
            )
            controlled_nuclei_preview.update(preview_reuse)

        return DashboardSnapshot(
            project_name=value(
                latest,
                project_column,
                "Black Hat MEA Demo Web Assessment",
            ),
            execution_id=execution_id,
            target_scope=value(latest, target_column, "Authorized scope"),
            authorization="CONFIRMED",
            mode="LOCAL / SAFE + SMART",
            current_phase=infer_phase(
                execution_state,
                evidence_types,
            ),
            phase_progress=progress_for_state(execution_state),
            evidence_count=evidence_count,
            finding_count=finding_count,
            execution_state=execution_state,
            recent_executions=recent_executions,
            recent_activity=self._load_orchestration_activity(
                connection,
                tables,
                orchestration_execution_ids,
            ),
            completed_phases=completed_phases,
            orchestration_status=orchestration_status,
            outcome_counts=outcome_counts,
            optional_failure_summary=optional_failure_summary,
            attack_hypothesis_set=attack_hypothesis_set,
            controlled_observation=controlled_observation,
            controlled_nuclei_execution=controlled_nuclei_execution,
            controlled_nuclei_preparation=(
                controlled_nuclei_preparation
            ),
            controlled_nuclei_preview=controlled_nuclei_preview,
        )

    def _evidence_types(
        self,
        connection: sqlite3.Connection,
        tables: set[str],
        execution_id: str,
    ) -> set[str]:
        """Return normalized evidence types associated with an execution."""

        table = next(
            (name for name in ("evidence", "evidence_items") if name in tables),
            None,
        )
        if table is None:
            return set()

        columns = self._columns(connection, table)
        type_column = self._pick(
            columns,
            "evidence_type",
            "type",
            "kind",
        )
        execution_column = self._pick(
            columns,
            "execution_id",
            "execution",
        )

        if type_column is None:
            return set()

        where_sql = ""
        parameters: tuple[Any, ...] = ()

        if execution_column is not None:
            where_sql = f'WHERE "{execution_column}" = ?'
            parameters = (execution_id,)

        rows = connection.execute(
            f'SELECT "{type_column}" FROM "{table}" {where_sql}',
            parameters,
        ).fetchall()

        return {
            str(row[type_column]).strip().lower() for row in rows if row[type_column] is not None
        }

    def _load_attack_hypothesis_set(
        self,
        connection: sqlite3.Connection,
        tables: set[str],
        execution_id: str,
    ) -> dict[str, str] | None:
        """Load the newest valid Phase 6A hypothesis-set summary."""

        table = next(
            (
                name
                for name in ("evidence", "evidence_items")
                if name in tables
            ),
            None,
        )

        if table is None:
            return None

        columns = self._columns(connection, table)
        execution_column = self._pick(
            columns,
            "execution_id",
            "execution",
        )
        type_column = self._pick(
            columns,
            "evidence_type",
            "type",
            "kind",
        )
        evidence_id_column = self._pick(
            columns,
            "evidence_id",
            "id",
        )
        sha256_column = self._pick(columns, "sha256")
        metadata_column = self._pick(
            columns,
            "metadata_json",
            "metadata",
        )
        created_column = self._pick(
            columns,
            "created_at",
            "timestamp",
        )

        if (
            execution_column is None
            or type_column is None
            or metadata_column is None
        ):
            return None

        order_sql = (
            f'ORDER BY "{created_column}" DESC'
            if created_column
            else ""
        )
        rows = connection.execute(
            f"""
            SELECT *
            FROM "{table}"
            WHERE "{execution_column}" = ?
              AND LOWER("{type_column}") = ?
            {order_sql}
            LIMIT 50
            """,
            (
                execution_id,
                "attack_hypothesis_set",
            ),
        ).fetchall()

        def display(value: Any, default: str = "—") -> str:
            if value is None:
                return default

            if isinstance(value, bool):
                return str(value).lower()

            if isinstance(value, int) and not isinstance(value, bool):
                return str(value)

            if isinstance(value, str):
                return value

            return default

        for row in rows:
            try:
                metadata = json.loads(str(row[metadata_column]))
            except (
                json.JSONDecodeError,
                TypeError,
                ValueError,
            ):
                continue

            if not isinstance(metadata, dict):
                continue

            families = metadata.get("families")
            hypothesis_ids = metadata.get("hypothesis_ids")
            considered_ids = metadata.get(
                "considered_evidence_ids"
            )
            rejected_ids = metadata.get(
                "rejected_evidence_ids"
            )

            return {
                "evidence_id": (
                    display(row[evidence_id_column])
                    if evidence_id_column
                    else "—"
                ),
                "evidence_sha256": (
                    display(row[sha256_column])
                    if sha256_column
                    else "—"
                ),
                "target_url": display(
                    metadata.get("target_url")
                ),
                "hypothesis_count": display(
                    metadata.get("hypothesis_count"),
                    "0",
                ),
                "families": (
                    ", ".join(
                        item
                        for item in families
                        if isinstance(item, str)
                    )
                    if isinstance(families, list)
                    else "—"
                ),
                "hypothesis_ids": (
                    ", ".join(
                        item
                        for item in hypothesis_ids
                        if isinstance(item, str)
                    )
                    if isinstance(hypothesis_ids, list)
                    else "—"
                ),
                "considered_evidence_count": (
                    str(len(considered_ids))
                    if isinstance(considered_ids, list)
                    else "0"
                ),
                "rejected_evidence_count": (
                    str(len(rejected_ids))
                    if isinstance(rejected_ids, list)
                    else "0"
                ),
                "truncated": display(
                    metadata.get("truncated"),
                    "false",
                ),
                "executed": display(
                    metadata.get("executed"),
                    "false",
                ),
                "network_activity": display(
                    metadata.get("network_activity"),
                    "false",
                ),
                "payload_generated": display(
                    metadata.get("payload_generated"),
                    "false",
                ),
                "subprocess_started": display(
                    metadata.get("subprocess_started"),
                    "false",
                ),
            }

        return None

    def _load_controlled_validation_observation(
        self,
        connection: sqlite3.Connection,
        tables: set[str],
        execution_id: str,
    ) -> dict[str, str] | None:
        """Load the newest valid safe controlled-observation summary."""

        table = next(
            (
                name
                for name in ("evidence", "evidence_items")
                if name in tables
            ),
            None,
        )

        if table is None:
            return None

        columns = self._columns(connection, table)
        execution_column = self._pick(
            columns,
            "execution_id",
            "execution",
        )
        type_column = self._pick(
            columns,
            "evidence_type",
            "type",
            "kind",
        )
        evidence_id_column = self._pick(
            columns,
            "evidence_id",
            "id",
        )
        sha256_column = self._pick(columns, "sha256")
        metadata_column = self._pick(
            columns,
            "metadata_json",
            "metadata",
        )
        created_column = self._pick(
            columns,
            "created_at",
            "timestamp",
        )

        if (
            execution_column is None
            or type_column is None
            or metadata_column is None
        ):
            return None

        order_sql = (
            f'ORDER BY "{created_column}" DESC'
            if created_column
            else ""
        )

        rows = connection.execute(
            f"""
            SELECT *
            FROM "{table}"
            WHERE "{execution_column}" = ?
              AND LOWER("{type_column}") = ?
            {order_sql}
            LIMIT 50
            """,
            (
                execution_id,
                "controlled_validation_observation",
            ),
        ).fetchall()

        def display(value: Any, default: str = "—") -> str:
            if value is None:
                return default

            if isinstance(value, bool):
                return str(value).lower()

            return str(value)

        for row in rows:
            try:
                metadata = json.loads(str(row[metadata_column]))
            except (
                json.JSONDecodeError,
                TypeError,
                ValueError,
            ):
                continue

            if not isinstance(metadata, dict):
                continue

            return {
                "evidence_id": (
                    display(row[evidence_id_column])
                    if evidence_id_column
                    else "—"
                ),
                "evidence_sha256": (
                    display(row[sha256_column])
                    if sha256_column
                    else "—"
                ),
                "target_url": display(metadata.get("target_url")),
                "action": display(metadata.get("action")),
                "method": display(metadata.get("method")),
                "status_code": display(metadata.get("status_code")),
                "final_url": display(metadata.get("final_url")),
                "body_bytes_captured": display(
                    metadata.get("body_bytes_captured"),
                    "0",
                ),
                "body_truncated": display(
                    metadata.get("body_truncated"),
                    "false",
                ),
                "body_sha256": display(
                    metadata.get("body_sha256")
                ),
                "plan_evidence_id": display(
                    metadata.get("plan_evidence_id")
                ),
                "network_activity": display(
                    metadata.get("network_activity"),
                    "false",
                ),
                "request_attempted": display(
                    metadata.get("request_attempted"),
                    "false",
                ),
                "follow_redirects": display(
                    metadata.get("follow_redirects"),
                    "false",
                ),
                "reused_existing_evidence": "false",
                "second_request_sent": "—",
            }

        return None

    def _load_controlled_observation_reuse(
        self,
        connection: sqlite3.Connection,
        tables: set[str],
        execution_id: str,
        evidence_id: str,
    ) -> dict[str, str]:
        """Load the latest matching idempotent-reuse audit summary."""

        defaults = {
            "reused_existing_evidence": "false",
            "second_request_sent": "—",
        }

        table = next(
            (
                name
                for name in (
                    "audit_events",
                    "audit_log",
                    "events",
                )
                if name in tables
            ),
            None,
        )

        if table is None:
            return defaults

        columns = self._columns(connection, table)
        execution_column = self._pick(
            columns,
            "execution_id",
            "execution",
        )
        details_column = self._pick(
            columns,
            "details_json",
            "details",
            "metadata_json",
        )
        timestamp_column = self._pick(
            columns,
            "created_at",
            "timestamp",
            "occurred_at",
        )

        if execution_column is None or details_column is None:
            return defaults

        order_sql = (
            f'ORDER BY "{timestamp_column}" DESC'
            if timestamp_column
            else ""
        )

        rows = connection.execute(
            f"""
            SELECT "{details_column}"
            FROM "{table}"
            WHERE "{execution_column}" = ?
            {order_sql}
            LIMIT 200
            """,
            (execution_id,),
        ).fetchall()

        for row in rows:
            try:
                details = json.loads(str(row[details_column]))
            except (
                json.JSONDecodeError,
                TypeError,
                ValueError,
            ):
                continue

            if not isinstance(details, dict):
                continue

            if details.get("idempotent_reuse") is not True:
                continue

            if str(details.get("evidence_id") or "") != evidence_id:
                continue

            second_request_sent = details.get(
                "second_request_sent"
            )

            return {
                "reused_existing_evidence": "true",
                "second_request_sent": (
                    str(second_request_sent).lower()
                    if isinstance(second_request_sent, bool)
                    else "—"
                ),
            }

        return defaults

    def _load_controlled_nuclei_execution(
        self,
        connection: sqlite3.Connection,
        tables: set[str],
        execution_id: str,
    ) -> dict[str, str] | None:
        """Load the newest valid controlled Nuclei execution summary."""

        table = next(
            (
                name
                for name in ("evidence", "evidence_items")
                if name in tables
            ),
            None,
        )

        if table is None:
            return None

        columns = self._columns(connection, table)
        execution_column = self._pick(
            columns,
            "execution_id",
            "execution",
        )
        type_column = self._pick(
            columns,
            "evidence_type",
            "type",
            "kind",
        )
        evidence_id_column = self._pick(
            columns,
            "evidence_id",
            "id",
        )
        sha256_column = self._pick(columns, "sha256")
        metadata_column = self._pick(
            columns,
            "metadata_json",
            "metadata",
        )
        created_column = self._pick(
            columns,
            "created_at",
            "timestamp",
        )

        if (
            execution_column is None
            or type_column is None
            or metadata_column is None
        ):
            return None

        order_sql = (
            f'ORDER BY "{created_column}" DESC'
            if created_column
            else ""
        )

        rows = connection.execute(
            f"""
            SELECT *
            FROM "{table}"
            WHERE "{execution_column}" = ?
              AND LOWER("{type_column}") = ?
            {order_sql}
            LIMIT 50
            """,
            (
                execution_id,
                "controlled_nuclei_execution",
            ),
        ).fetchall()

        def display(value: Any, default: str = "—") -> str:
            if value is None:
                return default

            if isinstance(value, bool):
                return str(value).lower()

            if isinstance(value, int) and not isinstance(value, bool):
                return str(value)

            if isinstance(value, str):
                return value

            return default

        for row in rows:
            try:
                metadata = json.loads(str(row[metadata_column]))
            except (
                json.JSONDecodeError,
                TypeError,
                ValueError,
            ):
                continue

            if not isinstance(metadata, dict):
                continue

            arguments = metadata.get("arguments")

            if isinstance(arguments, list) and all(
                isinstance(item, str) for item in arguments
            ):
                argument_summary = " ".join(arguments)
            else:
                argument_summary = "—"

            return {
                "evidence_id": (
                    display(row[evidence_id_column])
                    if evidence_id_column
                    else "—"
                ),
                "evidence_sha256": (
                    display(row[sha256_column])
                    if sha256_column
                    else "—"
                ),
                "preparation_evidence_id": display(
                    metadata.get("preparation_evidence_id")
                ),
                "tool_name": "nuclei",
                "target_url": display(metadata.get("target_url")),
                "executable": display(metadata.get("executable")),
                "arguments": argument_summary,
                "exit_code": display(metadata.get("exit_code")),
                "timed_out": display(
                    metadata.get("timed_out"),
                    "false",
                ),
                "stdout_bytes": display(metadata.get("stdout_bytes")),
                "stderr_bytes": display(metadata.get("stderr_bytes")),
                "stdout_truncated": display(
                    metadata.get("stdout_truncated"),
                    "false",
                ),
                "stderr_truncated": display(
                    metadata.get("stderr_truncated"),
                    "false",
                ),
                "started_at": display(metadata.get("started_at")),
                "completed_at": display(metadata.get("completed_at")),
                "executed": display(
                    metadata.get("executed"),
                    "false",
                ),
                "network_activity": display(
                    metadata.get("network_activity"),
                    "false",
                ),
                "subprocess_started": display(
                    metadata.get("subprocess_started"),
                    "false",
                ),
                "runner_invoked": display(
                    metadata.get("runner_invoked"),
                    "false",
                ),
                "executable_resolved": display(
                    metadata.get("executable_resolved"),
                    "false",
                ),
                "automatic_retry": display(
                    metadata.get("automatic_retry"),
                    "false",
                ),
            }

        return None

    def _load_controlled_nuclei_preparation(
        self,
        connection: sqlite3.Connection,
        tables: set[str],
        execution_id: str,
    ) -> dict[str, str] | None:
        """Load the newest valid non-executed Nuclei preparation."""

        table = next(
            (
                name
                for name in ("evidence", "evidence_items")
                if name in tables
            ),
            None,
        )

        if table is None:
            return None

        columns = self._columns(connection, table)
        execution_column = self._pick(
            columns,
            "execution_id",
            "execution",
        )
        type_column = self._pick(
            columns,
            "evidence_type",
            "type",
            "kind",
        )
        evidence_id_column = self._pick(
            columns,
            "evidence_id",
            "id",
        )
        sha256_column = self._pick(columns, "sha256")
        metadata_column = self._pick(
            columns,
            "metadata_json",
            "metadata",
        )
        created_column = self._pick(
            columns,
            "created_at",
            "timestamp",
        )

        if (
            execution_column is None
            or type_column is None
            or metadata_column is None
        ):
            return None

        order_sql = (
            f'ORDER BY "{created_column}" DESC'
            if created_column
            else ""
        )

        rows = connection.execute(
            f"""
            SELECT *
            FROM "{table}"
            WHERE "{execution_column}" = ?
              AND LOWER("{type_column}") = ?
            {order_sql}
            LIMIT 50
            """,
            (
                execution_id,
                "controlled_nuclei_preparation",
            ),
        ).fetchall()

        def display(value: Any, default: str = "—") -> str:
            if value is None:
                return default

            if isinstance(value, bool):
                return str(value).lower()

            if isinstance(value, int) and not isinstance(value, bool):
                return str(value)

            if isinstance(value, str):
                return value

            return default

        for row in rows:
            try:
                metadata = json.loads(str(row[metadata_column]))
            except (
                json.JSONDecodeError,
                TypeError,
                ValueError,
            ):
                continue

            if not isinstance(metadata, dict):
                continue

            arguments = metadata.get("arguments")

            if isinstance(arguments, list) and all(
                isinstance(item, str) for item in arguments
            ):
                argument_summary = " ".join(arguments)
            else:
                argument_summary = "—"

            return {
                "evidence_id": (
                    display(row[evidence_id_column])
                    if evidence_id_column
                    else "—"
                ),
                "evidence_sha256": (
                    display(row[sha256_column])
                    if sha256_column
                    else "—"
                ),
                "preview_evidence_id": display(
                    metadata.get("preview_evidence_id")
                ),
                "tool_name": "nuclei",
                "target_url": display(
                    metadata.get("target_url")
                ),
                "arguments": argument_summary,
                "rate_limit_per_second": display(
                    metadata.get("rate_limit_per_second")
                ),
                "concurrency": display(
                    metadata.get("concurrency")
                ),
                "request_timeout_seconds": display(
                    metadata.get("request_timeout_seconds")
                ),
                "process_timeout_seconds": display(
                    metadata.get("process_timeout_seconds")
                ),
                "max_output_bytes": display(
                    metadata.get("max_output_bytes")
                ),
                "executed": display(
                    metadata.get("executed"),
                    "false",
                ),
                "network_activity": display(
                    metadata.get("network_activity"),
                    "false",
                ),
                "subprocess_started": display(
                    metadata.get("subprocess_started"),
                    "false",
                ),
                "runner_invoked": display(
                    metadata.get("runner_invoked"),
                    "false",
                ),
                "executable_resolved": display(
                    metadata.get("executable_resolved"),
                    "false",
                ),
                "reused_existing_evidence": "false",
            }

        return None

    def _load_nuclei_preparation_reuse(
        self,
        connection: sqlite3.Connection,
        tables: set[str],
        execution_id: str,
        evidence_id: str,
    ) -> dict[str, str]:
        """Load the latest matching Nuclei-preparation reuse event."""

        defaults = {
            "reused_existing_evidence": "false",
        }

        table = next(
            (
                name
                for name in (
                    "audit_events",
                    "audit_log",
                    "events",
                )
                if name in tables
            ),
            None,
        )

        if table is None:
            return defaults

        columns = self._columns(connection, table)
        execution_column = self._pick(
            columns,
            "execution_id",
            "execution",
        )
        details_column = self._pick(
            columns,
            "details_json",
            "details",
            "metadata_json",
        )
        timestamp_column = self._pick(
            columns,
            "created_at",
            "timestamp",
            "occurred_at",
        )

        if execution_column is None or details_column is None:
            return defaults

        order_sql = (
            f'ORDER BY "{timestamp_column}" DESC'
            if timestamp_column
            else ""
        )

        rows = connection.execute(
            f"""
            SELECT "{details_column}"
            FROM "{table}"
            WHERE "{execution_column}" = ?
            {order_sql}
            LIMIT 200
            """,
            (execution_id,),
        ).fetchall()

        for row in rows:
            try:
                details = json.loads(str(row[details_column]))
            except (
                json.JSONDecodeError,
                TypeError,
                ValueError,
            ):
                continue

            if not isinstance(details, dict):
                continue

            if details.get("idempotent_reuse") is not True:
                continue

            if str(details.get("evidence_id") or "") != evidence_id:
                continue

            if str(details.get("phase_code") or "") != "6C":
                continue

            return {
                "reused_existing_evidence": "true",
            }

        return defaults

    def _load_controlled_nuclei_preview(
        self,
        connection: sqlite3.Connection,
        tables: set[str],
        execution_id: str,
    ) -> dict[str, str] | None:
        """Load the newest valid non-executed Nuclei preview summary."""

        table = next(
            (
                name
                for name in ("evidence", "evidence_items")
                if name in tables
            ),
            None,
        )

        if table is None:
            return None

        columns = self._columns(connection, table)
        execution_column = self._pick(
            columns,
            "execution_id",
            "execution",
        )
        type_column = self._pick(
            columns,
            "evidence_type",
            "type",
            "kind",
        )
        evidence_id_column = self._pick(
            columns,
            "evidence_id",
            "id",
        )
        sha256_column = self._pick(columns, "sha256")
        metadata_column = self._pick(
            columns,
            "metadata_json",
            "metadata",
        )
        created_column = self._pick(
            columns,
            "created_at",
            "timestamp",
        )

        if (
            execution_column is None
            or type_column is None
            or metadata_column is None
        ):
            return None

        order_sql = (
            f'ORDER BY "{created_column}" DESC'
            if created_column
            else ""
        )

        rows = connection.execute(
            f"""
            SELECT *
            FROM "{table}"
            WHERE "{execution_column}" = ?
              AND LOWER("{type_column}") = ?
            {order_sql}
            LIMIT 50
            """,
            (
                execution_id,
                "controlled_nuclei_preview",
            ),
        ).fetchall()

        def display(value: Any, default: str = "—") -> str:
            if value is None:
                return default

            if isinstance(value, bool):
                return str(value).lower()

            if isinstance(value, int) and not isinstance(value, bool):
                return str(value)

            if isinstance(value, str):
                return value

            return default

        def argument_value(
            arguments: object,
            flag: str,
        ) -> str:
            if not isinstance(arguments, list):
                return "—"

            if not all(isinstance(item, str) for item in arguments):
                return "—"

            try:
                index = arguments.index(flag)
            except ValueError:
                return "—"

            value_index = index + 1

            if value_index >= len(arguments):
                return "—"

            return arguments[value_index]

        for row in rows:
            try:
                metadata = json.loads(str(row[metadata_column]))
            except (
                json.JSONDecodeError,
                TypeError,
                ValueError,
            ):
                continue

            if not isinstance(metadata, dict):
                continue

            arguments = metadata.get("arguments")

            if isinstance(arguments, list) and all(
                isinstance(item, str) for item in arguments
            ):
                argument_summary = " ".join(arguments)
            else:
                argument_summary = "—"

            return {
                "evidence_id": (
                    display(row[evidence_id_column])
                    if evidence_id_column
                    else "—"
                ),
                "evidence_sha256": (
                    display(row[sha256_column])
                    if sha256_column
                    else "—"
                ),
                "tool_name": "nuclei",
                "target_url": display(metadata.get("target_url")),
                "arguments": argument_summary,
                "rate_limit_per_second": display(
                    metadata.get("rate_limit_per_second")
                ),
                "concurrency": display(
                    metadata.get("concurrency")
                ),
                "timeout_seconds": display(
                    metadata.get("timeout_seconds")
                ),
                "allowed_tags": argument_value(
                    arguments,
                    "-tags",
                ),
                "excluded_tags": argument_value(
                    arguments,
                    "-exclude-tags",
                ),
                "executed": display(
                    metadata.get("executed"),
                    "false",
                ),
                "network_activity": display(
                    metadata.get("network_activity"),
                    "false",
                ),
                "subprocess_started": display(
                    metadata.get("subprocess_started"),
                    "false",
                ),
                "reused_existing_evidence": "false",
            }

        return None

    def _load_nuclei_preview_reuse(
        self,
        connection: sqlite3.Connection,
        tables: set[str],
        execution_id: str,
        evidence_id: str,
    ) -> dict[str, str]:
        """Load the latest matching Nuclei-preview reuse event."""

        defaults = {
            "reused_existing_evidence": "false",
        }

        table = next(
            (
                name
                for name in (
                    "audit_events",
                    "audit_log",
                    "events",
                )
                if name in tables
            ),
            None,
        )

        if table is None:
            return defaults

        columns = self._columns(connection, table)
        execution_column = self._pick(
            columns,
            "execution_id",
            "execution",
        )
        details_column = self._pick(
            columns,
            "details_json",
            "details",
            "metadata_json",
        )
        timestamp_column = self._pick(
            columns,
            "created_at",
            "timestamp",
            "occurred_at",
        )

        if execution_column is None or details_column is None:
            return defaults

        order_sql = (
            f'ORDER BY "{timestamp_column}" DESC'
            if timestamp_column
            else ""
        )

        rows = connection.execute(
            f"""
            SELECT "{details_column}"
            FROM "{table}"
            WHERE "{execution_column}" = ?
            {order_sql}
            LIMIT 200
            """,
            (execution_id,),
        ).fetchall()

        for row in rows:
            try:
                details = json.loads(str(row[details_column]))
            except (
                json.JSONDecodeError,
                TypeError,
                ValueError,
            ):
                continue

            if not isinstance(details, dict):
                continue

            if details.get("idempotent_reuse") is not True:
                continue

            if str(details.get("evidence_id") or "") != evidence_id:
                continue

            if str(details.get("tool") or "").lower() != "nuclei":
                continue

            return {
                "reused_existing_evidence": "true",
            }

        return defaults

    def _count_related(
        self,
        connection: sqlite3.Connection,
        tables: set[str],
        candidates: Iterable[str],
        execution_id: str,
    ) -> int:
        table = next((name for name in candidates if name in tables), None)
        if table is None:
            return 0

        columns = self._columns(connection, table)
        execution_column = self._pick(columns, "execution_id", "execution")
        if execution_column is None:
            row = connection.execute(f'SELECT COUNT(*) AS total FROM "{table}"').fetchone()
        else:
            row = connection.execute(
                f'SELECT COUNT(*) AS total FROM "{table}" WHERE "{execution_column}" = ?',
                (execution_id,),
            ).fetchone()
        return int(row["total"])

    def _load_orchestration_outcome(
        self,
        connection: sqlite3.Connection,
        tables: set[str],
        parent_execution_id: str,
    ) -> tuple[str, dict[str, int], str | None]:
        """Load the latest calculated orchestration outcome."""

        table = next(
            (
                name
                for name in (
                    "audit_events",
                    "audit_log",
                    "events",
                )
                if name in tables
            ),
            None,
        )

        if table is None:
            return "unknown", {}, None

        columns = self._columns(connection, table)
        execution_column = self._pick(
            columns,
            "execution_id",
            "execution",
        )
        details_column = self._pick(
            columns,
            "details_json",
            "details",
            "metadata_json",
        )
        timestamp_column = self._pick(
            columns,
            "created_at",
            "timestamp",
            "occurred_at",
        )

        if execution_column is None or details_column is None:
            return "unknown", {}, None

        order_sql = (
            f'ORDER BY "{timestamp_column}" DESC'
            if timestamp_column
            else ""
        )

        rows = connection.execute(
            f"""
            SELECT "{details_column}"
            FROM "{table}"
            WHERE "{execution_column}" = ?
            {order_sql}
            LIMIT 200
            """,
            (parent_execution_id,),
        ).fetchall()

        for row in rows:
            try:
                details = json.loads(
                    str(row[details_column])
                )
            except (
                json.JSONDecodeError,
                TypeError,
                ValueError,
            ):
                continue

            if not isinstance(details, dict):
                continue

            raw_status = details.get("orchestration_status")

            if not isinstance(raw_status, str):
                continue

            raw_counts = details.get("outcome_counts")
            outcome_counts: dict[str, int] = {}

            if isinstance(raw_counts, dict):
                outcome_counts = {
                    str(key): int(value)
                    for key, value in raw_counts.items()
                    if isinstance(value, int)
                    and not isinstance(value, bool)
                }

            optional_failure_summary = None
            phase_outcomes = details.get("phase_outcomes")

            if isinstance(phase_outcomes, list):
                for phase in phase_outcomes:
                    if not isinstance(phase, dict):
                        continue

                    if phase.get("required") is not False:
                        continue

                    if phase.get("outcome") != "failed":
                        continue

                    phase_name = str(
                        phase.get("phase") or "optional phase"
                    )
                    error = (
                        phase.get("error_summary")
                        or phase.get("reason")
                        or "No failure summary recorded."
                    )

                    optional_failure_summary = (
                        f"{phase_name}: {error}"
                    )
                    break

            return (
                raw_status.lower(),
                outcome_counts,
                optional_failure_summary,
            )

        return "unknown", {}, None

    def _load_orchestration_activity(
        self,
        connection: sqlite3.Connection,
        tables: set[str],
        execution_ids: Iterable[str],
    ) -> list[str]:
        """Return detailed audit activity across an orchestration."""

        table = next(
            (
                name
                for name in (
                    "audit_events",
                    "audit_log",
                    "events",
                )
                if name in tables
            ),
            None,
        )
        if table is None:
            return ["[INF] No audit table detected."]

        columns = self._columns(connection, table)
        message_column = self._pick(
            columns,
            "message",
            "event",
            "action",
        )
        timestamp_column = self._pick(
            columns,
            "created_at",
            "timestamp",
            "occurred_at",
        )
        execution_column = self._pick(
            columns,
            "execution_id",
            "execution",
        )
        event_type_column = self._pick(
            columns,
            "event_type",
            "type",
        )
        actor_column = self._pick(
            columns,
            "actor",
            "source",
        )
        details_column = self._pick(
            columns,
            "details_json",
            "details",
            "metadata_json",
        )

        if message_column is None:
            return [
                "[WRN] Audit table has no readable message column."
            ]

        normalized_ids = list(
            dict.fromkeys(
                execution_id
                for execution_id in execution_ids
                if execution_id
            )
        )

        if execution_column is None or not normalized_ids:
            return [
                "[INF] No orchestration activity recorded."
            ]

        placeholders = ", ".join(
            "?" for _ in normalized_ids
        )
        order_sql = (
            f'ORDER BY "{timestamp_column}" DESC'
            if timestamp_column
            else ""
        )

        rows = connection.execute(
            f"""
            SELECT *
            FROM "{table}"
            WHERE "{execution_column}" IN ({placeholders})
            {order_sql}
            LIMIT 200
            """,
            tuple(normalized_ids),
        ).fetchall()

        sensitive_terms = {
            "authorization",
            "cookie",
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "header",
        }

        activity: list[str] = []

        for row in reversed(rows):
            stamp = (
                compact_timestamp(str(row[timestamp_column]))
                if (
                    timestamp_column
                    and row[timestamp_column] is not None
                )
                else datetime.now().strftime("%H:%M:%S")
            )

            event_type = (
                str(row[event_type_column]).upper()
                if (
                    event_type_column
                    and row[event_type_column] is not None
                )
                else "INFO"
            )

            actor = (
                str(row[actor_column])
                if actor_column and row[actor_column] is not None
                else "system"
            )

            details_text = ""

            if details_column and row[details_column] is not None:
                try:
                    raw_details = json.loads(
                        str(row[details_column])
                    )
                except (
                    json.JSONDecodeError,
                    TypeError,
                    ValueError,
                ):
                    raw_details = {}

                if isinstance(raw_details, dict):
                    safe_details = {
                        str(key): value
                        for key, value in raw_details.items()
                        if not any(
                            term in str(key).lower()
                            for term in sensitive_terms
                        )
                    }

                    if safe_details:
                        details_text = " | " + ", ".join(
                            f"{key}={value}"
                            for key, value in safe_details.items()
                        )

            activity.append(
                f"{stamp:<19} "
                f"{event_type:<18} "
                f"[{actor}] "
                f"{row[message_column]}"
                f"{details_text}"
            )

        return activity or [
            "[INF] No orchestration activity recorded."
        ]


    def _load_activity(
        self,
        connection: sqlite3.Connection,
        tables: set[str],
        execution_id: str,
    ) -> list[str]:
        table = next(
            (name for name in ("audit_events", "audit_log", "events") if name in tables),
            None,
        )
        if table is None:
            return [
                "[INF] Local database connected in read-only mode.",
                f"[INF] Latest execution loaded: {execution_id}",
            ]

        columns = self._columns(connection, table)
        message_column = self._pick(
            columns,
            "message",
            "event_type",
            "action",
            "event",
        )
        timestamp_column = self._pick(
            columns,
            "created_at",
            "timestamp",
            "occurred_at",
        )
        execution_column = self._pick(columns, "execution_id", "execution")

        if message_column is None:
            return ["[WRN] Audit table has no readable message column."]

        where_sql = ""
        parameters: tuple[Any, ...] = ()
        if execution_column is not None:
            where_sql = f'WHERE "{execution_column}" = ?'
            parameters = (execution_id,)

        order_sql = f'ORDER BY "{timestamp_column}" DESC' if timestamp_column else ""
        rows = connection.execute(
            f'SELECT * FROM "{table}" {where_sql} {order_sql} LIMIT 12',
            parameters,
        ).fetchall()

        activity: list[str] = []
        for row in reversed(rows):
            stamp = (
                compact_timestamp(str(row[timestamp_column]))
                if timestamp_column and row[timestamp_column] is not None
                else datetime.now().strftime("%H:%M:%S")
            )
            activity.append(f"{stamp:<19} INF  {row[message_column]}")
        return activity or ["[INF] No activity recorded."]



SENSITIVE_DISPLAY_VALUE = re.compile(
    r"""(?ix)
    \b(
        authorization
        | cookie
        | password
        | secret
        | token
        | api[_-]?key
        | apikey
        | credential
    )
    \b
    \s*[:=]\s*
    ([^\s&,;]+)
    """
)

URL_USERINFO = re.compile(
    r"(?i)(https?://)[^/@\s]+@"
)


def safe_tui_display(
    value: Any,
    *,
    max_length: int = 96,
    default: str = "—",
) -> str:
    """Return bounded, redacted, markup-safe display text."""

    if value is None:
        text = default
    elif isinstance(value, bool):
        text = str(value).lower()
    elif isinstance(value, (dict, list, tuple, set)):
        text = "[unsupported value]"
    else:
        text = str(value)

    text = " ".join(text.split())
    text = URL_USERINFO.sub(
        r"\1[REDACTED]@",
        text,
    )
    text = SENSITIVE_DISPLAY_VALUE.sub(
        lambda match: (
            f"{match.group(1)}=[REDACTED]"
        ),
        text,
    )

    if max_length < 2:
        raise ValueError("max_length must be at least 2.")

    if len(text) > max_length:
        text = f"{text[: max_length - 1]}…"

    return escape_markup(text)


def parse_execution_metadata(
    row: sqlite3.Row,
    metadata_column: str | None,
) -> dict[str, Any]:
    """Safely parse execution metadata stored as JSON."""

    if metadata_column is None or row[metadata_column] is None:
        return {}

    try:
        payload = json.loads(str(row[metadata_column]))
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}

    return payload if isinstance(payload, dict) else {}


def select_dashboard_execution_rows(
    rows: list[sqlite3.Row],
    metadata_column: str | None,
) -> tuple[sqlite3.Row, list[sqlite3.Row], frozenset[str]]:
    """Select the latest orchestration parent and its child executions."""

    latest = rows[0]
    latest_metadata = parse_execution_metadata(
        latest,
        metadata_column,
    )
    orchestration_id = latest_metadata.get("orchestration_id")

    if not isinstance(orchestration_id, str) or not orchestration_id:
        return latest, rows[:6], frozenset()

    orchestration_rows = [
        row
        for row in rows
        if parse_execution_metadata(
            row,
            metadata_column,
        ).get("orchestration_id")
        == orchestration_id
    ]

    parent = next(
        (
            row
            for row in orchestration_rows
            if parse_execution_metadata(
                row,
                metadata_column,
            ).get("execution_role")
            == "orchestration_parent"
        ),
        latest,
    )

    completed_phases = frozenset(
        str(metadata["phase_code"])
        for row in orchestration_rows
        if (
            (metadata := parse_execution_metadata(
                row,
                metadata_column,
            )).get("execution_role")
            == "orchestration_child"
            and metadata.get("phase_code")
            and str(row["state"]).lower() == "completed"
        )
    )

    child_rows = [
        row
        for row in orchestration_rows
        if parse_execution_metadata(
            row,
            metadata_column,
        ).get("execution_role")
        == "orchestration_child"
    ]

    return parent, child_rows[:7], completed_phases




def execution_order_sql(
    updated_column: str | None,
    completed_column: str | None,
    created_column: str | None,
) -> str:
    """Order executions by their latest workflow activity."""

    columns = [
        column
        for column in (
            updated_column,
            completed_column,
            created_column,
        )
        if column is not None
    ]

    if not columns:
        return ""

    expression = ", ".join(f'"{column}" DESC' for column in columns)
    return f"ORDER BY {expression}"


def parse_datetime(value: str) -> datetime | None:
    if not value or value == "—":
        return None
    candidate = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def calculate_duration(started: str, completed: str) -> str:
    start = parse_datetime(started)
    end = parse_datetime(completed)
    if start is None or end is None:
        return "—"

    seconds = max(0, int((end - start).total_seconds()))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02}:{minutes:02}:{seconds:02}"


def compact_timestamp(value: str) -> str:
    parsed = parse_datetime(value)
    if parsed is None:
        return value[:19] if value else "—"
    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def infer_phase(
    state: str,
    evidence_types: Iterable[str] = (),
) -> str:
    """Infer the latest completed workflow from execution evidence."""

    normalized = state.lower()
    normalized_evidence = {evidence_type.strip().lower() for evidence_type in evidence_types}

    if normalized == "completed":
        if "attack_hypothesis_set" in normalized_evidence:
            return "6A — ATTACK HYPOTHESIS & PATH GENERATION"
        if (
            "controlled_nuclei_execution"
            in normalized_evidence
        ):
            return "6C — LOW-RISK NUCLEI VALIDATOR"
        if (
            "controlled_validation_observation"
            in normalized_evidence
        ):
            return "6C — LOW-RISK HTTP VALIDATOR"
        if "confirmation_result" in normalized_evidence:
            return "4D — CONFIRMATION ENGINE"
        if "oast_observation" in normalized_evidence:
            return "4C — OAST MANAGER"
        if "blind_validation_result" in normalized_evidence:
            return "4B — BLIND VALIDATION"
        if "direct_check_result" in normalized_evidence:
            return "4A — DIRECT VULNERABILITY CHECKS"
        if "javascript_intelligence_result" in normalized_evidence:
            return "3E — JAVASCRIPT INTELLIGENCE"
        if "crawl_result" in normalized_evidence:
            return "3D — CRAWLING & URL INTELLIGENCE"
        if "http_intelligence_result" in normalized_evidence:
            return "3C — LIVE HOST INTELLIGENCE"
        if "subdomain_result" in normalized_evidence:
            return "3B — SUBDOMAIN ENUMERATION"
        if "dns_result" in normalized_evidence:
            return "3A — DNS INTELLIGENCE"

        # Preserve compatibility with executions created before evidence-aware TUI.
        return "3B — SUBDOMAIN ENUMERATION"

    if normalized in {"running", "analyzing"}:
        if "attack_hypothesis_set" in normalized_evidence:
            return "6A — ATTACK HYPOTHESIS & PATH GENERATION"
        if (
            "controlled_nuclei_execution"
            in normalized_evidence
        ):
            return "6C — LOW-RISK NUCLEI VALIDATOR"
        if (
            "controlled_validation_observation"
            in normalized_evidence
        ):
            return "6C — LOW-RISK HTTP VALIDATOR"
        if "confirmation_result" in normalized_evidence:
            return "4D — CONFIRMATION ENGINE"
        if "oast_observation" in normalized_evidence:
            return "4C — OAST MANAGER"
        if "blind_validation_result" in normalized_evidence:
            return "4B — BLIND VALIDATION"
        if "direct_check_result" in normalized_evidence:
            return "4A — DIRECT VULNERABILITY CHECKS"
        if "javascript_intelligence_result" in normalized_evidence:
            return "4A — DIRECT VULNERABILITY CHECKS"
        if "crawl_result" in normalized_evidence:
            return "3E — JAVASCRIPT INTELLIGENCE"
        if "http_intelligence_result" in normalized_evidence:
            return "3D — CRAWLING & URL INTELLIGENCE"
        if "subdomain_result" in normalized_evidence:
            return "3C — LIVE HOST INTELLIGENCE"
        if "dns_result" in normalized_evidence:
            return "3B — SUBDOMAIN ENUMERATION"
        return "ACTIVE WORKFLOW"

    if normalized in {"planned", "created"}:
        if "attack_hypothesis_set" in normalized_evidence:
            return "6A — ATTACK HYPOTHESIS & PATH GENERATION"
        if (
            "controlled_nuclei_preparation"
            in normalized_evidence
        ):
            return "6C — NUCLEI VALIDATOR PREPARATION"
        if "controlled_nuclei_preview" in normalized_evidence:
            return "6C — NUCLEI VALIDATOR PREVIEW"
        if "controlled_validation_plan" in normalized_evidence:
            return "6B — CONTROLLED VALIDATION PLAN"
        return "PLANNING"

    if normalized == "failed":
        if "attack_hypothesis_set" in normalized_evidence:
            return "6A — ATTACK HYPOTHESIS REVIEW"
        if (
            "controlled_nuclei_execution"
            in normalized_evidence
        ):
            return "6C — LOW-RISK NUCLEI VALIDATOR REVIEW"
        if (
            "controlled_validation_observation"
            in normalized_evidence
        ):
            return "6C — LOW-RISK HTTP VALIDATOR REVIEW"
        return "EXECUTION REVIEW"

    return "CURRENT WORKFLOW"


def infer_phase_short(
    state: str,
    evidence_types: Iterable[str] = (),
) -> str:
    """Return the compact phase label used by the execution table."""

    phase = infer_phase(state, evidence_types)

    if phase.startswith("6A"):
        return "6A"
    if phase.startswith("6C"):
        return "6C"
    if phase.startswith("6B"):
        return "6B"
    if phase.startswith("4D"):
        return "4D"
    if phase.startswith("4C"):
        return "4C"
    if phase.startswith("4B"):
        return "4B"
    if phase.startswith("4A"):
        return "4A"
    if phase.startswith("3E"):
        return "3E"
    if phase.startswith("3D"):
        return "3D"
    if phase.startswith("3C"):
        return "3C"
    if phase.startswith("3B"):
        return "3B"
    if phase.startswith("3A"):
        return "3A"
    if phase == "ACTIVE WORKFLOW":
        return "ACTIVE"
    if phase == "PLANNING":
        return "PLAN"
    if phase == "EXECUTION REVIEW":
        return "REVIEW"

    return "—"


def progress_for_state(state: str) -> int:
    return {
        "created": 10,
        "planned": 20,
        "running": 55,
        "analyzing": 80,
        "completed": 100,
        "failed": 100,
    }.get(state.lower(), 35)


def demo_snapshot(activity: list[str] | None = None) -> DashboardSnapshot:
    return DashboardSnapshot(
        project_name="Black Hat MEA Demo",
        execution_id="execution-demo-read-only",
        target_scope="*.authorized-example.test",
        authorization="CONFIRMED",
        mode="LOCAL / SAFE + SMART",
        current_phase="3E — JAVASCRIPT INTELLIGENCE",
        phase_progress=100,
        evidence_count=3,
        finding_count=0,
        execution_state="completed",
        recent_executions=[
            {
                "execution_id": "execution-demo-read-only",
                "phase": "3E",
                "target": "*.authorized-example.test",
                "status": "COMPLETED",
                "started": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "duration": "00:03:24",
                "evidence": "3",
                "findings": "0",
            }
        ],
        recent_activity=activity
        or [
            "2026-08-01 01:50:02 INF  DNS intelligence collected.",
            "2026-08-01 01:50:18 INF  Subdomain enumeration completed.",
            "2026-08-02 09:42:10 INF  Live-host intelligence completed.",
            "2026-08-02 09:42:11 INF  HTTP intelligence evidence registered.",
            "2026-08-02 20:15:57 INF  URL crawling completed.",
            "2026-08-02 20:15:57 INF  Crawl evidence registered.",
            "2026-08-02 22:35:00 INF  JavaScript intelligence completed.",
            "2026-08-02 22:35:00 INF  JavaScript evidence registered.",
        ],
    )


BASE_PHASES = [
    ("3A", "DNS Intelligence"),
    ("3B", "Subdomain Enumeration"),
    ("3C", "Live Host Intelligence"),
    ("3D", "Crawling & URL Intelligence"),
    ("3E", "JavaScript Intelligence"),
    ("4A", "Direct Vulnerability Checks"),
    ("4B", "Blind Validation"),
    ("4C", "OAST Manager"),
    ("4D", "Confirmation Engine"),
]


def normalize_phase_code(phase_code: str) -> str:
    """Normalize orchestration child phase identifiers for the TUI."""

    normalized = phase_code.strip()

    if normalized.startswith("4A-"):
        return "4A"

    return normalized


def phase_rows(
    current_phase: str,
    completed_phases: Iterable[str] = (),
) -> list[tuple[str, str, str, str, str]]:
    """Build workflow rows from explicit orchestration state when available."""

    normalized_completed = {
        normalize_phase_code(code)
        for code in completed_phases
    }

    if normalized_completed:
        rows: list[tuple[str, str, str, str, str]] = []
        phase_codes = [code for code, _ in BASE_PHASES]

        completed_indexes = [
            phase_codes.index(code)
            for code in normalized_completed
            if code in phase_codes
        ]
        latest_completed_index = (
            max(completed_indexes)
            if completed_indexes
            else -1
        )

        for index, (code, name) in enumerate(BASE_PHASES):
            if code in normalized_completed:
                marker = "✓"
                status = "DONE"
            elif index == latest_completed_index + 1:
                marker = "→"
                status = "NEXT"
            else:
                marker = "·"
                status = "PLANNED"

            rows.append((marker, code, name, status, "—"))

        return rows

    current_code = current_phase.split(" ", 1)[0]
    phase_codes = [code for code, _ in BASE_PHASES]

    try:
        current_index = phase_codes.index(current_code)
    except ValueError:
        current_index = -1

    rows = []

    for index, (code, name) in enumerate(BASE_PHASES):
        if current_index == -1:
            marker = "·"
            status = "PLANNED"
        elif index <= current_index:
            marker = "✓"
            status = "DONE"
        elif index == current_index + 1:
            marker = "→"
            status = "NEXT"
        else:
            marker = "·"
            status = "PLANNED"

        rows.append((marker, code, name, status, "—"))

    return rows


TOOLS = [
    ("subfinder", "Subdomain Discovery", "ENABLED"),
    ("amass", "Passive Asset Discovery", "ENABLED"),
    ("assetfinder", "Passive Asset Discovery", "ENABLED"),
    ("crt.sh", "Certificate Transparency", "ENABLED"),
    ("httpx", "Live Host & Service Probe", "ENABLED"),
    ("katana", "Web Crawler", "ENABLED"),
    ("Saarthi 6A", "Attack Hypothesis Engine", "ENABLED"),
    ("nuclei", "Controlled Preview / Execution", "APPROVAL"),
    ("sqlmap", "SQL Injection Testing", "PHASE 4A"),
    ("ghauri", "Blind SQLi Cross-check", "PHASE 4B"),
    ("Saarthi JS", "JavaScript Intelligence", "ENABLED"),
    ("OAST Manager", "Out-of-band Correlation", "PHASE 4C"),
]


def build_scope_lines(
    snapshot: DashboardSnapshot,
) -> list[str]:
    """Build safe read-only scope-panel lines for one snapshot."""

    status_value = snapshot.orchestration_status.upper()

    if snapshot.orchestration_status == "partial":
        status_display = (
            "[yellow]PARTIAL — REVIEW REQUIRED[/yellow]"
        )
    elif snapshot.orchestration_status == "completed":
        status_display = "[green]COMPLETED[/green]"
    elif snapshot.orchestration_status == "failed":
        status_display = "[red]FAILED[/red]"
    else:
        status_display = status_value

    scope_lines = [
        f"Project Name       : {snapshot.project_name}",
        f"Execution ID       : {snapshot.execution_id}",
        f"Target Scope       : {snapshot.target_scope}",
        "Authorization      : [green]✓ CONFIRMED[/green]",
        "Rules of Engagement: [green]✓ ACCEPTED[/green]",
        "Data Handling      : LOCAL ONLY",
        f"Mode               : {snapshot.mode}",
        f"Current Phase      : {snapshot.current_phase}",
        (
            "Evidence / Findings: "
            f"{snapshot.evidence_count} / "
            f"{snapshot.finding_count}"
        ),
    ]

    if snapshot.orchestration_status != "unknown":
        counts = snapshot.outcome_counts

        scope_lines.extend(
            [
                f"Orchestration      : {status_display}",
                (
                    "Phase Outcomes     : "
                    f"{counts.get('completed', 0)} completed · "
                    f"{counts.get('skipped', 0)} skipped · "
                    f"{counts.get('failed', 0)} failed"
                ),
                (
                    "Required / Optional: "
                    f"{counts.get('required', 0)} / "
                    f"{counts.get('optional', 0)}"
                ),
            ]
        )

    if snapshot.attack_hypothesis_set:
        hypothesis_set = snapshot.attack_hypothesis_set

        def hypothesis_value(
            key: str,
            *,
            max_length: int = 96,
        ) -> str:
            return safe_tui_display(
                hypothesis_set.get(key),
                max_length=max_length,
            )

        scope_lines.extend(
            [
                "",
                "[bold cyan]PHASE 6A — ATTACK HYPOTHESES[/bold cyan]",
                (
                    "Evidence ID        : "
                    f"{hypothesis_value('evidence_id', max_length=72)}"
                ),
                (
                    "Target             : "
                    f"{hypothesis_value('target_url', max_length=88)}"
                ),
                (
                    "Hypothesis Count   : "
                    f"{hypothesis_value('hypothesis_count', max_length=12)}"
                ),
                (
                    "Families           : "
                    f"{hypothesis_value('families', max_length=120)}"
                ),
                (
                    "Hypothesis IDs     : "
                    f"{hypothesis_value('hypothesis_ids', max_length=120)}"
                ),
                (
                    "Evidence Considered: "
                    f"{hypothesis_value('considered_evidence_count', max_length=12)}"
                ),
                (
                    "Evidence Rejected  : "
                    f"{hypothesis_value('rejected_evidence_count', max_length=12)}"
                ),
                (
                    "Output Truncated   : "
                    f"{hypothesis_value('truncated', max_length=12)}"
                ),
                (
                    "Executed           : "
                    f"{hypothesis_value('executed', max_length=12)}"
                ),
                (
                    "Network Activity   : "
                    f"{hypothesis_value('network_activity', max_length=12)}"
                ),
                (
                    "Payload Generated  : "
                    f"{hypothesis_value('payload_generated', max_length=12)}"
                ),
                (
                    "Subprocess Started : "
                    f"{hypothesis_value('subprocess_started', max_length=12)}"
                ),
                (
                    "Evidence SHA-256   : "
                    f"{hypothesis_value('evidence_sha256', max_length=72)}"
                ),
                (
                    "[dim]Read-only Phase 6A candidate paths generated "
                    "from redacted evidence metadata. No validation or "
                    "security test was executed.[/dim]"
                ),
            ]
        )

    elif snapshot.controlled_observation:
        observation = snapshot.controlled_observation

        def observation_value(
            key: str,
            *,
            max_length: int = 96,
        ) -> str:
            return safe_tui_display(
                observation.get(key),
                max_length=max_length,
            )

        scope_lines.extend(
            [
                "",
                "[bold cyan]CONTROLLED OBSERVATION[/bold cyan]",
                (
                    "Observation ID     : "
                    f"{observation_value('evidence_id', max_length=72)}"
                ),
                (
                    "Target / Action    : "
                    f"{observation_value('target_url', max_length=88)} · "
                    f"{observation_value('action', max_length=40)}"
                ),
                (
                    "Method / Status    : "
                    f"{observation_value('method', max_length=12)} · "
                    f"HTTP {observation_value('status_code', max_length=12)}"
                ),
                (
                    "Captured / Truncated: "
                    f"{observation_value('body_bytes_captured', max_length=20)} bytes · "
                    f"{observation_value('body_truncated', max_length=12)}"
                ),
                (
                    "Body SHA-256       : "
                    f"{observation_value('body_sha256', max_length=72)}"
                ),
                (
                    "Plan Evidence      : "
                    f"{observation_value('plan_evidence_id', max_length=72)}"
                ),
                (
                    "Network Activity   : "
                    f"{observation_value('network_activity', max_length=12)}"
                ),
                (
                    "Request Attempted  : "
                    f"{observation_value('request_attempted', max_length=12)}"
                ),
                (
                    "Evidence Reused    : "
                    f"{observation_value('reused_existing_evidence', max_length=12)}"
                ),
                (
                    "Second Request Sent: "
                    f"{observation_value('second_request_sent', max_length=12)}"
                ),
                (
                    "Redirects Followed : "
                    f"{observation_value('follow_redirects', max_length=12)}"
                ),
                (
                    "Evidence SHA-256   : "
                    f"{observation_value('evidence_sha256', max_length=72)}"
                ),
            ]
        )

        if snapshot.execution_state.lower() == "failed":
            scope_lines.append(
                "[yellow]Failure Guidance   : Automatic retry is "
                "disabled. Review the audit log and create a new "
                "approved execution before another observation."
                "[/yellow]"
            )

    elif snapshot.controlled_nuclei_execution:
        execution = snapshot.controlled_nuclei_execution

        def nuclei_execution_value(
            key: str,
            *,
            max_length: int = 96,
        ) -> str:
            return safe_tui_display(
                execution.get(key),
                max_length=max_length,
            )

        scope_lines.extend(
            [
                "",
                "[bold cyan]CONTROLLED NUCLEI EXECUTION[/bold cyan]",
                (
                    "Evidence ID        : "
                    f"{nuclei_execution_value('evidence_id', max_length=72)}"
                ),
                (
                    "Preparation        : "
                    f"{nuclei_execution_value('preparation_evidence_id', max_length=72)}"
                ),
                (
                    "Tool / Target      : "
                    f"{nuclei_execution_value('tool_name', max_length=20)} · "
                    f"{nuclei_execution_value('target_url', max_length=88)}"
                ),
                (
                    "Executable         : "
                    f"{nuclei_execution_value('executable', max_length=88)}"
                ),
                (
                    "Arguments          : "
                    f"{nuclei_execution_value('arguments', max_length=120)}"
                ),
                (
                    "Exit / Timed Out   : "
                    f"{nuclei_execution_value('exit_code', max_length=12)} · "
                    f"{nuclei_execution_value('timed_out', max_length=12)}"
                ),
                (
                    "Output Bytes       : stdout "
                    f"{nuclei_execution_value('stdout_bytes', max_length=20)} · stderr "
                    f"{nuclei_execution_value('stderr_bytes', max_length=20)}"
                ),
                (
                    "Output Truncated   : stdout "
                    f"{nuclei_execution_value('stdout_truncated', max_length=12)} · stderr "
                    f"{nuclei_execution_value('stderr_truncated', max_length=12)}"
                ),
                (
                    "Started            : "
                    f"{nuclei_execution_value('started_at', max_length=40)}"
                ),
                (
                    "Completed          : "
                    f"{nuclei_execution_value('completed_at', max_length=40)}"
                ),
                (
                    "Executed           : "
                    f"{nuclei_execution_value('executed', max_length=12)}"
                ),
                (
                    "Network Activity   : "
                    f"{nuclei_execution_value('network_activity', max_length=12)}"
                ),
                (
                    "Subprocess Started : "
                    f"{nuclei_execution_value('subprocess_started', max_length=12)}"
                ),
                (
                    "Runner Invoked     : "
                    f"{nuclei_execution_value('runner_invoked', max_length=12)}"
                ),
                (
                    "Executable Resolved: "
                    f"{nuclei_execution_value('executable_resolved', max_length=12)}"
                ),
                (
                    "Automatic Retry    : "
                    f"{nuclei_execution_value('automatic_retry', max_length=12)}"
                ),
                (
                    "Evidence SHA-256   : "
                    f"{nuclei_execution_value('evidence_sha256', max_length=72)}"
                ),
                (
                    "[dim]Read-only Phase 6C execution evidence. "
                    "Automatic retry remains disabled.[/dim]"
                ),
            ]
        )

        if snapshot.execution_state.lower() == "failed":
            scope_lines.append(
                "[yellow]Failure Guidance   : Review the bounded stdout, "
                "stderr, and audit trail before creating a new approved "
                "execution. Automatic retry is disabled.[/yellow]"
            )

    elif snapshot.controlled_nuclei_preparation:
        preparation = snapshot.controlled_nuclei_preparation

        def preparation_value(
            key: str,
            *,
            max_length: int = 96,
        ) -> str:
            return safe_tui_display(
                preparation.get(key),
                max_length=max_length,
            )

        scope_lines.extend(
            [
                "",
                "[bold cyan]CONTROLLED NUCLEI PREPARATION[/bold cyan]",
                (
                    "Evidence ID        : "
                    f"{preparation_value('evidence_id', max_length=72)}"
                ),
                (
                    "Preview Evidence   : "
                    f"{preparation_value('preview_evidence_id', max_length=72)}"
                ),
                (
                    "Tool / Target      : "
                    f"{preparation_value('tool_name', max_length=20)} · "
                    f"{preparation_value('target_url', max_length=88)}"
                ),
                (
                    "Rate / Concurrency : "
                    f"{preparation_value('rate_limit_per_second', max_length=12)} req/s · "
                    f"{preparation_value('concurrency', max_length=12)}"
                ),
                (
                    "Request Timeout    : "
                    f"{preparation_value('request_timeout_seconds', max_length=12)} seconds"
                ),
                (
                    "Process Timeout    : "
                    f"{preparation_value('process_timeout_seconds', max_length=12)} seconds"
                ),
                (
                    "Output Cap / Stream: "
                    f"{preparation_value('max_output_bytes', max_length=20)} bytes"
                ),
                (
                    "Arguments          : "
                    f"{preparation_value('arguments', max_length=120)}"
                ),
                (
                    "Executed           : "
                    f"{preparation_value('executed', max_length=12)}"
                ),
                (
                    "Network Activity   : "
                    f"{preparation_value('network_activity', max_length=12)}"
                ),
                (
                    "Subprocess Started : "
                    f"{preparation_value('subprocess_started', max_length=12)}"
                ),
                (
                    "Runner Invoked     : "
                    f"{preparation_value('runner_invoked', max_length=12)}"
                ),
                (
                    "Executable Resolved: "
                    f"{preparation_value('executable_resolved', max_length=12)}"
                ),
                (
                    "Evidence Reused    : "
                    f"{preparation_value('reused_existing_evidence', max_length=12)}"
                ),
                (
                    "Evidence SHA-256   : "
                    f"{preparation_value('evidence_sha256', max_length=72)}"
                ),
                (
                    "[dim]Read-only preparation evidence. The runner was not "
                    "invoked, no executable was resolved, Nuclei was not "
                    "started, and no network request was sent.[/dim]"
                ),
            ]
        )

    elif snapshot.controlled_nuclei_preview:
        preview = snapshot.controlled_nuclei_preview

        def preview_value(
            key: str,
            *,
            max_length: int = 96,
        ) -> str:
            return safe_tui_display(
                preview.get(key),
                max_length=max_length,
            )

        scope_lines.extend(
            [
                "",
                "[bold cyan]CONTROLLED NUCLEI PREVIEW[/bold cyan]",
                (
                    "Evidence ID        : "
                    f"{preview_value('evidence_id', max_length=72)}"
                ),
                (
                    "Tool / Target      : "
                    f"{preview_value('tool_name', max_length=20)} · "
                    f"{preview_value('target_url', max_length=88)}"
                ),
                (
                    "Rate / Concurrency : "
                    f"{preview_value('rate_limit_per_second', max_length=12)} req/s · "
                    f"{preview_value('concurrency', max_length=12)}"
                ),
                (
                    "Timeout            : "
                    f"{preview_value('timeout_seconds', max_length=12)} seconds"
                ),
                (
                    "Allowed Tags       : "
                    f"{preview_value('allowed_tags', max_length=88)}"
                ),
                (
                    "Excluded Tags      : "
                    f"{preview_value('excluded_tags', max_length=88)}"
                ),
                (
                    "Arguments          : "
                    f"{preview_value('arguments', max_length=120)}"
                ),
                (
                    "Executed           : "
                    f"{preview_value('executed', max_length=12)}"
                ),
                (
                    "Network Activity   : "
                    f"{preview_value('network_activity', max_length=12)}"
                ),
                (
                    "Subprocess Started : "
                    f"{preview_value('subprocess_started', max_length=12)}"
                ),
                (
                    "Evidence Reused    : "
                    f"{preview_value('reused_existing_evidence', max_length=12)}"
                ),
                (
                    "Evidence SHA-256   : "
                    f"{preview_value('evidence_sha256', max_length=72)}"
                ),
                (
                    "[dim]Preview only. Nuclei was not started and "
                    "no network request was sent.[/dim]"
                ),
            ]
        )

    if snapshot.optional_failure_summary:
        scope_lines.append(
            "[yellow]Optional Failure   : "
            f"{safe_tui_display(snapshot.optional_failure_summary, max_length=160)}"
            "[/yellow]"
        )

    return scope_lines


class SaarthiDashboard(App[None]):
    CSS_PATH = "styles.tcss"
    TITLE = "Saarthi OPS"

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("p", "focus_phases", "Phases"),
        ("t", "focus_tools", "Tools"),
        ("e", "focus_executions", "Evidence"),
        ("h", "help", "Help"),
    ]

    snapshot: reactive[DashboardSnapshot] = reactive(demo_snapshot)

    def __init__(self, database_path: Path = DEFAULT_DB_PATH) -> None:
        super().__init__()
        self.repository = ReadOnlySaarthiRepository(database_path)

    def compose(self) -> ComposeResult:
        with Grid(id="hero"):
            with Vertical(id="brand-block"):
                yield Label("SAARTHI OPS", id="brand-title")
                yield Label(
                    "LOCAL-FIRST · PRIVACY-FIRST · OPERATOR-FIRST",
                    id="brand-tagline",
                )

            with Vertical(id="hero-center"):
                yield Label("SAARTHI OPS", id="hero-title")
                yield Label(
                    "AI-assisted authorized VAPT platform",
                    id="hero-subtitle",
                )

            yield Static(id="runtime-panel")

        with Grid(id="top-grid"):
            with Vertical(classes="panel", id="scope-panel"):
                yield Label("[ 1. PROJECT & SCOPE ]", classes="panel-title")
                yield Static(id="scope-content")
                yield Label("PHASE PROGRESS", classes="section-label")
                yield ProgressBar(total=100, show_eta=False, id="phase-progress")

            with Vertical(classes="panel", id="phase-panel"):
                yield Label("[ 2. WORKFLOW STATUS ]", classes="panel-title")
                yield DataTable(id="phase-table")

            with Vertical(classes="panel", id="tools-panel"):
                yield Label("[ 3. ENABLED TOOLS ]", classes="panel-title")
                yield DataTable(id="tools-table")
                yield Static(
                    "LOCAL EXECUTION · CONTROLLED ADAPTERS · NO RAW SHELL",
                    id="tools-note",
                )

        with Vertical(classes="panel", id="executions-panel"):
            yield Label("[ 4. RECENT EXECUTIONS ]", classes="panel-title")
            yield DataTable(id="executions-table")

        with Vertical(classes="panel", id="activity-panel"):
            with Horizontal(id="activity-heading"):
                yield Label("[ 5. ACTIVITY LOG (LIVE) ]", classes="panel-title")
                yield Label("LATEST 200 EVENTS", id="activity-caption")
            yield Log(id="activity-log", highlight=True, max_lines=250)

        with Grid(id="system-status"):
            yield Label("LOCAL DB", classes="system-key")
            yield Label("● ONLINE", classes="system-ok")
            yield Label("MODE", classes="system-key")
            yield Label("READ-ONLY", classes="system-value")
            yield Label("OAST", classes="system-key")
            yield Label("○ OFFLINE", classes="system-warn")

        yield Footer()

    def on_mount(self) -> None:
        self._configure_tables()
        self.set_interval(1.0, self._update_runtime)
        self.set_interval(
            1.0,
            self._refresh_snapshot_silently,
        )
        self.action_refresh()

    def _configure_tables(self) -> None:
        phase_table = self.query_one("#phase-table", DataTable)
        phase_table.add_columns("", "Phase", "Name", "Status", "Completed")
        phase_table.cursor_type = "row"
        phase_table.zebra_stripes = True

        tools_table = self.query_one("#tools-table", DataTable)
        tools_table.add_columns("Tool", "Purpose", "Status")
        tools_table.cursor_type = "row"
        tools_table.zebra_stripes = True

        executions = self.query_one("#executions-table", DataTable)
        executions.add_columns(
            "Execution ID",
            "Phase",
            "Started",
            "Duration",
            "Target",
            "Evidence",
            "Findings",
            "Status",
        )
        executions.cursor_type = "row"
        executions.zebra_stripes = True

    def _update_runtime(self) -> None:
        now = datetime.now()
        runtime = (
            "[cyan]HOST[/cyan] : saarthi-ops.local\n"
            "[cyan]USER[/cyan] : operator\n"
            "[cyan]MODE[/cyan] : LOCAL\n"
            "[cyan]DATA[/cyan] : Local Only\n"
            "────────────────────────\n"
            f"[bold cyan]{now:%H:%M:%S}[/bold cyan]  "
            f"{now:%Y-%m-%d}\n"
            "UTC+04:00"
        )
        self.query_one("#runtime-panel", Static).update(runtime)

    def watch_snapshot(self, snapshot: DashboardSnapshot) -> None:
        if self.is_mounted:
            self._render_snapshot(snapshot)

    def _render_snapshot(self, snapshot: DashboardSnapshot) -> None:
        scope_lines = build_scope_lines(snapshot)

        self.query_one("#scope-content", Static).update(
            "\n".join(scope_lines)
        )
        self.query_one("#phase-progress", ProgressBar).update(progress=snapshot.phase_progress)

        phase_table = self.query_one("#phase-table", DataTable)
        phase_table.clear()
        for row in phase_rows(
            snapshot.current_phase,
            snapshot.completed_phases,
        ):
            phase_table.add_row(*row)

        tools_table = self.query_one("#tools-table", DataTable)
        tools_table.clear()
        for row in TOOLS:
            tools_table.add_row(*row)

        executions = self.query_one("#executions-table", DataTable)
        executions.clear()
        for item in snapshot.recent_executions:
            executions.add_row(
                item["execution_id"],
                item["phase"],
                item["started"],
                item["duration"],
                item["target"],
                item["evidence"],
                item["findings"],
                item["status"],
            )

        activity = self.query_one("#activity-log", Log)
        activity.clear()
        for line in snapshot.recent_activity:
            activity.write_line(line)

    def _refresh_snapshot_silently(self) -> None:
        """Reload local state without creating notification noise."""

        try:
            latest_snapshot = self.repository.load()
        except Exception:
            return

        if latest_snapshot != self.snapshot:
            self.snapshot = latest_snapshot

    def action_refresh(self) -> None:
        self.snapshot = self.repository.load()
        self._update_runtime()
        self.notify(
            "Dashboard refreshed from the local "
            "read-only database."
        )

    def action_focus_phases(self) -> None:
        self.query_one("#phase-table", DataTable).focus()

    def action_focus_tools(self) -> None:
        self.query_one("#tools-table", DataTable).focus()

    def action_focus_executions(self) -> None:
        self.query_one("#executions-table", DataTable).focus()

    def action_help(self) -> None:
        self.notify(
            "R refresh · P phases · T tools · E executions · Q quit",
            timeout=5,
        )


def run() -> None:
    SaarthiDashboard().run()


if __name__ == "__main__":
    run()
