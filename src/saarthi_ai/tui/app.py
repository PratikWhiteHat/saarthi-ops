from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from rich.markup import escape as escape_markup
from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Grid, Horizontal, Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Input,
    Label,
    ProgressBar,
    RichLog,
    Static,
)

from saarthi_ai.controlled_validation.validator_registry import (
    summarize_phase6_validator_modules,
    validator_module_tool_rows,
)
from saarthi_ai.execution.tool_runner import terminate_active_tools

DEFAULT_DB_PATH = Path.home() / ".saarthi" / "saarthi.db"

# Real-time activity feed limits. The dashboard streams every tool and
# phase audit event across the whole orchestration; these bound how much
# scrollback is retained in memory and in the on-screen log widget.
MAX_ACTIVITY_EVENTS = 2000
MAX_LIVE_VALIDATION_LINES = 2000
MAX_ACTIVITY_LOG_LINES = MAX_ACTIVITY_EVENTS + MAX_LIVE_VALIDATION_LINES + 100
DASHBOARD_REFRESH_SECONDS = 0.5

# Idle labels for the TARGET & AUTHORIZE bar (restored when no run is
# active; overridden with the live target + stage while a run is in flight).
AUTHORIZE_BUTTON_LABEL = "AUTHORIZE & RUN ▶"
AUTHORIZE_NOTE_IDLE = (
    "Authorize runs ALL phases: recon → Phase 6 → "
    "nuclei + sqlmap   ·   [u] focus URL"
)


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
    controlled_validation_plan: dict[str, str] | None = None
    controlled_observation: dict[str, str] | None = None
    controlled_nuclei_execution: dict[str, str] | None = None
    controlled_nuclei_preparation: dict[str, str] | None = None
    controlled_nuclei_preview: dict[str, str] | None = None
    phase6_chain_status: dict[str, str] = field(default_factory=dict)
    recent_worker_jobs: list[dict[str, str]] = field(default_factory=list)


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

        latest_metadata = parse_execution_metadata(
            latest,
            metadata_column,
        )
        orchestration_id = latest_metadata.get("orchestration_id")
        related_rows = [
            row
            for row in rows
            if (
                isinstance(orchestration_id, str)
                and orchestration_id
                and parse_execution_metadata(
                    row,
                    metadata_column,
                ).get("orchestration_id")
                == orchestration_id
            )
        ] or [latest, *display_rows]

        orchestration_execution_ids = [
            str(row[id_column])
            for row in related_rows
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
            row_metadata = parse_execution_metadata(
                row,
                metadata_column,
            )
            row_evidence_count = self._count_related(
                connection,
                tables,
                ("evidence", "evidence_items"),
                row_execution_id,
            )
            row_finding_count = self._count_findings(
                connection,
                tables,
                row_execution_id,
            )

            recent_executions.append(
                {
                    "execution_id": row_execution_id,
                    "phase": str(
                        phase_execution_label(row_metadata)
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
                    "evidence": str(row_evidence_count),
                    "findings": str(row_finding_count),
                }
            )

        evidence_count = sum(
            self._count_related(
                connection,
                tables,
                ("evidence", "evidence_items"),
                related_execution_id,
            )
            for related_execution_id in orchestration_execution_ids
        )
        evidence_types = self._evidence_types(
            connection,
            tables,
            execution_id,
        )
        finding_count = sum(
            self._count_findings(
                connection,
                tables,
                related_execution_id,
            )
            for related_execution_id in orchestration_execution_ids
        )

        (
            orchestration_status,
            outcome_counts,
            optional_failure_summary,
        ) = self._load_orchestration_outcome(
            connection,
            tables,
            execution_id,
        )
        phase6_chain_status = build_phase6_chain_status(
            related_rows,
            metadata_column,
            state_column,
        )

        attack_hypothesis_set = next(
            (
                summary
                for related_execution_id in orchestration_execution_ids
                if (
                    summary
                    := self._load_attack_hypothesis_set(
                        connection,
                        tables,
                        related_execution_id,
                    )
                )
            ),
            None,
        )

        controlled_validation_plan = next(
            (
                summary
                for related_execution_id in orchestration_execution_ids
                if (
                    summary
                    := self._load_controlled_validation_plan(
                        connection,
                        tables,
                        related_execution_id,
                    )
                )
            ),
            None,
        )

        controlled_observation = next(
            (
                summary
                for related_execution_id in orchestration_execution_ids
                if (
                    summary
                    := self._load_controlled_validation_observation(
                        connection,
                        tables,
                        related_execution_id,
                    )
                )
            ),
            None,
        )

        if controlled_observation is not None:
            reuse = self._load_controlled_observation_reuse(
                connection,
                tables,
                controlled_observation.get(
                    "execution_id",
                    execution_id,
                ),
                controlled_observation["evidence_id"],
            )
            controlled_observation.update(reuse)

        controlled_nuclei_execution = next(
            (
                summary
                for related_execution_id in orchestration_execution_ids
                if (
                    summary
                    := self._load_controlled_nuclei_execution(
                        connection,
                        tables,
                        related_execution_id,
                    )
                )
            ),
            None,
        )
        if controlled_nuclei_execution is not None:
            if (
                controlled_nuclei_execution.get("timed_out")
                == "true"
            ):
                phase6_chain_status["nuclei"] = "TIMED OUT"
            elif phase6_chain_status.get("nuclei") != "FAILED":
                phase6_chain_status["nuclei"] = "EXECUTED"

        if phase6_chain_status.get("nuclei") in {
            "FAILED",
            "TIMED OUT",
        }:
            orchestration_status = "partial"
            outcome_counts = dict(outcome_counts)
            outcome_counts["failed"] = max(
                outcome_counts.get("failed", 0),
                1,
            )
            optional_failure_summary = (
                optional_failure_summary
                or "6C Nuclei: optional bounded execution did not complete."
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

        controlled_nuclei_preview = next(
            (
                summary
                for related_execution_id in orchestration_execution_ids
                if (
                    summary
                    := self._load_controlled_nuclei_preview(
                        connection,
                        tables,
                        related_execution_id,
                    )
                )
            ),
            None,
        )

        if controlled_nuclei_preview is not None:
            preview_reuse = self._load_nuclei_preview_reuse(
                connection,
                tables,
                controlled_nuclei_preview.get(
                    "execution_id",
                    execution_id,
                ),
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
            current_phase=current_phase_for_dashboard(
                execution_state,
                evidence_types,
                completed_phases,
                phase6_chain_status,
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
            controlled_validation_plan=controlled_validation_plan,
            controlled_observation=controlled_observation,
            controlled_nuclei_execution=controlled_nuclei_execution,
            controlled_nuclei_preparation=(
                controlled_nuclei_preparation
            ),
            controlled_nuclei_preview=controlled_nuclei_preview,
            phase6_chain_status=phase6_chain_status,
            recent_worker_jobs=self._load_worker_jobs(
                connection,
                tables,
                orchestration_execution_ids,
            ),
        )

    def _load_worker_jobs(
        self,
        connection: sqlite3.Connection,
        tables: set[str],
        execution_ids: list[str],
    ) -> list[dict[str, str]]:
        """Load recent restricted-worker states without mutating the database."""

        if (
            "restricted_worker_jobs" not in tables
            or not execution_ids
        ):
            return []
        placeholders = ",".join("?" for _ in execution_ids)
        rows = connection.execute(
            f"""
            SELECT job_id, execution_id, tool_name, adapter_name, state,
                   approval_actor, manifest_sha256, updated_at
            FROM restricted_worker_jobs
            WHERE execution_id IN ({placeholders})
            ORDER BY updated_at DESC
            LIMIT 25
            """,
            execution_ids,
        ).fetchall()
        return [
            {
                "job_id": safe_tui_plain_text(row["job_id"], max_length=80),
                "execution_id": safe_tui_plain_text(
                    row["execution_id"],
                    max_length=80,
                ),
                "tool_name": safe_tui_plain_text(
                    row["tool_name"],
                    max_length=40,
                ),
                "adapter_name": safe_tui_plain_text(
                    row["adapter_name"],
                    max_length=40,
                ),
                "state": safe_tui_plain_text(
                    row["state"],
                    max_length=40,
                ).upper(),
                "approval_actor": safe_tui_plain_text(
                    row["approval_actor"] or "—",
                    max_length=40,
                ),
                "manifest_sha256": safe_tui_plain_text(
                    row["manifest_sha256"],
                    max_length=64,
                ),
                "updated_at": compact_timestamp(str(row["updated_at"])),
            }
            for row in rows
        ]

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
                "execution_id": execution_id,
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
                "parameter_count": display(
                    metadata.get("parameter_count"),
                    "0",
                ),
                "duplicate_parameter_names": (
                    ", ".join(
                        item
                        for item in metadata.get(
                            "duplicate_parameter_names",
                            [],
                        )
                        if isinstance(item, str)
                    )
                    if isinstance(
                        metadata.get("duplicate_parameter_names"),
                        list,
                    )
                    else "—"
                ),
                "variant_parameter_groups": (
                    ", ".join(
                        item
                        for item in metadata.get(
                            "variant_parameter_groups",
                            [],
                        )
                        if isinstance(item, str)
                    )
                    if isinstance(
                        metadata.get("variant_parameter_groups"),
                        list,
                    )
                    else "—"
                ),
                "target_unchanged": display(
                    metadata.get("target_unchanged"),
                    "false",
                ),
                "parameters_mutated": display(
                    metadata.get("parameters_mutated"),
                    "false",
                ),
                "parser_attack_sent": display(
                    metadata.get("parser_attack_sent"),
                    "false",
                ),
                "cookie_count": display(
                    metadata.get("cookie_count"),
                    "0",
                ),
                "cookies_with_issues": display(
                    metadata.get("cookies_with_issues"),
                    "0",
                ),
                "issue_counts": (
                    ", ".join(
                        f"{key}={value}"
                        for key, value in sorted(
                            metadata.get("issue_counts", {}).items()
                        )
                        if isinstance(key, str)
                        and isinstance(value, int)
                        and not isinstance(value, bool)
                    )
                    if isinstance(
                        metadata.get("issue_counts"),
                        dict,
                    )
                    else "—"
                ),
                "cookie_values_discarded": display(
                    metadata.get("cookie_values_discarded"),
                    "false",
                ),
                "raw_set_cookie_stored": display(
                    metadata.get("raw_set_cookie_stored"),
                    "false",
                ),
                "cookie_replayed": display(
                    metadata.get("cookie_replayed"),
                    "false",
                ),
                "credential_header_sent": display(
                    metadata.get("credential_header_sent"),
                    "false",
                ),
                "post_form_count": display(
                    metadata.get("post_form_count"),
                    "0",
                ),
                "forms_with_token_signal": display(
                    metadata.get("forms_with_token_signal"),
                    "0",
                ),
                "forms_without_token_signal": display(
                    metadata.get("forms_without_token_signal"),
                    "0",
                ),
                "cross_origin_action_count": display(
                    metadata.get("cross_origin_action_count"),
                    "0",
                ),
                "token_values_discarded": display(
                    metadata.get("token_values_discarded"),
                    "false",
                ),
                "form_submitted": display(
                    metadata.get("form_submitted"),
                    "false",
                ),
                "request_body_sent": display(
                    metadata.get("request_body_sent"),
                    "false",
                ),
                "upload_form_count": display(
                    metadata.get("upload_form_count"),
                    "0",
                ),
                "file_input_count": display(
                    metadata.get("file_input_count"),
                    "0",
                ),
                "post_upload_form_count": display(
                    metadata.get("post_upload_form_count"),
                    "0",
                ),
                "multipart_upload_form_count": display(
                    metadata.get("multipart_upload_form_count"),
                    "0",
                ),
                "restricted_accept_input_count": display(
                    metadata.get("restricted_accept_input_count"),
                    "0",
                ),
                "unrestricted_accept_input_count": display(
                    metadata.get("unrestricted_accept_input_count"),
                    "0",
                ),
                "field_names_discarded": display(
                    metadata.get("field_names_discarded"),
                    "false",
                ),
                "field_values_discarded": display(
                    metadata.get("field_values_discarded"),
                    "false",
                ),
                "form_actions_discarded": display(
                    metadata.get("form_actions_discarded"),
                    "false",
                ),
                "file_uploaded": display(
                    metadata.get("file_uploaded"),
                    "false",
                ),
                "nodes_inspected": display(
                    metadata.get("nodes_inspected"),
                    "0",
                ),
                "sensitive_category_counts": (
                    ", ".join(
                        f"{key}={value}"
                        for key, value in sorted(
                            metadata.get(
                                "sensitive_category_counts",
                                {},
                            ).items()
                        )
                        if isinstance(key, str)
                        and isinstance(value, int)
                        and not isinstance(value, bool)
                    )
                    if isinstance(
                        metadata.get("sensitive_category_counts"),
                        dict,
                    )
                    else "—"
                ),
                "json_keys_discarded": display(
                    metadata.get("json_keys_discarded"),
                    "false",
                ),
                "json_values_discarded": display(
                    metadata.get("json_values_discarded"),
                    "false",
                ),
                "raw_json_stored": display(
                    metadata.get("raw_json_stored"),
                    "false",
                ),
                "authentication_used": display(
                    metadata.get("authentication_used"),
                    "false",
                ),
                "subprocess_started": display(
                    metadata.get("subprocess_started"),
                    "false",
                ),
            }

        return None

    def _load_controlled_validation_plan(
        self,
        connection: sqlite3.Connection,
        tables: set[str],
        execution_id: str,
    ) -> dict[str, str] | None:
        """Load a safe Phase 6B plan and hypothesis-link summary."""

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
        row = connection.execute(
            f"""
            SELECT *
            FROM "{table}"
            WHERE "{execution_column}" = ?
              AND LOWER("{type_column}") = ?
            {order_sql}
            LIMIT 1
            """,
            (execution_id, "controlled_validation_plan"),
        ).fetchone()
        if row is None:
            return None

        try:
            metadata = json.loads(str(row[metadata_column]))
        except (json.JSONDecodeError, TypeError, ValueError):
            return None
        if not isinstance(metadata, dict):
            return None

        def display(value: Any, default: str = "—") -> str:
            if isinstance(value, bool):
                return str(value).lower()
            if isinstance(value, int) and not isinstance(value, bool):
                return str(value)
            if isinstance(value, str):
                return value
            return default

        return {
            "execution_id": execution_id,
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
            "risk": display(metadata.get("risk")),
            "policy_decision": display(
                metadata.get("policy_decision")
            ),
            "requested_requests": display(
                metadata.get("requested_requests")
            ),
            "source_execution_id": display(
                metadata.get("source_execution_id")
            ),
            "source_hypothesis_evidence_id": display(
                metadata.get("source_hypothesis_evidence_id")
            ),
            "source_hypothesis_id": display(
                metadata.get("source_hypothesis_id")
            ),
            "executed": display(metadata.get("executed"), "false"),
            "network_activity": display(
                metadata.get("network_activity"),
                "false",
            ),
        }

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
                "execution_id": execution_id,
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
                "validator_id": display(
                    metadata.get("validator_id")
                ),
                "validator_classification": display(
                    metadata.get("validator_classification")
                ),
                "validator_reason": display(
                    metadata.get("validator_reason")
                ),
                "injection_types_covered": (
                    str(
                        len(metadata.get("injection_types_covered", []))
                    )
                    if isinstance(
                        metadata.get("injection_types_covered"),
                        list,
                    )
                    else "0"
                ),
                "observed_surfaces": (
                    ", ".join(
                        (
                            f"{item.get('injection_type')}="
                            f"{item.get('signal_count')}"
                        )
                        for item in metadata.get(
                            "observed_surfaces",
                            [],
                        )
                        if isinstance(item, dict)
                        and item.get("injection_type")
                    )
                    if isinstance(
                        metadata.get("observed_surfaces"),
                        list,
                    )
                    else "—"
                ),
                "query_parameter_count": display(
                    metadata.get("query_parameter_count"),
                    "0",
                ),
                "form_input_count": display(
                    metadata.get("form_input_count"),
                    "0",
                ),
                "parameter_names_discarded": display(
                    metadata.get("parameter_names_discarded"),
                    "false",
                ),
                "parameter_values_discarded": display(
                    metadata.get("parameter_values_discarded"),
                    "false",
                ),
                "response_body_discarded": display(
                    metadata.get("response_body_discarded"),
                    "false",
                ),
                "parameters_mutated": display(
                    metadata.get("parameters_mutated"),
                    "false",
                ),
                "exploit_executed": display(
                    metadata.get("exploit_executed"),
                    "false",
                ),
                "browser_attack_types_covered": (
                    str(
                        len(metadata.get("attack_types_covered", []))
                    )
                    if isinstance(
                        metadata.get("attack_types_covered"),
                        list,
                    )
                    else "0"
                ),
                "browser_observed_surfaces": (
                    ", ".join(
                        (
                            f"{item.get('attack_type')}="
                            f"{item.get('signal_count')}"
                        )
                        for item in metadata.get(
                            "browser_observed_surfaces",
                            [],
                        )
                        if isinstance(item, dict)
                        and item.get("attack_type")
                    )
                    if isinstance(
                        metadata.get("browser_observed_surfaces"),
                        list,
                    )
                    else "—"
                ),
                "browser_form_count": display(
                    metadata.get("browser_form_count"),
                    "0",
                ),
                "form_control_count": display(
                    metadata.get("form_control_count"),
                    "0",
                ),
                "script_block_count": display(
                    metadata.get("script_block_count"),
                    "0",
                ),
                "cors_wildcard_origin": display(
                    metadata.get("cors_wildcard_origin"),
                    "false",
                ),
                "cors_credentials_allowed": display(
                    metadata.get("cors_credentials_allowed"),
                    "false",
                ),
                "postmessage_handler_observed": display(
                    metadata.get("postmessage_handler_observed"),
                    "false",
                ),
                "postmessage_origin_check_observed": display(
                    metadata.get(
                        "postmessage_origin_check_observed"
                    ),
                    "false",
                ),
                "websocket_usage_observed": display(
                    metadata.get("websocket_usage_observed"),
                    "false",
                ),
                "websocket_auth_signal_observed": display(
                    metadata.get(
                        "websocket_auth_signal_observed"
                    ),
                    "false",
                ),
                "source_text_discarded": display(
                    metadata.get("source_text_discarded"),
                    "false",
                ),
                "attribute_values_discarded": display(
                    metadata.get("attribute_values_discarded"),
                    "false",
                ),
                "script_executed": display(
                    metadata.get("script_executed"),
                    "false",
                ),
                "server_parser_attack_types": (
                    str(
                        len(
                            metadata.get(
                                "server_parser_attack_types",
                                [],
                            )
                        )
                    )
                    if isinstance(
                        metadata.get("server_parser_attack_types"),
                        list,
                    )
                    else "0"
                ),
                "server_parser_observed_surfaces": (
                    ", ".join(
                        (
                            f"{item.get('attack_type')}="
                            f"{item.get('signal_count')}"
                        )
                        for item in metadata.get(
                            "server_parser_observed_surfaces",
                            [],
                        )
                        if isinstance(item, dict)
                        and item.get("attack_type")
                    )
                    if isinstance(
                        metadata.get("server_parser_observed_surfaces"),
                        list,
                    )
                    else "—"
                ),
                "server_query_parameter_count": display(
                    metadata.get("server_query_parameter_count"),
                    "0",
                ),
                "server_form_control_count": display(
                    metadata.get("server_form_control_count"),
                    "0",
                ),
                "absolute_url_value_count": display(
                    metadata.get("absolute_url_value_count"),
                    "0",
                ),
                "xml_content_type_observed": display(
                    metadata.get("xml_content_type_observed"),
                    "false",
                ),
                "serialized_content_type_observed": display(
                    metadata.get("serialized_content_type_observed"),
                    "false",
                ),
                "archive_content_type_observed": display(
                    metadata.get("archive_content_type_observed"),
                    "false",
                ),
                "parser_payload_sent": display(
                    metadata.get("parser_payload_sent"),
                    "false",
                ),
                "callback_generated": display(
                    metadata.get("callback_generated"),
                    "false",
                ),
                "subprocess_started": display(
                    metadata.get("subprocess_started"),
                    "false",
                ),
                "protection_sources": (
                    ", ".join(
                        item
                        for item in metadata.get(
                            "protection_sources",
                            [],
                        )
                        if isinstance(item, str)
                    )
                    if isinstance(
                        metadata.get("protection_sources"),
                        list,
                    )
                    else "—"
                ),
                "header_only": display(
                    metadata.get("header_only"),
                    "false",
                ),
                "exploit_page_generated": display(
                    metadata.get("exploit_page_generated"),
                    "false",
                ),
                "browser_launched": display(
                    metadata.get("browser_launched"),
                    "false",
                ),
                "payload_generated": display(
                    metadata.get("payload_generated"),
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
                "execution_id": execution_id,
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

    def _count_findings(
        self,
        connection: sqlite3.Connection,
        tables: set[str],
        execution_id: str,
    ) -> int:
        persisted = self._count_related(
            connection,
            tables,
            ("findings", "finding"),
            execution_id,
        )
        table = next(
            (
                name
                for name in ("audit_events", "audit_log", "events")
                if name in tables
            ),
            None,
        )
        if table is None:
            return persisted

        columns = self._columns(connection, table)
        execution_column = self._pick(
            columns,
            "execution_id",
            "execution",
        )
        event_type_column = self._pick(
            columns,
            "event_type",
            "type",
            "kind",
        )
        if execution_column is None or event_type_column is None:
            return persisted

        row = connection.execute(
            f"""
            SELECT COUNT(*) AS total
            FROM "{table}"
            WHERE "{execution_column}" = ?
              AND LOWER("{event_type_column}") = 'finding_created'
            """,
            (execution_id,),
        ).fetchone()
        audited = int(row["total"]) if row is not None else 0
        return max(persisted, audited)

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
            LIMIT {MAX_ACTIVITY_EVENTS}
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
            f'SELECT * FROM "{table}" {where_sql} {order_sql} '
            f"LIMIT {MAX_ACTIVITY_EVENTS}",
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

    return escape_markup(
        safe_tui_plain_text(
            value,
            max_length=max_length,
            default=default,
        )
    )


def safe_tui_plain_text(
    value: Any,
    *,
    max_length: int = 96,
    default: str = "—",
) -> str:
    """Return bounded, redacted plain text for Rich Text widgets."""

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

    return text


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


PHASE6_SAFE_ACTIONS = (
    "injection_surface_validation",
    "browser_attack_surface_validation",
    "server_parser_surface_validation",
    "http_parameter_surface_validation",
    "clickjacking_header_validation",
    "session_cookie_attribute_validation",
    "csrf_protection_surface_validation",
    "api_data_exposure_surface_validation",
    "file_upload_surface_validation",
)


def phase_execution_label(metadata: dict[str, Any]) -> str:
    """Return a compact, specific label for an orchestration child."""

    phase_code = str(metadata.get("phase_code") or "")
    phase_name = str(metadata.get("phase_name") or "")

    if phase_code in {"6C-nuclei", "6C-nuclei-preview"}:
        return "6C Nuclei"
    if phase_code == "6C-sqlmap-preview":
        return "6C SQLmap"
    if phase_code == "6C-safe-validator":
        action_labels = {
            "injection_surface_validation": "Injection",
            "browser_attack_surface_validation": "Browser",
            "server_parser_surface_validation": "Server",
            "http_parameter_surface_validation": "Parameters",
            "clickjacking_header_validation": "Clickjack",
            "session_cookie_attribute_validation": "Cookies",
            "csrf_protection_surface_validation": "CSRF",
            "api_data_exposure_surface_validation": "API",
            "file_upload_surface_validation": "Upload",
        }
        return f"6C {action_labels.get(phase_name, 'Validator')}"

    return phase_code


def build_phase6_chain_status(
    rows: Iterable[sqlite3.Row],
    metadata_column: str | None,
    state_column: str | None,
) -> dict[str, str]:
    """Summarize Phase 6C children for dynamic TUI labels."""

    child_states: dict[str, str] = {}
    completed_actions: set[str] = set()

    for row in rows:
        metadata = parse_execution_metadata(row, metadata_column)
        phase_code = str(metadata.get("phase_code") or "")
        phase_name = str(metadata.get("phase_name") or "")
        state = (
            str(row[state_column]).lower()
            if state_column and row[state_column] is not None
            else "unknown"
        )

        if phase_code == "6C-safe-validator" and phase_name:
            child_states[phase_name] = state
            if state == "completed":
                completed_actions.add(phase_name)
        elif phase_code in {"6C-nuclei", "6C-nuclei-preview"}:
            child_states["nuclei"] = state
        elif phase_code == "6C-sqlmap-preview":
            child_states["sqlmap"] = state

    def preview_status(tool: str) -> str:
        state = child_states.get(tool)
        if tool == "sqlmap":
            if state == "planned":
                return "AWAITING RESULT"
            if state == "completed":
                return "IMPORTED"
        if state in {"planned", "completed"}:
            return "PREVIEW READY"
        if state in {"created", "validated"}:
            return "PREPARING"
        if state == "running":
            return "RUNNING"
        if state == "analyzing":
            return "ANALYZING"
        if state == "failed":
            return "FAILED"
        return "APPROVAL REQUIRED"

    def validator_status(action: str) -> str:
        state = child_states.get(action)
        if state == "completed":
            return "DONE"
        if state == "failed":
            return "FAILED"
        if state in {"created", "validated", "planned", "running"}:
            return "IN PROGRESS"
        return "APPROVAL"

    status = {
        "validator_completed": str(len(completed_actions)),
        "validator_total": str(len(PHASE6_SAFE_ACTIONS)),
        "nuclei": preview_status("nuclei"),
        "sqlmap": preview_status("sqlmap"),
        "completed_actions": ",".join(sorted(completed_actions)),
    }
    status.update(
        {
            action: validator_status(action)
            for action in PHASE6_SAFE_ACTIONS
        }
    )
    return status


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

    completed_phase_codes = {
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
        and str(metadata["phase_code"]) != "6C-safe-validator"
    }
    completed_safe_actions = {
        str(metadata.get("phase_name"))
        for row in orchestration_rows
        if (
            (metadata := parse_execution_metadata(
                row,
                metadata_column,
            )).get("phase_code")
            == "6C-safe-validator"
            and str(row["state"]).lower() == "completed"
        )
    }
    foundation_codes = {
        "3A",
        "3B",
        "3C",
        "3D",
        "3E",
        "4A-security-headers",
        "4A-cors",
    }
    if (
        str(parent["state"]).lower() == "completed"
        and foundation_codes.issubset(completed_phase_codes)
    ):
        completed_phase_codes.update({"5A", "5B", "5C", "5D"})
    if set(PHASE6_SAFE_ACTIONS).issubset(completed_safe_actions):
        completed_phase_codes.add("6B")
        completed_phase_codes.add("6C-safe-validator")

    completed_phases = frozenset(completed_phase_codes)

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


def current_phase_for_dashboard(
    state: str,
    evidence_types: Iterable[str],
    completed_phases: Iterable[str],
    phase6_chain_status: dict[str, str],
) -> str:
    """Prefer explicit orchestration progress over parent evidence fallback."""

    if (
        int(phase6_chain_status.get("validator_completed", "0")) > 0
        or phase6_chain_status.get("nuclei")
        in {
            "PREPARING",
            "RUNNING",
            "ANALYZING",
            "PREVIEW READY",
            "EXECUTED",
            "FAILED",
            "TIMED OUT",
        }
        or phase6_chain_status.get("sqlmap")
        in {
            "PREPARING",
            "RUNNING",
            "ANALYZING",
            "PREVIEW READY",
            "AWAITING RESULT",
            "IMPORTED",
        }
    ):
        return "6C — LOW-RISK ATTACK VALIDATORS"

    normalized_completed = {
        normalize_phase_code(code)
        for code in completed_phases
    }
    for code, name in reversed(BASE_PHASES):
        if code in normalized_completed:
            return f"{code} — {name.upper()}"

    return infer_phase(state, evidence_types)


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
    ("5A", "Assessment Planner"),
    ("5B", "Dependency Outcomes"),
    ("5C", "Parent Outcome Handling"),
    ("5D", "Optional Phase Handling"),
    ("6A", "Attack Hypothesis Engine"),
    ("6B", "Policy & Approval Gate"),
    ("6C", "Low-Risk Attack Validators"),
    ("6D", "Authenticated Workflows"),
    ("6E", "Exploit Confirmation"),
    ("6F", "Post-Exploitation Simulation"),
    ("6G", "Cleanup & Rollback"),
    ("6H", "Evidence & Findings"),
    ("7A", "Post-Exploitation & Chaining"),
    ("8A", "Reporting & Remediation"),
]


def normalize_phase_code(phase_code: str) -> str:
    """Normalize orchestration child phase identifiers for the TUI."""

    normalized = phase_code.strip()

    if normalized.startswith("4A-"):
        return "4A"
    if normalized.startswith("6C-"):
        return "6C"

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
        current_code = current_phase.split(" ", 1)[0]
        current_index = (
            phase_codes.index(current_code)
            if current_code in phase_codes
            else -1
        )

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
            elif code == current_code:
                marker = "→"
                status = "IN PROGRESS"
            elif index < latest_completed_index:
                marker = "!"
                status = (
                    "NO CAND."
                    if code in {"4B", "4C", "4D"}
                    else "NOT RUN"
                )
            elif 0 <= current_index and index < current_index:
                marker = "!"
                status = (
                    "NO CAND."
                    if code in {"4B", "4C", "4D"}
                    else "NOT RUN"
                )
            elif index == latest_completed_index + 1:
                marker = "→"
                status = "NEXT"
            else:
                marker = "·"
                status = "PLANNED"

            rows.append(
                (
                    marker,
                    code,
                    name,
                    status,
                    "✓" if status == "DONE" else "—",
                )
            )

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

        rows.append(
            (
                marker,
                code,
                name,
                status,
                "✓" if status == "DONE" else "—",
            )
        )

    return rows


TOOLS = [
    ("subfinder", "Subdomain Discovery", "ENABLED"),
    ("amass", "Passive Asset Discovery", "ENABLED"),
    ("assetfinder", "Passive Asset Discovery", "ENABLED"),
    ("crt.sh", "Certificate Transparency", "ENABLED"),
    ("httpx", "Live Host & Service Probe", "ENABLED"),
    ("katana", "Web Crawler", "ENABLED"),
    ("wayback-cdx", "Historical URL Intelligence (3D)", "ENABLED"),
    ("Saarthi JS", "JavaScript Intelligence", "ENABLED"),
    ("wayback", "Web Archiving (opt-in · publishes ext.)", "APPROVAL"),
    ("nuclei", "Controlled Preview / Execution", "APPROVAL"),
    ("sqlmap", "External Result Handoff / Import", "6C.1 HANDOFF"),
    ("ghauri", "Blind SQLi Cross-check (auto 6C)", "ENABLED"),
    ("OAST Manager", "Out-of-band Correlation", "PHASE 6"),
    ("Saarthi 6A", "Attack Hypothesis Engine", "ENABLED"),
    ("Saarthi 6B", "Policy & Approval Gate", "APPROVAL"),
    ("Saarthi 6C.1", "Injection Surface Validator", "APPROVAL"),
    ("Saarthi 6C.2", "Browser Attack Surface Validator", "APPROVAL"),
    ("Saarthi 6C.3", "Server/Parser Surface Validator", "APPROVAL"),
    ("Saarthi 6C.2", "Clickjacking Header Validator", "APPROVAL"),
    ("Saarthi 6C.2", "CSRF Protection Surface Validator", "APPROVAL"),
    ("Saarthi 6C.3", "HTTP Parameter Surface Validator", "APPROVAL"),
    ("Saarthi 6C.4", "Session Cookie Attribute Validator", "APPROVAL"),
    ("Saarthi 6C.6", "File Upload Surface Validator", "APPROVAL"),
    ("Saarthi 6C.7", "API Data-Exposure Surface Validator", "APPROVAL"),
    *validator_module_tool_rows(),
]

WORKER_DEFINITIONS = (
    (
        "nuclei",
        "Controlled local adapter",
        "TUI approval",
        "Configured",
    ),
    (
        "sqlmap",
        "External handoff + import",
        "TUI approval",
        "No launcher",
    ),
    (
        "ffuf",
        "Restricted execution worker",
        "TUI approval",
        "Not configured",
    ),
    (
        "callback",
        "OAST/callback validator",
        "TUI approval",
        "Not configured",
    ),
)


def worker_rows(
    snapshot: DashboardSnapshot,
) -> list[tuple[str, str, str, str]]:
    """Build truthful execution-worker rows from persisted workflow state."""

    phase6 = snapshot.phase6_chain_status
    nuclei_status = phase6.get("nuclei", "APPROVAL REQUIRED")
    sqlmap_status = phase6.get("sqlmap", "APPROVAL REQUIRED")
    latest_jobs: dict[str, dict[str, str]] = {}
    for job in snapshot.recent_worker_jobs:
        latest_jobs.setdefault(job.get("tool_name", ""), job)
    rows: list[tuple[str, str, str, str]] = []

    for tool, mode, gate, default_state in WORKER_DEFINITIONS:
        job = latest_jobs.get(tool)
        if job is not None:
            actor = job.get("approval_actor", "—")
            job_gate = "Approved" if actor != "—" else "Awaiting approval"
            rows.append(
                (
                    tool,
                    f"{job.get('adapter_name', 'unbound')} adapter",
                    job_gate,
                    job.get("state", "UNKNOWN"),
                )
            )
            continue
        state = default_state
        if tool == "nuclei":
            state = nuclei_status
        elif tool == "sqlmap":
            if sqlmap_status in {"AWAITING RESULT", "IMPORTED"}:
                gate = "Approved"
            state = (
                f"{sqlmap_status} · EXTERNAL"
                if sqlmap_status != "APPROVAL REQUIRED"
                else "NO LAUNCHER"
            )
        rows.append((tool, mode, gate, state))

    return rows


def tool_rows(
    snapshot: DashboardSnapshot,
) -> list[tuple[str, str, str]]:
    """Apply live Phase 6C permission and completion labels."""

    status = snapshot.phase6_chain_status
    if not status:
        return TOOLS

    rows: list[tuple[str, str, str]] = []
    purpose_actions = {
        "Injection Surface Validator": (
            "injection_surface_validation"
        ),
        "Browser Attack Surface Validator": (
            "browser_attack_surface_validation"
        ),
        "Server/Parser Surface Validator": (
            "server_parser_surface_validation"
        ),
        "Clickjacking Header Validator": (
            "clickjacking_header_validation"
        ),
        "CSRF Protection Surface Validator": (
            "csrf_protection_surface_validation"
        ),
        "HTTP Parameter Surface Validator": (
            "http_parameter_surface_validation"
        ),
        "Session Cookie Attribute Validator": (
            "session_cookie_attribute_validation"
        ),
        "File Upload Surface Validator": (
            "file_upload_surface_validation"
        ),
        "API Data-Exposure Surface Validator": (
            "api_data_exposure_surface_validation"
        ),
    }

    for tool, purpose, default_status in TOOLS:
        dynamic_status = default_status
        if tool == "nuclei":
            dynamic_status = status.get("nuclei", default_status)
        elif tool == "sqlmap":
            dynamic_status = status.get("sqlmap", default_status)
        elif (
            tool == "Saarthi 6B"
            and status.get("validator_completed")
            == status.get("validator_total")
        ):
            dynamic_status = "DONE"
        elif purpose in purpose_actions:
            dynamic_status = status.get(
                purpose_actions[purpose],
                default_status,
            )
        rows.append((tool, purpose, dynamic_status))

    return rows


def build_orchestration_summary_lines(
    snapshot: DashboardSnapshot,
) -> list[str]:
    """Build compact project-level status lines for the scope panel."""

    summaries = summarize_phase6_validator_modules()
    implemented = sum(item.implemented for item in summaries)
    partial = sum(item.partial for item in summaries)
    total = sum(item.total for item in summaries)
    completed = max(
        snapshot.outcome_counts.get("completed", 0),
        len(
            {
                normalize_phase_code(code)
                for code in snapshot.completed_phases
            }
        ),
    )
    optional_failures = snapshot.outcome_counts.get("failed", 0)
    overall = (
        snapshot.orchestration_status.upper()
        if snapshot.orchestration_status != "unknown"
        else snapshot.execution_state.upper()
    )
    phase6 = snapshot.phase6_chain_status
    validator_completed = phase6.get("validator_completed", "0")
    validator_total = phase6.get(
        "validator_total",
        str(len(PHASE6_SAFE_ACTIONS)),
    )
    nuclei_status = phase6.get("nuclei", "APPROVAL REQUIRED")
    sqlmap_status = phase6.get("sqlmap", "APPROVAL REQUIRED")

    return [
        "[bold cyan]ORCHESTRATION SUMMARY[/bold cyan]",
        f"Overall Status       : {safe_tui_display(overall, max_length=24)}",
        f"Optional Failures    : {optional_failures}",
        f"Completed Phases     : {completed}",
        (
            "Validator Coverage   : "
            f"{implemented} ready · {partial} partial · {total} total"
        ),
        (
            "Phase 6C Safe Chain  : "
            f"{validator_completed}/{validator_total} complete"
        ),
        (
            "Nuclei / SQLmap      : "
            f"{nuclei_status} / {sqlmap_status}"
        ),
    ]


def build_activity_text(line: str) -> Text:
    """Color one sanitized audit line without interpreting Rich markup."""

    value = safe_tui_plain_text(line, max_length=1_000)
    rendered = Text(value)
    if len(value) >= 19 and value[:4].isdigit():
        rendered.stylize("bright_cyan", 0, 19)

    styles = {
        "ERROR": "bold red",
        "FAILED": "bold red",
        "WARNING": "yellow",
        "WRN": "yellow",
        "APPROVAL": "green",
        "COMPLETED": "green",
        "EVIDENCE": "magenta",
        "FINDING": "bold yellow",
        "SQLMAP": "bright_magenta",
        "NUCLEI": "bright_magenta",
        "INFO": "cyan",
        "INF": "cyan",
    }
    upper = value.upper()
    for token, style in styles.items():
        start = 0
        while (index := upper.find(token, start)) >= 0:
            rendered.stylize(style, index, index + len(token))
            start = index + len(token)
    return rendered


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

    elif snapshot.controlled_validation_plan:
        plan = snapshot.controlled_validation_plan

        def plan_value(
            key: str,
            *,
            max_length: int = 96,
        ) -> str:
            return safe_tui_display(
                plan.get(key),
                max_length=max_length,
            )

        scope_lines.extend(
            [
                "",
                "[bold cyan]PHASE 6B — POLICY & APPROVAL GATE[/bold cyan]",
                (
                    "Validation Execution: "
                    f"{plan_value('execution_id', max_length=72)}"
                ),
                (
                    "Plan Evidence       : "
                    f"{plan_value('evidence_id', max_length=72)}"
                ),
                (
                    "Source Execution    : "
                    f"{plan_value('source_execution_id', max_length=72)}"
                ),
                (
                    "Source Hypothesis   : "
                    f"{plan_value('source_hypothesis_id', max_length=72)}"
                ),
                (
                    "Source Evidence     : "
                    f"{plan_value('source_hypothesis_evidence_id', max_length=72)}"
                ),
                (
                    "Target              : "
                    f"{plan_value('target_url', max_length=88)}"
                ),
                (
                    "Action / Risk       : "
                    f"{plan_value('action', max_length=48)} / "
                    f"{plan_value('risk', max_length=16)}"
                ),
                (
                    "Policy Decision     : "
                    f"{plan_value('policy_decision', max_length=20)}"
                ),
                (
                    "Request Bound       : "
                    f"{plan_value('requested_requests', max_length=8)}"
                ),
                (
                    "Executed            : "
                    f"{plan_value('executed', max_length=12)}"
                ),
                (
                    "Network Activity    : "
                    f"{plan_value('network_activity', max_length=12)}"
                ),
                (
                    "[dim]Integrity-checked 6A hypothesis routed into a "
                    "separate approval-gated plan. No validation request "
                    "was sent.[/dim]"
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

        if (
            observation.get("validator_id")
            == "6C.2-clickjacking-header-validation"
        ):
            scope_lines.extend(
                [
                    "",
                    (
                        "[bold cyan]6C.2 — CLICKJACKING HEADER "
                        "VALIDATION[/bold cyan]"
                    ),
                    (
                        "Classification     : "
                        f"{observation_value('validator_classification', max_length=32)}"
                    ),
                    (
                        "Reason             : "
                        f"{observation_value('validator_reason', max_length=120)}"
                    ),
                    (
                        "Protection Sources : "
                        f"{observation_value('protection_sources', max_length=72)}"
                    ),
                    (
                        "Header Only        : "
                        f"{observation_value('header_only', max_length=12)}"
                    ),
                    (
                        "Exploit Page       : "
                        f"{observation_value('exploit_page_generated', max_length=12)}"
                    ),
                    (
                        "Browser Launched   : "
                        f"{observation_value('browser_launched', max_length=12)}"
                    ),
                    (
                        "Payload Generated  : "
                        f"{observation_value('payload_generated', max_length=12)}"
                    ),
                ]
            )
        elif (
            observation.get("validator_id")
            == "6C.1-injection-surface-analysis"
        ):
            scope_lines.extend(
                [
                    "",
                    (
                        "[bold cyan]6C.1 — INJECTION SURFACE "
                        "VALIDATION[/bold cyan]"
                    ),
                    (
                        "Classification     : "
                        f"{observation_value('validator_classification', max_length=40)}"
                    ),
                    (
                        "Reason             : "
                        f"{observation_value('validator_reason', max_length=120)}"
                    ),
                    (
                        "Injection Coverage : "
                        f"{observation_value('injection_types_covered', max_length=12)} types"
                    ),
                    (
                        "Observed Surfaces  : "
                        f"{observation_value('observed_surfaces', max_length=120)}"
                    ),
                    (
                        "Query / Form Inputs: "
                        f"{observation_value('query_parameter_count', max_length=12)} / "
                        f"{observation_value('form_input_count', max_length=12)}"
                    ),
                    (
                        "Names / Values Gone: "
                        f"{observation_value('parameter_names_discarded', max_length=12)} / "
                        f"{observation_value('parameter_values_discarded', max_length=12)}"
                    ),
                    (
                        "Body Discarded     : "
                        f"{observation_value('response_body_discarded', max_length=12)}"
                    ),
                    (
                        "Parameters Mutated : "
                        f"{observation_value('parameters_mutated', max_length=12)}"
                    ),
                    (
                        "Payload / Exploit  : "
                        f"{observation_value('payload_generated', max_length=12)} / "
                        f"{observation_value('exploit_executed', max_length=12)}"
                    ),
                ]
            )
        elif (
            observation.get("validator_id")
            == "6C.2-browser-attack-surface-analysis"
        ):
            scope_lines.extend(
                [
                    "",
                    (
                        "[bold cyan]6C.2 — BROWSER ATTACK SURFACE "
                        "VALIDATION[/bold cyan]"
                    ),
                    (
                        "Classification     : "
                        f"{observation_value('validator_classification', max_length=40)}"
                    ),
                    (
                        "Reason             : "
                        f"{observation_value('validator_reason', max_length=120)}"
                    ),
                    (
                        "Browser Coverage   : "
                        f"{observation_value('browser_attack_types_covered', max_length=12)} types"
                    ),
                    (
                        "Observed Surfaces  : "
                        f"{observation_value('browser_observed_surfaces', max_length=120)}"
                    ),
                    (
                        "Forms / Inputs / JS: "
                        f"{observation_value('browser_form_count', max_length=10)} / "
                        f"{observation_value('form_control_count', max_length=10)} / "
                        f"{observation_value('script_block_count', max_length=10)}"
                    ),
                    (
                        "postMessage / Origin: "
                        f"{observation_value('postmessage_handler_observed', max_length=10)} / "
                        f"{observation_value('postmessage_origin_check_observed', max_length=10)}"
                    ),
                    (
                        "WebSocket / Auth   : "
                        f"{observation_value('websocket_usage_observed', max_length=10)} / "
                        f"{observation_value('websocket_auth_signal_observed', max_length=10)}"
                    ),
                    (
                        "CORS Wildcard / Cred: "
                        f"{observation_value('cors_wildcard_origin', max_length=10)} / "
                        f"{observation_value('cors_credentials_allowed', max_length=10)}"
                    ),
                    (
                        "Source / Attr Gone : "
                        f"{observation_value('source_text_discarded', max_length=10)} / "
                        f"{observation_value('attribute_values_discarded', max_length=10)}"
                    ),
                    (
                        "Browser / Script   : "
                        f"{observation_value('browser_launched', max_length=10)} / "
                        f"{observation_value('script_executed', max_length=10)}"
                    ),
                    (
                        "Payload / Exploit  : "
                        f"{observation_value('payload_generated', max_length=10)} / "
                        f"{observation_value('exploit_executed', max_length=10)}"
                    ),
                ]
            )
        elif (
            observation.get("validator_id")
            == "6C.3-server-parser-surface-analysis"
        ):
            scope_lines.extend(
                [
                    "",
                    (
                        "[bold cyan]6C.3 — SERVER/PARSER SURFACE "
                        "VALIDATION[/bold cyan]"
                    ),
                    (
                        "Classification     : "
                        f"{observation_value('validator_classification', max_length=40)}"
                    ),
                    (
                        "Reason             : "
                        f"{observation_value('validator_reason', max_length=120)}"
                    ),
                    (
                        "Attack Coverage    : "
                        f"{observation_value('server_parser_attack_types', max_length=12)} types"
                    ),
                    (
                        "Observed Surfaces  : "
                        f"{observation_value('server_parser_observed_surfaces', max_length=120)}"
                    ),
                    (
                        "Query / Form / URLs: "
                        f"{observation_value('server_query_parameter_count', max_length=10)} / "
                        f"{observation_value('server_form_control_count', max_length=10)} / "
                        f"{observation_value('absolute_url_value_count', max_length=10)}"
                    ),
                    (
                        "XML / Serial / Arch: "
                        f"{observation_value('xml_content_type_observed', max_length=10)} / "
                        f"{observation_value('serialized_content_type_observed', max_length=10)} / "
                        f"{observation_value('archive_content_type_observed', max_length=10)}"
                    ),
                    (
                        "Parser / Callback  : "
                        f"{observation_value('parser_payload_sent', max_length=10)} / "
                        f"{observation_value('callback_generated', max_length=10)}"
                    ),
                    (
                        "Mutation / Process : "
                        f"{observation_value('parameters_mutated', max_length=10)} / "
                        f"{observation_value('subprocess_started', max_length=10)}"
                    ),
                    (
                        "Payload / Exploit  : "
                        f"{observation_value('payload_generated', max_length=10)} / "
                        f"{observation_value('exploit_executed', max_length=10)}"
                    ),
                ]
            )
        elif (
            observation.get("validator_id")
            == "6C.3-http-parameter-surface-validation"
        ):
            scope_lines.extend(
                [
                    "",
                    (
                        "[bold cyan]6C.3 — HTTP PARAMETER SURFACE "
                        "VALIDATION[/bold cyan]"
                    ),
                    (
                        "Classification     : "
                        f"{observation_value('validator_classification', max_length=40)}"
                    ),
                    (
                        "Reason             : "
                        f"{observation_value('validator_reason', max_length=120)}"
                    ),
                    (
                        "Parameter Count    : "
                        f"{observation_value('parameter_count', max_length=12)}"
                    ),
                    (
                        "Duplicate Names    : "
                        f"{observation_value('duplicate_parameter_names', max_length=72)}"
                    ),
                    (
                        "Variant Groups     : "
                        f"{observation_value('variant_parameter_groups', max_length=72)}"
                    ),
                    (
                        "Target Unchanged   : "
                        f"{observation_value('target_unchanged', max_length=12)}"
                    ),
                    (
                        "Parameters Mutated : "
                        f"{observation_value('parameters_mutated', max_length=12)}"
                    ),
                    (
                        "Parser Attack Sent : "
                        f"{observation_value('parser_attack_sent', max_length=12)}"
                    ),
                    (
                        "Payload Generated  : "
                        f"{observation_value('payload_generated', max_length=12)}"
                    ),
                ]
            )
        elif (
            observation.get("validator_id")
            == "6C.4-session-cookie-attribute-validation"
        ):
            scope_lines.extend(
                [
                    "",
                    (
                        "[bold cyan]6C.4 — SESSION COOKIE ATTRIBUTE "
                        "VALIDATION[/bold cyan]"
                    ),
                    (
                        "Classification     : "
                        f"{observation_value('validator_classification', max_length=40)}"
                    ),
                    (
                        "Reason             : "
                        f"{observation_value('validator_reason', max_length=120)}"
                    ),
                    (
                        "Cookies / Issues   : "
                        f"{observation_value('cookie_count', max_length=12)} / "
                        f"{observation_value('cookies_with_issues', max_length=12)}"
                    ),
                    (
                        "Issue Counts       : "
                        f"{observation_value('issue_counts', max_length=120)}"
                    ),
                    (
                        "Values Discarded   : "
                        f"{observation_value('cookie_values_discarded', max_length=12)}"
                    ),
                    (
                        "Raw Header Stored  : "
                        f"{observation_value('raw_set_cookie_stored', max_length=12)}"
                    ),
                    (
                        "Cookie Replayed    : "
                        f"{observation_value('cookie_replayed', max_length=12)}"
                    ),
                    (
                        "Credential Sent    : "
                        f"{observation_value('credential_header_sent', max_length=12)}"
                    ),
                    (
                        "Payload Generated  : "
                        f"{observation_value('payload_generated', max_length=12)}"
                    ),
                ]
            )
        elif (
            observation.get("validator_id")
            == "6C.2-csrf-protection-surface-validation"
        ):
            scope_lines.extend(
                [
                    "",
                    (
                        "[bold cyan]6C.2 — CSRF PROTECTION SURFACE "
                        "VALIDATION[/bold cyan]"
                    ),
                    (
                        "Classification     : "
                        f"{observation_value('validator_classification', max_length=40)}"
                    ),
                    (
                        "Reason             : "
                        f"{observation_value('validator_reason', max_length=120)}"
                    ),
                    (
                        "POST Forms         : "
                        f"{observation_value('post_form_count', max_length=12)}"
                    ),
                    (
                        "With / Without Token: "
                        f"{observation_value('forms_with_token_signal', max_length=12)} / "
                        f"{observation_value('forms_without_token_signal', max_length=12)}"
                    ),
                    (
                        "Cross-Origin Action: "
                        f"{observation_value('cross_origin_action_count', max_length=12)}"
                    ),
                    (
                        "Protection Sources : "
                        f"{observation_value('protection_sources', max_length=72)}"
                    ),
                    (
                        "Tokens Discarded   : "
                        f"{observation_value('token_values_discarded', max_length=12)}"
                    ),
                    (
                        "Form Submitted     : "
                        f"{observation_value('form_submitted', max_length=12)}"
                    ),
                    (
                        "Browser Launched   : "
                        f"{observation_value('browser_launched', max_length=12)}"
                    ),
                    (
                        "Request Body Sent  : "
                        f"{observation_value('request_body_sent', max_length=12)}"
                    ),
                    (
                        "Payload Generated  : "
                        f"{observation_value('payload_generated', max_length=12)}"
                    ),
                ]
            )
        elif (
            observation.get("validator_id")
            in {
                "6C.5-file-upload-surface-validation",
                "6C.6-file-upload-surface-validation",
            }
        ):
            scope_lines.extend(
                [
                    "",
                    (
                        "[bold cyan]6C.6 — FILE UPLOAD SURFACE "
                        "VALIDATION[/bold cyan]"
                    ),
                    (
                        "Classification     : "
                        f"{observation_value('validator_classification', max_length=40)}"
                    ),
                    (
                        "Reason             : "
                        f"{observation_value('validator_reason', max_length=120)}"
                    ),
                    (
                        "Upload Forms       : "
                        f"{observation_value('upload_form_count', max_length=12)}"
                    ),
                    (
                        "File Inputs        : "
                        f"{observation_value('file_input_count', max_length=12)}"
                    ),
                    (
                        "POST / Multipart   : "
                        f"{observation_value('post_upload_form_count', max_length=12)} / "
                        f"{observation_value('multipart_upload_form_count', max_length=12)}"
                    ),
                    (
                        "Accept Restricted  : "
                        f"{observation_value('restricted_accept_input_count', max_length=12)}"
                    ),
                    (
                        "Accept Unrestricted: "
                        f"{observation_value('unrestricted_accept_input_count', max_length=12)}"
                    ),
                    (
                        "Names / Values Gone: "
                        f"{observation_value('field_names_discarded', max_length=12)} / "
                        f"{observation_value('field_values_discarded', max_length=12)}"
                    ),
                    (
                        "Actions Discarded  : "
                        f"{observation_value('form_actions_discarded', max_length=12)}"
                    ),
                    (
                        "File Uploaded      : "
                        f"{observation_value('file_uploaded', max_length=12)}"
                    ),
                    (
                        "Form Submitted     : "
                        f"{observation_value('form_submitted', max_length=12)}"
                    ),
                    (
                        "Request Body Sent  : "
                        f"{observation_value('request_body_sent', max_length=12)}"
                    ),
                    (
                        "Payload Generated  : "
                        f"{observation_value('payload_generated', max_length=12)}"
                    ),
                ]
            )
        elif (
            observation.get("validator_id")
            == "6C.7-api-data-exposure-surface-validation"
        ):
            scope_lines.extend(
                [
                    "",
                    (
                        "[bold cyan]6C.7 — API DATA-EXPOSURE SURFACE "
                        "VALIDATION[/bold cyan]"
                    ),
                    (
                        "Classification     : "
                        f"{observation_value('validator_classification', max_length=40)}"
                    ),
                    (
                        "Reason             : "
                        f"{observation_value('validator_reason', max_length=120)}"
                    ),
                    (
                        "JSON Nodes         : "
                        f"{observation_value('nodes_inspected', max_length=16)}"
                    ),
                    (
                        "Sensitive Categories: "
                        f"{observation_value('sensitive_category_counts', max_length=120)}"
                    ),
                    (
                        "Keys Discarded     : "
                        f"{observation_value('json_keys_discarded', max_length=12)}"
                    ),
                    (
                        "Values Discarded   : "
                        f"{observation_value('json_values_discarded', max_length=12)}"
                    ),
                    (
                        "Raw JSON Stored    : "
                        f"{observation_value('raw_json_stored', max_length=12)}"
                    ),
                    (
                        "Request Body Sent  : "
                        f"{observation_value('request_body_sent', max_length=12)}"
                    ),
                    (
                        "Authentication Used: "
                        f"{observation_value('authentication_used', max_length=12)}"
                    ),
                    (
                        "Payload Generated  : "
                        f"{observation_value('payload_generated', max_length=12)}"
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


class ConfirmScanScreen(ModalScreen[bool]):
    """Confirm before launching any real active/intrusive scan."""

    DEFAULT_CSS = """
    ConfirmScanScreen {
        align: center middle;
    }
    #confirm-dialog {
        width: 74;
        height: auto;
        border: thick $warning;
        background: $surface;
        padding: 1 2;
    }
    #confirm-title {
        text-style: bold;
        color: $warning;
    }
    #confirm-body {
        margin: 1 0;
    }
    #confirm-buttons {
        align-horizontal: center;
        height: auto;
        margin-top: 1;
    }
    #confirm-buttons Button {
        margin: 0 1;
    }
    """

    AUTO_FOCUS = "#confirm-cancel"

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
        ("n", "cancel", "Cancel"),
        ("y", "confirm", "Launch"),
    ]

    def __init__(self, title: str, body: str) -> None:
        super().__init__()
        self._title = title
        self._body = body

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-dialog"):
            yield Label(self._title, id="confirm-title")
            yield Static(self._body, id="confirm-body")
            with Horizontal(id="confirm-buttons"):
                yield Button(
                    "Launch",
                    variant="error",
                    id="confirm-launch",
                )
                yield Button(
                    "Cancel",
                    variant="primary",
                    id="confirm-cancel",
                )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm-launch")

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class SaarthiDashboard(App[None]):
    CSS_PATH = "styles.tcss"
    TITLE = "Saarthi OPS"
    # Do not auto-focus the URL field on start, so single-key bindings
    # (v, V, r, q, u, ...) work immediately. Press 'u' to type a URL.
    AUTO_FOCUS = None

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("p", "focus_phases", "Phases"),
        ("t", "focus_tools", "Tools"),
        ("e", "focus_executions", "Evidence"),
        ("u", "focus_url", "URL"),
        ("h", "help", "Help"),
    ]

    snapshot: reactive[DashboardSnapshot] = reactive(demo_snapshot)

    def __init__(self, database_path: Path = DEFAULT_DB_PATH) -> None:
        super().__init__()
        self.repository = ReadOnlySaarthiRepository(database_path)
        self._validation_running = False
        # Label of the current operator-launched stage (recon / Phase 6 /
        # nuclei+sqlmap). None when idle. Drives the live-run overlay so the
        # header never shows "COMPLETED / 100%" while nuclei/sqlmap (an
        # untracked post-assessment step) is still executing.
        self._run_stage: str | None = None
        # Target URL of the current operator-launched run, shown in the
        # TARGET & AUTHORIZE bar while the run is active.
        self._run_target: str | None = None
        self._analysis_running = False
        # Live AI co-pilot: comments on each phase as the assessment runs.
        self._ai_live_enabled = True
        self._ai_observer_running = False
        # AI action queue: propose -> operator approve -> execute. Actions are
        # drawn from a fixed non-destructive menu, so nothing here can ever be
        # a data dump, shell, evasion, or out-of-scope host.
        self._ai_action_queue: list = []
        self._propose_running = False
        self._live_validation_lines: list[str] = []
        # Snapshot of every line currently in the activity log (DB audit
        # events + live tool lines), used to append only new lines instead
        # of clearing and redrawing the whole log on each refresh.
        self._rendered_lines: list[str] = []

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

        with Vertical(classes="panel", id="authorize-panel"):
            yield Label("[ TARGET & AUTHORIZE ]", classes="panel-title")
            with Horizontal(id="authorize-row"):
                yield Input(
                    placeholder=(
                        "Authorized target URL, e.g. "
                        "https://target/path?id=1"
                    ),
                    id="target-url-input",
                )
                yield Button(
                    AUTHORIZE_BUTTON_LABEL,
                    variant="success",
                    id="authorize-button",
                )
            yield Static(
                AUTHORIZE_NOTE_IDLE,
                id="authorize-note",
            )

        with Grid(id="top-grid"):
            with Vertical(classes="panel", id="scope-panel"):
                yield Label("[ 1. PROJECT & SCOPE ]", classes="panel-title")
                yield Static(id="scope-content")
                yield Label("PHASE PROGRESS", classes="section-label")
                yield ProgressBar(total=100, show_eta=False, id="phase-progress")
                yield Static(id="orchestration-summary")

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
                yield Label(
                    "LIVE · ALL PHASES + TOOLS",
                    id="activity-caption",
                )
            yield RichLog(
                id="activity-log",
                highlight=False,
                markup=False,
                max_lines=MAX_ACTIVITY_LOG_LINES,
                auto_scroll=True,
                wrap=False,
            )

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
            DASHBOARD_REFRESH_SECONDS,
            self._refresh_snapshot_silently,
        )
        self.action_refresh()

    def _configure_tables(self) -> None:
        phase_table = self.query_one("#phase-table", DataTable)
        phase_table.add_column("", width=1)
        phase_table.add_column("Phase", width=5)
        phase_table.add_column("Name", width=27)
        phase_table.add_column("Status", width=10)
        phase_table.add_column("Completed", width=10)
        phase_table.cursor_type = "row"
        phase_table.zebra_stripes = True

        tools_table = self.query_one("#tools-table", DataTable)
        tools_table.add_column("Tool", width=14)
        tools_table.add_column("Purpose", width=31)
        tools_table.add_column("Status", width=18)
        tools_table.cursor_type = "row"
        tools_table.zebra_stripes = True

        executions = self.query_one("#executions-table", DataTable)
        executions.add_column("Execution ID", width=36)
        executions.add_column("Phase", width=18)
        executions.add_column("Started", width=20)
        executions.add_column("Duration", width=10)
        executions.add_column("Target", width=34)
        executions.add_column("Evidence", width=9)
        executions.add_column("Findings", width=9)
        executions.add_column("Status", width=12)
        executions.cursor_type = "row"
        executions.zebra_stripes = True

    def _update_runtime(self) -> None:
        now = datetime.now()
        if self._validation_running:
            status_line = (
                "[bold yellow]● RUN : "
                f"{self._run_stage or 'running'}[/bold yellow]"
            )
        else:
            status_line = "[dim]○ IDLE[/dim]"
        runtime = (
            "[cyan]HOST[/cyan] : saarthi-ops.local\n"
            "[cyan]USER[/cyan] : operator\n"
            "[cyan]MODE[/cyan] : LOCAL\n"
            "[cyan]DATA[/cyan] : Local Only\n"
            "────────────────────────\n"
            f"[bold cyan]{now:%H:%M:%S}[/bold cyan]  "
            f"{now:%Y-%m-%d}\n"
            f"{status_line}"
        )
        self.query_one("#runtime-panel", Static).update(runtime)
        # Keep the live-run overlay applied even when the DB (and thus the
        # snapshot) is static, e.g. while nuclei/sqlmap runs after the parent
        # execution has already been marked completed.
        self._apply_run_overlay()

    def watch_snapshot(self, snapshot: DashboardSnapshot) -> None:
        if self.is_mounted:
            self._render_snapshot(snapshot)

    def _render_snapshot(self, snapshot: DashboardSnapshot) -> None:
        scope_lines = build_scope_lines(snapshot)

        self.query_one("#scope-content", Static).update(
            "\n".join(scope_lines)
        )
        self.query_one("#orchestration-summary", Static).update(
            "\n".join(
                build_orchestration_summary_lines(snapshot)
            )
        )
        self.query_one("#phase-progress", ProgressBar).update(
            total=100,
            progress=snapshot.phase_progress,
        )

        phase_table = self.query_one("#phase-table", DataTable)
        phase_table.clear()
        for row in phase_rows(
            snapshot.current_phase,
            snapshot.completed_phases,
        ):
            phase_table.add_row(*row)

        tools_table = self.query_one("#tools-table", DataTable)
        tools_table.clear()
        for row in tool_rows(snapshot):
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

        self._sync_activity_log(snapshot.recent_activity)
        self._apply_run_overlay()

    def _set_run_stage(self, stage: str | None) -> None:
        """Set the live-run stage label and refresh the overlay."""

        self._run_stage = stage
        self._update_runtime()

    def _apply_run_overlay(self) -> None:
        """Reflect an in-progress operator run in the header.

        While a run is active the phase progress pulses (indeterminate) and
        the overall status reads RUNNING · <stage>, so the header can never
        claim COMPLETED while nuclei/sqlmap is still executing.
        """

        if not self.is_mounted:
            return

        try:
            progress = self.query_one("#phase-progress", ProgressBar)
            summary = self.query_one("#orchestration-summary", Static)
        except Exception:
            return

        if self._run_stage is None:
            # Idle: restore the determinate progress bar. The authorize bar
            # is restored once in _finish_validation (not here) so it never
            # clobbers a URL the operator is typing between runs.
            progress.update(
                total=100,
                progress=self.snapshot.phase_progress,
            )
            return

        # Indeterminate pulse while the run is live.
        progress.update(total=None)

        # Show the live target + stage in the TARGET & AUTHORIZE bar and
        # lock it while the run is in flight.
        try:
            url_input = self.query_one("#target-url-input", Input)
            button = self.query_one("#authorize-button", Button)
            note = self.query_one("#authorize-note", Static)
        except Exception:
            url_input = button = note = None

        if url_input is not None and button is not None and note is not None:
            target = self._run_target or ""
            if url_input.value != target:
                url_input.value = target
            url_input.disabled = True
            button.disabled = True
            if str(button.label) != "RUNNING…":
                button.label = "RUNNING…"
            note.update(
                f"▶ RUNNING · {self._run_stage}"
                + (f"  ·  {target}" if target else "")
            )

        lines = build_orchestration_summary_lines(self.snapshot)
        overridden = [
            (
                "Overall Status       : "
                f"[bold yellow]RUNNING · {self._run_stage}[/bold yellow]"
            )
            if line.startswith("Overall Status")
            else line
            for line in lines
        ]
        summary.update("\n".join(overridden))

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
            "R refresh · U focus URL (Enter = full assessment) · "
            "P phases · T tools · E evidence · Q quit. "
            "AI analyzes automatically during the run.",
            timeout=7,
        )

    def action_quit(self) -> None:
        """Stop any running scanners before exiting the operator console."""

        self._terminate_running_scanners()
        self.exit()

    def on_unmount(self) -> None:
        # Safety net for non-'q' exit paths (ctrl+c, ctrl+q, crash): never
        # leave nuclei/sqlmap orphaned and scanning the target after exit.
        self._terminate_running_scanners()

    def _terminate_running_scanners(self) -> None:
        try:
            stopped = terminate_active_tools()
        except Exception:
            return
        if stopped:
            self._run_stage = None
            self._validation_running = False

    def action_ai_analyze(self) -> None:
        """Triage the latest run's evidence with the local AI model."""

        if self._analysis_running:
            self.notify(
                "An AI analysis is already running.",
                severity="warning",
            )
            return

        self._analysis_running = True
        self.notify("Analyzing the latest run with the local model…")
        self._append_validation_line(
            "[AI] Gathering run evidence for analysis…"
        )
        self.run_worker(
            self._run_analysis_worker,
            name="ai-analysis",
            group="ai-analysis",
            thread=True,
            exclusive=True,
        )

    def _run_analysis_worker(self) -> None:
        """Gather the run digest and ask the local model to triage it."""

        import asyncio

        from saarthi_ai.analysis import (
            AnalysisError,
            analyze_run,
            gather_run_digest,
        )
        from saarthi_ai.config import get_settings
        from saarthi_ai.llm.ollama_client import (
            OllamaUnavailableError,
            SaarthiOllamaClient,
        )
        from saarthi_ai.persistence.database import SaarthiDatabase

        def log(line: str) -> None:
            self.call_from_thread(self._append_validation_line, line)

        def fail(message: str) -> None:
            log(f"[AI][ERR] {message}")
            self.call_from_thread(
                self.notify,
                message,
                severity="error",
            )
            self.call_from_thread(self._finish_analysis)

        try:
            database = SaarthiDatabase(self.repository.database_path)
            digest = gather_run_digest(database)
        except AnalysisError as error:
            fail(str(error))
            return
        except Exception as error:  # defensive
            fail(f"Could not gather run evidence: {error}")
            return

        log(
            f"[AI] Target: {digest.target} | "
            f"findings={len(digest.findings)} | "
            f"phases={len(digest.phases)} | state={digest.parent_state}"
        )
        log("[AI] Querying the local model (this can take a moment)…")

        client = SaarthiOllamaClient(get_settings())
        try:
            content = asyncio.run(analyze_run(client, digest))
        except OllamaUnavailableError as error:
            fail(str(error))
            return
        except Exception as error:  # defensive
            fail(f"Analysis failed: {error}")
            return

        log("[AI] ── Analysis ─────────────────────────────")
        for line in content.splitlines() or ["(empty response)"]:
            log(f"[AI] {line}")
        log("[AI] ── End of analysis ──────────────────────")
        self.call_from_thread(
            self.notify,
            "AI analysis complete — see the activity log.",
        )
        self.call_from_thread(self._finish_analysis)

    def _finish_analysis(self) -> None:
        self._analysis_running = False

    def action_toggle_ai_live(self) -> None:
        """Toggle the live per-phase AI co-pilot for assessments."""

        self._ai_live_enabled = not self._ai_live_enabled
        state = "ON" if self._ai_live_enabled else "OFF"
        self.notify(f"Live AI co-pilot {state}.")

    def action_ai_propose(self) -> None:
        """Ask the AI for a queue of safe next actions (the propose step)."""

        if self._propose_running:
            self.notify(
                "Already generating proposals.", severity="warning"
            )
            return
        self._propose_running = True
        self._append_validation_line(
            "[AI] Generating proposed next actions from the latest evidence…"
        )
        self.run_worker(
            self._run_propose_worker,
            name="ai-propose",
            group="ai-propose",
            thread=True,
            exclusive=True,
        )

    def _run_propose_worker(self) -> None:
        """Build the safe action menu and let the model select/annotate it."""

        import asyncio

        from saarthi_ai.analysis import gather_run_digest
        from saarthi_ai.automation.chain_config import ChainConfigError
        from saarthi_ai.automation.proposals import propose_actions
        from saarthi_ai.config import get_settings
        from saarthi_ai.llm.ollama_client import (
            OllamaUnavailableError,
            SaarthiOllamaClient,
        )
        from saarthi_ai.persistence.database import SaarthiDatabase

        def log(line: str) -> None:
            self.call_from_thread(self._append_validation_line, line)

        try:
            derived = self._derive_chain_validation(
                confirmed_poc=True,
                single_row_dump=False,
            )
            database = SaarthiDatabase(self.repository.database_path)
            digest = gather_run_digest(
                database, orchestration_id=derived.orchestration_id
            )
        except ChainConfigError as error:
            log(f"[AI][ERR] No chain to propose from: {error}")
            self.call_from_thread(self._finish_propose)
            return
        except Exception as error:  # defensive: never crash the TUI
            log(f"[AI][ERR] Could not assemble proposals: {error}")
            self.call_from_thread(self._finish_propose)
            return

        try:
            client = SaarthiOllamaClient(get_settings())
            actions = asyncio.run(propose_actions(client, derived, digest))
        except OllamaUnavailableError as error:
            log(f"[AI][ERR] {error}")
            self.call_from_thread(self._finish_propose)
            return
        except Exception as error:  # defensive
            log(f"[AI][ERR] Proposal generation failed: {error}")
            self.call_from_thread(self._finish_propose)
            return

        self.call_from_thread(self._set_action_queue, actions)
        self.call_from_thread(self._finish_propose)

    def _set_action_queue(self, actions: list) -> None:
        self._ai_action_queue = list(actions)
        if not actions:
            self._append_validation_line(
                "[AI] No further actions proposed — nothing worth running."
            )
            return
        self._append_validation_line(
            f"[AI] {len(actions)} action(s) proposed — press "
            "[G] to run the next, [x] to skip:"
        )
        for index, action in enumerate(actions, start=1):
            self._append_validation_line(
                f"[AI]   {index}. {action.describe()}"
            )

    def _finish_propose(self) -> None:
        self._propose_running = False

    def action_ai_run_next(self) -> None:
        """Approve and execute the next AI-proposed action (approve step)."""

        from saarthi_ai.automation.chain_config import ChainConfigError
        from saarthi_ai.automation.proposals import build_action_derived

        if not self._ai_action_queue:
            self.notify(
                "No AI actions queued — press g to propose.",
                severity="warning",
            )
            return
        if self._validation_running:
            self.notify(
                "A validation run is already in progress.",
                severity="warning",
            )
            return

        action = self._ai_action_queue.pop(0)
        try:
            base = self._derive_chain_validation(
                confirmed_poc=True,
                single_row_dump=False,
            )
            derived = build_action_derived(base, action)
        except ChainConfigError as error:
            self.notify(f"Cannot run action: {error}", severity="error")
            return
        except Exception as error:  # defensive
            self.notify(f"Cannot build action: {error}", severity="error")
            return

        self._append_validation_line(
            f"[AI] Operator approved → {action.label}"
        )
        self._launch_validation(derived, confirmed=True)

    def action_ai_skip(self) -> None:
        """Discard the next AI-proposed action (the skip step)."""

        if not self._ai_action_queue:
            self.notify("No AI actions queued.", severity="warning")
            return
        action = self._ai_action_queue.pop(0)
        self._append_validation_line(f"[AI] Skipped → {action.label}")

    def _start_ai_observer(self, orchestration_id: str) -> None:
        """Start the live AI observer for a just-created orchestration."""

        if not self._ai_live_enabled or self._ai_observer_running:
            return
        self._ai_observer_running = True
        self.run_worker(
            lambda: self._run_ai_observer_worker(orchestration_id),
            name="ai-observer",
            group="ai-observer",
            thread=True,
            exclusive=True,
        )

    def _finish_ai_observer(self) -> None:
        self._ai_observer_running = False

    def _run_ai_observer_worker(self, orchestration_id: str) -> None:
        """Comment on each phase as it completes, then a final triage."""

        import asyncio
        import time

        from saarthi_ai.analysis import (
            analyze_run,
            gather_phase_digest,
            gather_run_digest,
            suggest_for_phase,
        )
        from saarthi_ai.config import get_settings
        from saarthi_ai.llm.ollama_client import (
            OllamaUnavailableError,
            SaarthiOllamaClient,
        )
        from saarthi_ai.persistence.database import SaarthiDatabase

        def log(line: str) -> None:
            self.call_from_thread(self._append_validation_line, line)

        try:
            database = SaarthiDatabase(self.repository.database_path)
            client = SaarthiOllamaClient(get_settings())
        except Exception:
            self.call_from_thread(self._finish_ai_observer)
            return

        log("[AI] Live co-pilot watching the assessment…")
        seen: set[str] = set()
        commented = 0
        max_comments = 30
        llm_ok = True
        target = ""
        # Watch for the full run (tools now have generous budgets) so the
        # final AI triage always fires instead of the observer expiring early.
        deadline = time.monotonic() + 14400.0

        while time.monotonic() < deadline:
            running = self._validation_running
            try:
                executions = database.list_executions(limit=1_000)
            except Exception:
                executions = []

            children = []
            for execution in executions:
                meta = execution.metadata or {}
                if meta.get("orchestration_id") != orchestration_id:
                    continue
                role = meta.get("execution_role")
                if role == "orchestration_parent" and execution.targets:
                    target = target or str(execution.targets[0])
                elif role == "orchestration_child":
                    children.append(execution)

            children.sort(key=lambda item: item.created_at)
            for child in children:
                if child.execution_id in seen:
                    continue
                if child.state.value not in ("completed", "failed"):
                    continue
                seen.add(child.execution_id)
                if not llm_ok or commented >= max_comments:
                    continue
                try:
                    digest = gather_phase_digest(
                        database, child, target=target
                    )
                    text = asyncio.run(suggest_for_phase(client, digest))
                except OllamaUnavailableError:
                    log("[AI] Ollama unavailable — live suggestions paused.")
                    llm_ok = False
                    continue
                except Exception:
                    continue
                commented += 1
                header = f"{digest.phase_code} {digest.phase_name}".strip()
                log(f"[AI] ▸ {header}:")
                for line in text.splitlines():
                    if line.strip():
                        log(f"[AI]   {line.strip()}")

            if not running:
                break
            time.sleep(3.0)

        if llm_ok and commented:
            try:
                run_digest = gather_run_digest(
                    database, orchestration_id=orchestration_id
                )
                text = asyncio.run(analyze_run(client, run_digest))
                log("[AI] ══ Final triage ══")
                for line in text.splitlines():
                    if line.strip():
                        log(f"[AI] {line.strip()}")
            except Exception:
                pass

        self.call_from_thread(self._finish_ai_observer)

    def action_run_validation(self) -> None:
        """Run nuclei + SQLMap from the chain with confirmed-PoC proof."""

        self._start_validation(
            confirmed_poc=True,
            single_row_dump=False,
        )

    def action_run_validation_dump(self) -> None:
        """Run nuclei + SQLMap and permit a bounded single-row dump."""

        self._start_validation(
            confirmed_poc=True,
            single_row_dump=True,
        )

    def action_focus_url(self) -> None:
        self.query_one("#target-url-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "target-url-input":
            return

        url = event.value.strip()
        event.input.value = ""
        self._start_full_assessment(url)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "authorize-button":
            return

        url_input = self.query_one("#target-url-input", Input)
        url = url_input.value.strip()
        url_input.value = ""
        self._start_full_assessment(url)

    def _start_full_assessment(self, url: str) -> None:
        """Validate a typed URL, then ask the operator to confirm launch."""

        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            self.notify(
                "Enter an absolute http(s) URL, e.g. "
                "https://target/path?id=1",
                severity="error",
            )
            return

        if self._validation_running:
            self.notify(
                "A run is already in progress.",
                severity="warning",
            )
            return

        body = (
            f"Target : {url}\n"
            f"Host   : {parsed.hostname}\n\n"
            "This runs REAL active + intrusive testing:\n"
            "  • Recon (DNS, subdomains, HTTP, crawl, JS)\n"
            "  • Phase 6 safe validators\n"
            "  • Nuclei scan + SQLMap (confirmed-PoC)\n\n"
            "Proceed only on a target you are authorized to test.\n"
            "[Y] Launch   ·   [N]/[Esc] Cancel"
        )
        self.push_screen(
            ConfirmScanScreen("⚠  LAUNCH FULL ASSESSMENT?", body),
            lambda confirmed: self._launch_full_assessment(
                url,
                bool(confirmed),
            ),
        )

    def _launch_full_assessment(self, url: str, confirmed: bool) -> None:
        """Start the assessment worker once the operator has confirmed."""

        if not confirmed:
            self.notify("Full assessment cancelled.")
            return

        if self._validation_running:
            self.notify(
                "A run is already in progress.",
                severity="warning",
            )
            return

        self._validation_running = True
        self._run_target = url
        self._set_run_stage("Starting…")
        self.notify(
            f"Starting full assessment for {urlsplit(url).hostname}…"
        )
        self._append_validation_line(
            f"[INF] Operator launched full assessment for: {url}"
        )

        self.run_worker(
            lambda: self._run_full_assessment_worker(url),
            name="full-assessment",
            group="auto-validation",
            thread=True,
            exclusive=True,
        )

    def _run_full_assessment_worker(self, url: str) -> None:
        """Create a chain for the URL, run recon + Phase 6, then scan."""

        import asyncio

        from saarthi_ai.automation.auto_validation import (
            AutoValidationError,
            run_automatic_validation,
        )
        from saarthi_ai.automation.chain_config import (
            ChainConfigError,
            build_auto_validation_config_from_chain,
        )
        from saarthi_ai.execution.tool_runner import (
            ToolOutputEvent,
            ToolRunnerError,
        )
        from saarthi_ai.persistence.database import SaarthiDatabase
        from saarthi_ai.persistence.orchestration_workflow import (
            create_orchestration,
            run_assessment_pipeline,
        )
        from saarthi_ai.persistence.phase6_chain_workflow import (
            run_phase6_safe_chain,
        )

        actor = "saarthi-ops-tui"

        def log_line(line: str) -> None:
            self.call_from_thread(self._append_validation_line, line)

        def fail(message: str) -> None:
            log_line(f"[ERR] {message}")
            self.call_from_thread(
                self.notify,
                message,
                severity="error",
            )
            self.call_from_thread(self._finish_validation)

        try:
            database = SaarthiDatabase(self.repository.database_path)
            context = create_orchestration(
                database,
                assessment_name="Saarthi OPS ad-hoc assessment",
                target_url=url,
                active_testing_allowed=True,
                intrusive_testing_allowed=True,
                rate_limit_per_second=2,
                actor=actor,
            )
            evidence_root = (
                Path.cwd()
                / "evidence"
                / "orchestrations"
                / context.orchestration_id
            )

            log_line(
                f"[INF] Orchestration {context.orchestration_id} created."
            )
            self.call_from_thread(
                self._start_ai_observer,
                context.orchestration_id,
            )
            self.call_from_thread(self._set_run_stage, "Recon (3A–4A)")
            log_line("[INF] Running recon pipeline (Phase 3A-4A)…")
            result = run_assessment_pipeline(
                database,
                context,
                evidence_root=evidence_root,
                explicitly_approved=True,
                actor=actor,
            )
            for phase in result.phase_results:
                log_line(
                    f"[{phase.phase.value}] {phase.outcome.value}"
                )

            self.call_from_thread(self._set_run_stage, "Phase 6 chain")
            log_line("[INF] Running permission-gated Phase 6 chain…")
            asyncio.run(
                run_phase6_safe_chain(
                    database,
                    result.context,
                    evidence_root=evidence_root / "phase6",
                    explicitly_approved=True,
                    nuclei_preview_approved=False,
                    sqlmap_preview_approved=False,
                    nuclei_execute_approved=False,
                    actor=actor,
                )
            )

            self.call_from_thread(
                self._set_run_stage,
                "Nuclei + SQLMap",
            )
            log_line("[INF] Executing real Nuclei + SQLMap validation…")
            derived = build_auto_validation_config_from_chain(
                database,
                approved=True,
                orchestration_id=context.orchestration_id,
                confirmed_poc=True,
                single_row_dump=False,
                adaptive=True,
                allow_waf_bypass=True,
                evidence_root=evidence_root / "auto-validation",
            )
        except ChainConfigError as error:
            fail(str(error))
            return
        except Exception as error:  # defensive: never wedge the run flag
            fail(f"Assessment pipeline failed: {error}")
            return

        log_line(f"[INF] Target        : {derived.target_url}")
        if derived.sqlmap_parameters:
            log_line(
                "[INF] SQLMap params  : "
                + ", ".join(derived.sqlmap_parameters)
            )
        else:
            log_line("[INF] SQLMap params  : none (Nuclei-only run)")

        live_feed, live_stop = self._spawn_live_scan_ai(derived.target_url)

        def on_output(event: ToolOutputEvent) -> None:
            line = f"[{event.tool_name}:{event.stream}] {event.line}"
            live_feed(line)
            self.call_from_thread(self._append_validation_line, line)

        try:
            validation = run_automatic_validation(
                derived.config,
                on_output=on_output,
                on_log=log_line,
                on_adapt=self._make_adapt_callback(),
            )
        except (AutoValidationError, ToolRunnerError) as error:
            fail(str(error))
            return
        except Exception as error:  # defensive: surface, never crash the TUI
            fail(f"Validation run failed: {error}")
            return
        finally:
            live_stop()

        nuclei_exit = validation.nuclei.get("exit_code")
        log_line(
            f"[OK ] Full assessment complete. nuclei exit={nuclei_exit}, "
            f"sqlmap runs={len(validation.sqlmap)}."
        )
        log_line(f"[OK ] Evidence: {validation.evidence_path}")
        self.call_from_thread(
            self.notify,
            "Full assessment complete — evidence saved.",
        )
        self.call_from_thread(self._finish_validation)

    def _start_validation(
        self,
        *,
        confirmed_poc: bool,
        single_row_dump: bool,
    ) -> None:
        """Derive the chain target, then ask the operator to confirm."""

        if self._validation_running:
            self.notify(
                "A validation run is already in progress.",
                severity="warning",
            )
            return

        from saarthi_ai.automation.chain_config import ChainConfigError

        try:
            derived = self._derive_chain_validation(
                confirmed_poc=confirmed_poc,
                single_row_dump=single_row_dump,
            )
        except ChainConfigError as error:
            self._append_validation_line(f"[ERR] {error}")
            self.notify(str(error), severity="error")
            return
        except Exception as error:  # defensive: surface, never crash
            self._append_validation_line(
                f"[ERR] Could not read the workflow chain: {error}"
            )
            self.notify(
                "Could not read the workflow chain.",
                severity="error",
            )
            return

        params = (
            ", ".join(derived.sqlmap_parameters)
            if derived.sqlmap_parameters
            else "none (nuclei-only)"
        )
        dump_note = (
            "single-row --dump ENABLED"
            if derived.config.sqlmap_poc_single_row_dump
            else "identity proof only (no data dump)"
        )
        body = (
            f"Target : {derived.target_url}\n"
            f"Hosts  : {', '.join(derived.config.allowed_hosts)}\n"
            f"SQLMap : {params}\n"
            f"Mode   : confirmed-PoC · {dump_note}\n\n"
            "This runs REAL Nuclei + SQLMap against the chain target.\n"
            "Proceed only on a target you are authorized to test.\n"
            "[Y] Run   ·   [N]/[Esc] Cancel"
        )
        self.push_screen(
            ConfirmScanScreen("⚠  RUN NUCLEI + SQLMAP?", body),
            lambda confirmed: self._launch_validation(
                derived,
                bool(confirmed),
            ),
        )

    def _derive_chain_validation(
        self,
        *,
        confirmed_poc: bool,
        single_row_dump: bool,
    ):
        """Read the latest chain and build a run config (main thread)."""

        from saarthi_ai.automation.chain_config import (
            build_auto_validation_config_from_chain,
        )
        from saarthi_ai.persistence.database import SaarthiDatabase

        database = SaarthiDatabase(self.repository.database_path)
        return build_auto_validation_config_from_chain(
            database,
            approved=True,
            confirmed_poc=confirmed_poc,
            single_row_dump=single_row_dump,
            adaptive=True,
            allow_waf_bypass=True,
            evidence_root=(
                Path.cwd() / "evidence" / "automatic-validation"
            ),
        )

    def _make_adapt_callback(self):
        """Build an on_adapt callback that streams an AI rationale per change."""

        import asyncio

        from saarthi_ai.analysis import explain_adaptation
        from saarthi_ai.config import get_settings
        from saarthi_ai.llm.ollama_client import SaarthiOllamaClient

        try:
            client = SaarthiOllamaClient(get_settings())
        except Exception:
            client = None

        def on_adapt(event) -> None:
            if client is None:
                return
            try:
                text = asyncio.run(explain_adaptation(client, event))
            except Exception:
                return
            if text:
                self.call_from_thread(
                    self._append_validation_line, f"[AI] {text}"
                )

        return on_adapt

    def _launch_validation(self, derived, confirmed: bool) -> None:
        """Start the validation worker once the operator has confirmed."""

        if not confirmed:
            self.notify("Validation cancelled.")
            return

        if self._validation_running:
            self.notify(
                "A validation run is already in progress.",
                severity="warning",
            )
            return

        self._validation_running = True
        self._run_target = derived.target_url
        label = "Nuclei + SQLMap"
        if derived.config.sqlmap_poc_single_row_dump:
            label += " (+1-row dump)"

        self._set_run_stage(label)
        self.notify(f"Launching {label} from the Phase 6 chain…")
        self._append_validation_line(
            f"[INF] Operator launched chain-derived validation: {label}."
        )

        self.run_worker(
            lambda: self._run_validation_worker(derived),
            name="auto-validation",
            group="auto-validation",
            thread=True,
            exclusive=True,
        )

    def _spawn_live_scan_ai(self, target_url: str):
        """Start a non-blocking live AI co-pilot over streamed scan output.

        Returns ``(feed, stop)``. ``feed(line)`` buffers one tool-output
        line; ``stop()`` ends the watcher. While the scan runs, a daemon
        thread asks the local model for a terse note on the latest
        nuclei/sqlmap output every ~40s, so the operator sees AI analysis
        DURING nuclei and sqlmap — not only when the phase completes. The
        model call happens on its own thread and never blocks the tools.
        A no-op recorder is returned when live AI is toggled off.
        """

        import threading

        lines: list[str] = []
        lock = threading.Lock()
        stop_event = threading.Event()

        def feed(line: str) -> None:
            with lock:
                lines.append(line)

        if not self._ai_live_enabled:
            return feed, (lambda: None)

        def loop() -> None:
            import asyncio
            import time as _time

            from saarthi_ai.analysis import comment_on_live_output
            from saarthi_ai.config import get_settings
            from saarthi_ai.llm.ollama_client import (
                OllamaUnavailableError,
                SaarthiOllamaClient,
            )

            def log(line: str) -> None:
                self.call_from_thread(self._append_validation_line, line)

            try:
                client = SaarthiOllamaClient(get_settings())
            except Exception:
                return

            log("[AI] Live co-pilot watching nuclei/sqlmap output…")
            seen = 0
            comments = 0
            max_comments = 25
            interval = 40.0
            next_at = _time.monotonic() + interval
            while not stop_event.is_set():
                if _time.monotonic() < next_at:
                    _time.sleep(1.0)
                    continue
                next_at = _time.monotonic() + interval
                with lock:
                    fresh = lines[seen:]
                    seen = len(lines)
                if not fresh or comments >= max_comments:
                    continue
                tail = fresh[-40:]
                tool = (
                    "sqlmap"
                    if any("[sqlmap" in item for item in tail)
                    else "nuclei"
                )
                try:
                    note = asyncio.run(
                        comment_on_live_output(
                            client, tool, target_url, tail
                        )
                    )
                except OllamaUnavailableError:
                    log("[AI] Ollama unavailable — live notes paused.")
                    return
                except Exception:
                    continue
                comments += 1
                for entry in note.splitlines():
                    if entry.strip():
                        log(f"[AI] {entry.strip()}")

        thread = threading.Thread(
            target=loop, name="live-scan-ai", daemon=True
        )
        thread.start()

        def stop() -> None:
            stop_event.set()
            thread.join(timeout=8.0)

        return feed, stop

    def _run_validation_worker(self, derived) -> None:
        """Run nuclei+SQLMap for a pre-derived chain config in a thread."""

        from saarthi_ai.automation.auto_validation import (
            AutoValidationError,
            run_automatic_validation,
        )
        from saarthi_ai.execution.tool_runner import (
            ToolOutputEvent,
            ToolRunnerError,
        )

        def log_line(line: str) -> None:
            self.call_from_thread(self._append_validation_line, line)

        def fail(message: str) -> None:
            log_line(f"[ERR] {message}")
            self.call_from_thread(
                self.notify,
                message,
                severity="error",
            )
            self.call_from_thread(self._finish_validation)

        log_line(f"[INF] Target (chain) : {derived.target_url}")
        log_line(
            f"[INF] Allowed hosts  : {', '.join(derived.allowed_hosts)}"
        )
        if derived.sqlmap_parameters:
            log_line(
                "[INF] SQLMap params  : "
                + ", ".join(derived.sqlmap_parameters)
            )
        else:
            log_line(
                "[INF] SQLMap params  : none "
                "(intrusive testing not authorized; nuclei-only run)"
            )

        live_feed, live_stop = self._spawn_live_scan_ai(derived.target_url)

        def on_output(event: ToolOutputEvent) -> None:
            line = f"[{event.tool_name}:{event.stream}] {event.line}"
            live_feed(line)
            self.call_from_thread(self._append_validation_line, line)

        try:
            result = run_automatic_validation(
                derived.config,
                on_output=on_output,
                on_log=log_line,
                on_adapt=self._make_adapt_callback(),
            )
        except (AutoValidationError, ToolRunnerError) as error:
            fail(str(error))
            return
        except Exception as error:  # defensive: surface, never crash the TUI
            fail(f"Validation run failed: {error}")
            return
        finally:
            live_stop()

        nuclei_exit = result.nuclei.get("exit_code")
        log_line(
            f"[OK ] Completed. nuclei exit={nuclei_exit}, "
            f"sqlmap runs={len(result.sqlmap)}."
        )
        log_line(f"[OK ] Evidence: {result.evidence_path}")
        self.call_from_thread(
            self.notify,
            (
                "Validation complete — evidence saved "
                f"({len(result.sqlmap)} SQLMap runs)."
            ),
        )
        self.call_from_thread(self._finish_validation)

    def _append_validation_line(self, line: str) -> None:
        self._live_validation_lines.append(line)
        if len(self._live_validation_lines) > MAX_LIVE_VALIDATION_LINES:
            del self._live_validation_lines[:-MAX_LIVE_VALIDATION_LINES]

        if self.is_mounted:
            try:
                self.query_one("#activity-log", RichLog).write(line)
                # Keep the render cursor in sync so the next refresh appends
                # only new DB events rather than redrawing the whole log.
                self._rendered_lines.append(line)
            except Exception:
                # The log widget may be unavailable mid-teardown.
                return

    def _sync_activity_log(self, activity_lines: list[str]) -> None:
        """Append only new activity to the live log (no clear/flicker).

        The desired log is the DB audit events for the whole orchestration
        (every phase and tool) followed by the live tool lines. When the log
        only grew, write just the new tail; otherwise (reset / scrollback
        rolled over / new run) redraw once.
        """

        try:
            log = self.query_one("#activity-log", RichLog)
        except Exception:
            return

        desired = list(activity_lines) + list(self._live_validation_lines)
        activity_count = len(activity_lines)

        def write_at(index: int, text: str) -> None:
            if index < activity_count:
                log.write(build_activity_text(text))
            else:
                log.write(text)

        previous = self._rendered_lines
        if desired[: len(previous)] == previous:
            for index in range(len(previous), len(desired)):
                write_at(index, desired[index])
        else:
            log.clear()
            for index, text in enumerate(desired):
                write_at(index, text)

        self._rendered_lines = desired

    def _finish_validation(self) -> None:
        self._validation_running = False
        self._run_stage = None
        self._run_target = None
        self._restore_authorize_bar()
        self.snapshot = self.repository.load()
        self._update_runtime()

    def _restore_authorize_bar(self) -> None:
        """Re-enable and clear the TARGET & AUTHORIZE bar after a run."""

        try:
            url_input = self.query_one("#target-url-input", Input)
            button = self.query_one("#authorize-button", Button)
            note = self.query_one("#authorize-note", Static)
        except Exception:
            return

        url_input.value = ""
        url_input.disabled = False
        button.disabled = False
        button.label = AUTHORIZE_BUTTON_LABEL
        note.update(AUTHORIZE_NOTE_IDLE)


def run() -> None:
    SaarthiDashboard().run()


if __name__ == "__main__":
    run()
