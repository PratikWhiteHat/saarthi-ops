from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

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

        order_sql = execution_order_sql(
            updated_column,
            completed_column,
            created_column,
        )

        rows = connection.execute(
            f'SELECT * FROM "{execution_table}" {order_sql} LIMIT 6'
        ).fetchall()
        if not rows:
            return demo_snapshot(["[INF] No executions are currently stored."])

        latest = rows[0]

        def value(row: sqlite3.Row, column: str | None, default: str) -> str:
            if column is None or row[column] is None:
                return default
            return str(row[column])

        execution_id = value(latest, id_column, "unknown")
        execution_state = value(latest, state_column, "unknown")

        recent_executions: list[dict[str, str]] = []
        for row in rows:
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
                    "phase": infer_phase_short(
                        value(row, state_column, "unknown"),
                        row_evidence_types,
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
            recent_activity=self._load_activity(
                connection,
                tables,
                execution_id,
            ),
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
        return "PLANNING"

    if normalized == "failed":
        return "EXECUTION REVIEW"

    return "CURRENT WORKFLOW"


def infer_phase_short(
    state: str,
    evidence_types: Iterable[str] = (),
) -> str:
    """Return the compact phase label used by the execution table."""

    phase = infer_phase(state, evidence_types)

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


PHASES = [
    ("✓", "3A", "DNS Intelligence", "DONE", "2026-07-31 12:48"),
    ("✓", "3B", "Subdomain Enumeration", "DONE", "2026-07-31 13:05"),
    ("✓", "3C", "Live Host Intelligence", "DONE", "2026-08-02 09:42"),
    ("✓", "3D", "Crawling & URL Intelligence", "DONE", "2026-08-02 20:15"),
    ("✓", "3E", "JavaScript Intelligence", "DONE", "2026-08-02 22:35"),
    ("→", "4A", "Direct Vulnerability Checks", "NEXT", "—"),
    ("·", "4B", "Blind Validation", "PLANNED", "—"),
    ("·", "4C", "OAST Manager", "PLANNED", "—"),
    ("·", "4D", "Confirmation Engine", "PLANNED", "—"),
]

TOOLS = [
    ("subfinder", "Subdomain Discovery", "ENABLED"),
    ("amass", "Passive Asset Discovery", "ENABLED"),
    ("assetfinder", "Passive Asset Discovery", "ENABLED"),
    ("crt.sh", "Certificate Transparency", "ENABLED"),
    ("httpx", "Live Host & Service Probe", "ENABLED"),
    ("katana", "Web Crawler", "ENABLED"),
    ("nuclei", "Template-based Scanning", "PLANNED"),
    ("sqlmap", "SQL Injection Testing", "PHASE 4"),
    ("ghauri", "Blind SQLi Cross-check", "PHASE 4"),
    ("Saarthi JS", "JavaScript Intelligence", "ENABLED"),
    ("OAST Manager", "Out-of-band Correlation", "PHASE 4"),
]


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
                yield Label("LATEST 12 EVENTS", id="activity-caption")
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
        self.query_one("#scope-content", Static).update(
            "\n".join(
                [
                    f"Project Name       : {snapshot.project_name}",
                    f"Execution ID       : {snapshot.execution_id}",
                    f"Target Scope       : {snapshot.target_scope}",
                    "Authorization      : [green]✓ CONFIRMED[/green]",
                    "Rules of Engagement: [green]✓ ACCEPTED[/green]",
                    "Data Handling      : LOCAL ONLY",
                    f"Mode               : {snapshot.mode}",
                    f"Current Phase      : {snapshot.current_phase}",
                    f"Evidence / Findings: {snapshot.evidence_count} / {snapshot.finding_count}",
                ]
            )
        )
        self.query_one("#phase-progress", ProgressBar).update(progress=snapshot.phase_progress)

        phase_table = self.query_one("#phase-table", DataTable)
        phase_table.clear()
        for row in PHASES:
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

    def action_refresh(self) -> None:
        self.snapshot = self.repository.load()
        self._update_runtime()
        self.notify("Dashboard refreshed from the local read-only database.")

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
