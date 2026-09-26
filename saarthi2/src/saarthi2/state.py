"""Run state: SQLite (default) or PostgreSQL for runs/steps/findings + a
sha256 evidence store + an audit log.

The backend is chosen by ``database_url``: empty/absent -> local SQLite file;
a ``postgres://`` / ``postgresql://`` URL -> PostgreSQL (needs ``psycopg``). A
small dialect object papers over the placeholder style (``?`` vs ``%s``) and the
run upsert (``INSERT OR REPLACE`` vs ``ON CONFLICT``) so the rest of the code is
backend-agnostic.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from saarthi2.engine.models import RunResult, StepResult

# Bounded copy of a step's output kept in the DB for fast display; the full
# output of a tool step also lives on disk as sha256 evidence.
OUTPUT_PREVIEW_LIMIT = 20_000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    workflow TEXT NOT NULL,
    target TEXT,
    workspace TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS steps (
    run_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    status TEXT NOT NULL,
    exit_code INTEGER,
    duration_ms INTEGER,
    evidence_path TEXT,
    error TEXT,
    output TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    run_id TEXT NOT NULL,
    tool TEXT,
    rule_id TEXT,
    severity TEXT,
    message TEXT,
    location TEXT,
    created_at TEXT NOT NULL
);
"""


_RUN_COLUMNS = "(run_id, workflow, target, workspace, status, created_at, updated_at)"


@dataclass(frozen=True)
class _Dialect:
    """Per-backend SQL differences (placeholder style + run upsert)."""

    name: str
    placeholder: str

    def q(self, sql: str) -> str:
        """Translate ``?`` placeholders to the backend's style."""

        return sql if self.placeholder == "?" else sql.replace("?", self.placeholder)

    def upsert_runs(self) -> str:
        base = f"INSERT INTO runs {_RUN_COLUMNS} VALUES (?,?,?,?,?,?,?)"
        if self.name == "sqlite":
            return self.q(f"INSERT OR REPLACE INTO runs {_RUN_COLUMNS} VALUES (?,?,?,?,?,?,?)")
        return self.q(
            base + " ON CONFLICT (run_id) DO UPDATE SET "
            "workflow=EXCLUDED.workflow, target=EXCLUDED.target, "
            "workspace=EXCLUDED.workspace, status=EXCLUDED.status, "
            "updated_at=EXCLUDED.updated_at"
        )


def dialect_for(database_url: str) -> _Dialect:
    """Pick a dialect from a database URL (empty -> SQLite)."""

    scheme = (database_url or "").split("://", 1)[0].lower()
    if scheme in ("postgres", "postgresql"):
        return _Dialect("postgres", "%s")
    return _Dialect("sqlite", "?")


class Store:
    """A small persistence layer for runs/steps/findings (SQLite or PostgreSQL)."""

    def __init__(
        self,
        db_path: Path,
        evidence_dir: Path,
        audit_path: Path,
        database_url: str = "",
    ) -> None:
        self.db_path = Path(db_path)
        self.evidence_dir = Path(evidence_dir)
        self.audit_path = Path(audit_path)
        self.database_url = database_url
        self._dialect = dialect_for(database_url)
        self._q = self._dialect.q
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)

        if self._dialect.name == "sqlite":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self.db_path, timeout=5.0)
            self._conn.execute("PRAGMA journal_mode=WAL")
        else:
            import psycopg  # lazy: only for the PostgreSQL backend

            self._conn = psycopg.connect(database_url)

        for statement in _SCHEMA.split(";"):
            statement = statement.strip()
            if statement:
                self._conn.execute(statement)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """Additive migrations for databases created by an older schema."""

        runs_cols = self._table_columns("runs")
        if "workspace" not in runs_cols:
            self._conn.execute("ALTER TABLE runs ADD COLUMN workspace TEXT")
        steps_cols = self._table_columns("steps")
        if "output" not in steps_cols:
            self._conn.execute("ALTER TABLE steps ADD COLUMN output TEXT")

    def _table_columns(self, table: str) -> set[str]:
        if self._dialect.name == "sqlite":
            return {row[1] for row in self._conn.execute(f"PRAGMA table_info({table})").fetchall()}
        return {
            row[0]
            for row in self._conn.execute(
                self._q(
                    "SELECT column_name FROM information_schema.columns WHERE table_name = ?"
                ),
                (table,),
            ).fetchall()
        }

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()

    def create_run(self, run: RunResult) -> None:
        now = self._now()
        self._conn.execute(
            self._dialect.upsert_runs(),
            (run.run_id, run.workflow, run.target, run.workspace, run.status.value, now, now),
        )
        self._conn.commit()
        self.audit(
            "run_created",
            {"run_id": run.run_id, "workflow": run.workflow, "workspace": run.workspace},
        )

    def update_run(self, run: RunResult) -> None:
        self._conn.execute(
            self._q("UPDATE runs SET status=?, updated_at=? WHERE run_id=?"),
            (run.status.value, self._now(), run.run_id),
        )
        self._conn.commit()
        self.audit("run_updated", {"run_id": run.run_id, "status": run.status.value})

    def record_step(self, run_id: str, step: StepResult) -> None:
        self._conn.execute(
            self._q(
                "INSERT INTO steps "
                "(run_id, step_id, status, exit_code, duration_ms, evidence_path, "
                "error, output, created_at) VALUES (?,?,?,?,?,?,?,?,?)"
            ),
            (
                run_id,
                step.step_id,
                step.status.value,
                step.exit_code,
                step.duration_ms,
                step.evidence_path,
                step.error,
                (step.output or "")[:OUTPUT_PREVIEW_LIMIT],
                self._now(),
            ),
        )
        self._conn.commit()

    def record_findings(self, run_id: str, findings: list[dict]) -> int:
        now = self._now()
        rows = [
            (
                run_id,
                str(f.get("tool", "")),
                str(f.get("rule_id", "")),
                str(f.get("severity", "info")),
                str(f.get("message", ""))[:1000],
                str(f.get("location", ""))[:500],
                now,
            )
            for f in findings
            if isinstance(f, dict)
        ]
        if not rows:
            return 0
        cursor = self._conn.cursor()
        cursor.executemany(self._q("INSERT INTO findings VALUES (?,?,?,?,?,?,?)"), rows)
        self._conn.commit()
        return len(rows)

    def list_findings(self, run_id: str | None = None, limit: int = 500) -> list[dict]:
        if run_id is None:
            cursor = self._conn.execute(
                self._q(
                    "SELECT run_id, tool, rule_id, severity, message, location, created_at "
                    "FROM findings ORDER BY created_at DESC LIMIT ?"
                ),
                (limit,),
            )
        else:
            cursor = self._conn.execute(
                self._q(
                    "SELECT run_id, tool, rule_id, severity, message, location, created_at "
                    "FROM findings WHERE run_id = ? ORDER BY created_at DESC LIMIT ?"
                ),
                (run_id, limit),
            )
        cols = [c[0] for c in cursor.description]
        return [dict(zip(cols, row, strict=True)) for row in cursor.fetchall()]

    def save_evidence(self, run_id: str, name: str, content: bytes) -> tuple[str, str]:
        """Write bounded evidence to disk; return (path, sha256)."""

        digest = hashlib.sha256(content).hexdigest()
        run_dir = self.evidence_dir / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        path = run_dir / f"{name}-{digest[:12]}"
        path.write_bytes(content)
        return str(path), digest

    def list_runs(self, limit: int = 100, workspace: str | None = None) -> list[dict]:
        select = (
            "SELECT run_id, workflow, target, workspace, status, created_at, updated_at "
            "FROM runs "
        )
        if workspace is None:
            cursor = self._conn.execute(
                self._q(select + "ORDER BY created_at DESC LIMIT ?"), (limit,)
            )
        else:
            cursor = self._conn.execute(
                self._q(select + "WHERE workspace = ? ORDER BY created_at DESC LIMIT ?"),
                (workspace, limit),
            )
        cols = [c[0] for c in cursor.description]
        return [dict(zip(cols, row, strict=True)) for row in cursor.fetchall()]

    def list_workspaces(self) -> list[dict]:
        """Distinct workspaces with run counts + last activity (newest first)."""

        cursor = self._conn.execute(
            "SELECT COALESCE(workspace, '') AS workspace, COUNT(*) AS runs, "
            "MAX(updated_at) AS last_run FROM runs GROUP BY workspace "
            "ORDER BY last_run DESC"
        )
        cols = [c[0] for c in cursor.description]
        return [dict(zip(cols, row, strict=True)) for row in cursor.fetchall()]

    def get_run(self, run_id: str) -> dict | None:
        cursor = self._conn.execute(
            self._q(
                "SELECT run_id, workflow, target, workspace, status, created_at, updated_at "
                "FROM runs WHERE run_id = ?"
            ),
            (run_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        cols = [c[0] for c in cursor.description]
        return dict(zip(cols, row, strict=True))

    def list_steps(self, run_id: str) -> list[dict]:
        cursor = self._conn.execute(
            self._q(
                "SELECT step_id, status, exit_code, duration_ms, evidence_path, error, "
                "output, created_at FROM steps WHERE run_id = ? ORDER BY created_at"
            ),
            (run_id,),
        )
        cols = [c[0] for c in cursor.description]
        return [dict(zip(cols, row, strict=True)) for row in cursor.fetchall()]

    def read_evidence(self, path: str, limit: int = 200_000) -> str:
        """Read a bounded slice of an evidence file, if it is under evidence_dir."""

        target = Path(path)
        root = self.evidence_dir.resolve()
        try:
            resolved = target.resolve()
            resolved.relative_to(root)  # raises if outside the evidence tree
        except (ValueError, OSError):
            return ""
        if not resolved.is_file():
            return ""
        return resolved.read_text(encoding="utf-8", errors="replace")[:limit]

    def stats(self) -> dict:
        """Aggregate counts for the dashboard: runs by status + findings by severity."""

        runs_by_status: dict[str, int] = {}
        for status, count in self._conn.execute(
            "SELECT status, COUNT(*) FROM runs GROUP BY status"
        ).fetchall():
            runs_by_status[str(status)] = int(count)

        findings_by_severity: dict[str, int] = {}
        for severity, count in self._conn.execute(
            "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
        ).fetchall():
            findings_by_severity[str(severity)] = int(count)

        return {
            "runs": sum(runs_by_status.values()),
            "runs_by_status": runs_by_status,
            "findings": sum(findings_by_severity.values()),
            "findings_by_severity": findings_by_severity,
        }

    def tail_audit(self, limit: int = 100) -> list[dict]:
        """Return the last ``limit`` audit records (newest first)."""

        if not self.audit_path.is_file():
            return []
        lines = self.audit_path.read_text(encoding="utf-8", errors="replace").splitlines()
        records: list[dict] = []
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if len(records) >= limit:
                break
        return records

    def import_snapshot(self, payload: dict, new_run_id: str | None = None) -> str:
        """Import a snapshot (the JSON produced by ``report.render_json``).

        Re-inserts the run row, its steps, and its findings under ``new_run_id``
        (or the snapshot's original run id). Returns the run id used.
        """

        run = dict(payload.get("run") or {})
        run_id = new_run_id or str(run.get("run_id") or "")
        if not run_id:
            raise ValueError("snapshot has no run_id")
        now = self._now()
        self._conn.execute(
            self._dialect.upsert_runs(),
            (
                run_id,
                str(run.get("workflow", "imported")),
                run.get("target"),
                run.get("workspace"),
                str(run.get("status", "completed")),
                str(run.get("created_at") or now),
                now,
            ),
        )
        for step in payload.get("steps") or []:
            if not isinstance(step, dict):
                continue
            self._conn.execute(
                self._q(
                    "INSERT INTO steps "
                    "(run_id, step_id, status, exit_code, duration_ms, evidence_path, "
                    "error, output, created_at) VALUES (?,?,?,?,?,?,?,?,?)"
                ),
                (
                    run_id,
                    str(step.get("step_id", "")),
                    str(step.get("status", "")),
                    step.get("exit_code"),
                    step.get("duration_ms"),
                    step.get("evidence_path"),
                    step.get("error"),
                    (str(step.get("output") or ""))[:OUTPUT_PREVIEW_LIMIT],
                    str(step.get("created_at") or now),
                ),
            )
        self._conn.commit()
        findings = payload.get("findings") or []
        if isinstance(findings, list) and findings:
            self.record_findings(run_id, findings)
        self.audit("snapshot_imported", {"run_id": run_id})
        return run_id

    def audit(self, event: str, data: dict) -> None:
        record = {"ts": self._now(), "event": event, **data}
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str) + "\n")

    def close(self) -> None:
        self._conn.close()


def open_store(settings) -> Store:
    """Construct a :class:`Store` from settings, honoring ``database_url`` (PG)."""

    return Store(
        settings.db_path,
        settings.evidence_dir,
        settings.audit_path,
        database_url=getattr(settings, "database_url", ""),
    )
