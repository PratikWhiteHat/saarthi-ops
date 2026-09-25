"""Local run state: SQLite for runs/steps + a sha256 evidence store + audit log."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from saarthi2.engine.models import RunResult, StepResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    workflow TEXT NOT NULL,
    target TEXT,
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
    created_at TEXT NOT NULL
);
"""


class Store:
    """A small, local, append-only-ish persistence layer for a run."""

    def __init__(self, db_path: Path, evidence_dir: Path, audit_path: Path) -> None:
        self.db_path = Path(db_path)
        self.evidence_dir = Path(evidence_dir)
        self.audit_path = Path(audit_path)
        for directory in (self.db_path.parent, self.evidence_dir, self.audit_path.parent):
            directory.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()

    def create_run(self, run: RunResult) -> None:
        now = self._now()
        self._conn.execute(
            "INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?)",
            (run.run_id, run.workflow, run.target, run.status.value, now, now),
        )
        self._conn.commit()
        self.audit("run_created", {"run_id": run.run_id, "workflow": run.workflow})

    def update_run(self, run: RunResult) -> None:
        self._conn.execute(
            "UPDATE runs SET status=?, updated_at=? WHERE run_id=?",
            (run.status.value, self._now(), run.run_id),
        )
        self._conn.commit()
        self.audit("run_updated", {"run_id": run.run_id, "status": run.status.value})

    def record_step(self, run_id: str, step: StepResult) -> None:
        self._conn.execute(
            "INSERT INTO steps VALUES (?,?,?,?,?,?,?,?)",
            (
                run_id,
                step.step_id,
                step.status.value,
                step.exit_code,
                step.duration_ms,
                step.evidence_path,
                step.error,
                self._now(),
            ),
        )
        self._conn.commit()

    def save_evidence(self, run_id: str, name: str, content: bytes) -> tuple[str, str]:
        """Write bounded evidence to disk; return (path, sha256)."""

        digest = hashlib.sha256(content).hexdigest()
        run_dir = self.evidence_dir / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        path = run_dir / f"{name}-{digest[:12]}"
        path.write_bytes(content)
        return str(path), digest

    def audit(self, event: str, data: dict) -> None:
        record = {"ts": self._now(), "event": event, **data}
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str) + "\n")

    def close(self) -> None:
        self._conn.close()
