"""SQLite-backed, local-only NVD and CISA KEV catalog."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from saarthi_ai.cve.models import CpeMatch, CveRecord
from saarthi_ai.cve.parser import CveFeedError, parse_kev_document, parse_nvd_document


def default_catalog_path() -> Path:
    return Path.home() / ".saarthi" / "cve.db"


class CveCatalog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_catalog_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS cves (
                    cve_id TEXT PRIMARY KEY, description TEXT NOT NULL,
                    published TEXT, modified TEXT, cvss_score REAL,
                    cvss_severity TEXT, cvss_version TEXT,
                    exploit_reference INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS cpe_matches (
                    cve_id TEXT NOT NULL, criteria TEXT NOT NULL,
                    vulnerable INTEGER NOT NULL, version_start_including TEXT,
                    version_start_excluding TEXT, version_end_including TEXT,
                    version_end_excluding TEXT, complex_configuration INTEGER NOT NULL,
                    part TEXT NOT NULL, vendor TEXT NOT NULL, product TEXT NOT NULL,
                    FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS cpe_lookup
                    ON cpe_matches(part, vendor, product);
                CREATE TABLE IF NOT EXISTS kev (
                    cve_id TEXT PRIMARY KEY, date_added TEXT, due_date TEXT,
                    required_action TEXT, ransomware_use TEXT, vendor TEXT,
                    product TEXT, name TEXT
                );
                CREATE TABLE IF NOT EXISTS feed_state (
                    feed TEXT PRIMARY KEY, imported_at TEXT NOT NULL,
                    document_sha256 TEXT NOT NULL, records INTEGER NOT NULL
                );
                """
            )

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @staticmethod
    def _hash(document: object) -> str:
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()

    def import_nvd(self, document: object, *, feed: str = "nvd") -> int:
        entries = parse_nvd_document(document)
        if not entries:
            raise CveFeedError("NVD document has no valid CVEs; catalog left unchanged.")
        with self._connect() as db:
            for record, matches in entries:
                db.execute(
                    """INSERT INTO cves VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                    description=excluded.description, published=excluded.published,
                    modified=excluded.modified, cvss_score=excluded.cvss_score,
                    cvss_severity=excluded.cvss_severity,
                    cvss_version=excluded.cvss_version,
                    exploit_reference=excluded.exploit_reference""",
                    (
                        record.cve_id, record.description, record.published, record.modified,
                        record.cvss_score, record.cvss_severity, record.cvss_version,
                        int(record.exploit_reference),
                    ),
                )
                db.execute("DELETE FROM cpe_matches WHERE cve_id=?", (record.cve_id,))
                for match in matches:
                    parts = match.criteria.split(":")
                    if len(parts) < 6:
                        continue
                    db.execute(
                        """INSERT INTO cpe_matches VALUES
                        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            match.cve_id, match.criteria, int(match.vulnerable),
                            match.version_start_including, match.version_start_excluding,
                            match.version_end_including, match.version_end_excluding,
                            int(match.complex_configuration), parts[2], parts[3], parts[4],
                        ),
                    )
            db.execute(
                "INSERT OR REPLACE INTO feed_state VALUES (?, ?, ?, ?)",
                (feed, self._now(), self._hash(document), len(entries)),
            )
        return len(entries)

    def import_kev(self, document: object) -> int:
        entries = parse_kev_document(document)
        if not entries:
            raise CveFeedError("CISA KEV document has no valid entries; catalog left unchanged.")
        with self._connect() as db:
            db.execute("DELETE FROM kev")
            db.executemany(
                """INSERT INTO kev VALUES
                (:cve_id, :date_added, :due_date, :required_action,
                 :ransomware_use, :vendor, :product, :name)""",
                entries,
            )
            db.execute(
                "INSERT OR REPLACE INTO feed_state VALUES (?, ?, ?, ?)",
                ("kev", self._now(), self._hash(document), len(entries)),
            )
        return len(entries)

    def get_record(self, cve_id: str) -> CveRecord | None:
        with self._connect() as db:
            row = db.execute(
                """SELECT c.*, k.date_added, k.due_date, k.required_action,
                k.ransomware_use FROM cves c LEFT JOIN kev k USING(cve_id)
                WHERE c.cve_id=?""",
                (cve_id,),
            ).fetchone()
        if row is None:
            return None
        return CveRecord(
            cve_id=row["cve_id"], description=row["description"],
            published=row["published"], modified=row["modified"],
            cvss_score=row["cvss_score"], cvss_severity=row["cvss_severity"],
            cvss_version=row["cvss_version"],
            exploited_in_wild=row["date_added"] is not None,
            kev_date_added=row["date_added"], kev_due_date=row["due_date"],
            kev_required_action=row["required_action"],
            ransomware_use=row["ransomware_use"],
            exploit_reference=bool(row["exploit_reference"]),
        )

    def list_matches(self, part: str, vendor: str, product: str) -> list[CpeMatch]:
        with self._connect() as db:
            rows = db.execute(
                """SELECT * FROM cpe_matches WHERE part IN (?, '*')
                AND vendor IN (?, '*') AND product IN (?, '*') AND vulnerable=1""",
                (part, vendor, product),
            ).fetchall()
        return [
            CpeMatch(
                cve_id=row["cve_id"], criteria=row["criteria"],
                vulnerable=bool(row["vulnerable"]),
                version_start_including=row["version_start_including"],
                version_start_excluding=row["version_start_excluding"],
                version_end_including=row["version_end_including"],
                version_end_excluding=row["version_end_excluding"],
                complex_configuration=bool(row["complex_configuration"]),
            )
            for row in rows
        ]

    def stats(self) -> dict[str, object]:
        with self._connect() as db:
            counts = {
                table: db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("cves", "cpe_matches", "kev")
            }
            feeds = [dict(row) for row in db.execute("SELECT * FROM feed_state ORDER BY feed")]
        return {"path": str(self.path), "counts": counts, "feeds": feeds}
