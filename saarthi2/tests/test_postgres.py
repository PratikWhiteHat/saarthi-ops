"""SQL dialect selection + translation (SQLite default, PostgreSQL optional).

The live PostgreSQL path needs a running server + psycopg, so it is not
exercised here; these tests pin the pure dialect logic that drives it.
"""

from __future__ import annotations

from saarthi2.state import dialect_for


def test_dialect_selection() -> None:
    assert dialect_for("").name == "sqlite"
    assert dialect_for("sqlite:///x").name == "sqlite"
    assert dialect_for("postgres://u@h/db").name == "postgres"
    assert dialect_for("postgresql://u@h/db").name == "postgres"


def test_placeholder_translation() -> None:
    sqlite = dialect_for("")
    pg = dialect_for("postgresql://x")
    sql = "SELECT * FROM runs WHERE run_id = ? AND status = ?"
    assert sqlite.q(sql) == sql  # unchanged for sqlite
    assert pg.q(sql) == "SELECT * FROM runs WHERE run_id = %s AND status = %s"


def test_upsert_sql_per_dialect() -> None:
    sqlite = dialect_for("")
    pg = dialect_for("postgresql://x")

    sqlite_sql = sqlite.upsert_runs()
    assert sqlite_sql.startswith("INSERT OR REPLACE INTO runs")
    assert "?" in sqlite_sql and "%s" not in sqlite_sql

    pg_sql = pg.upsert_runs()
    assert pg_sql.startswith("INSERT INTO runs")
    assert "ON CONFLICT (run_id) DO UPDATE" in pg_sql
    assert "%s" in pg_sql and "?" not in pg_sql
