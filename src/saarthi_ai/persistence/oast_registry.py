"""Persistent hash-only OAST correlation registry."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path

from saarthi_ai.oast.models import (
    OastCorrelation,
    OastCorrelationStatus,
    OastProtocol,
)
from saarthi_ai.persistence.database import (
    DEFAULT_DATABASE_PATH,
    SaarthiDatabase,
)


class OastRegistryError(RuntimeError):
    """Base error raised by the persistent OAST registry."""


class OastCorrelationAlreadyExistsError(OastRegistryError):
    """Raised when a token ID or token hash is already registered."""


class PersistentOastCorrelationRegistry:
    """Store OAST correlations without ever storing raw token values."""

    def __init__(
        self,
        database: SaarthiDatabase | None = None,
        *,
        database_path: Path | str = DEFAULT_DATABASE_PATH,
    ) -> None:
        self.database = database or SaarthiDatabase(database_path)

    def initialize(self) -> None:
        """Create the hash-only OAST correlation table and indexes."""

        self.database.initialize()

        with self.database.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS oast_correlations (
                    token_id TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    execution_id TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (execution_id)
                        REFERENCES executions(execution_id)
                        ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS
                    idx_oast_correlations_execution_id
                    ON oast_correlations(execution_id);

                CREATE INDEX IF NOT EXISTS
                    idx_oast_correlations_status
                    ON oast_correlations(status);

                CREATE INDEX IF NOT EXISTS
                    idx_oast_correlations_expires_at
                    ON oast_correlations(expires_at);
                """
            )

    def register(
        self,
        correlation: OastCorrelation,
    ) -> OastCorrelation:
        """Register one correlation using only its token ID and hash."""

        self._validate_correlation(correlation)
        self.database.get_execution(correlation.execution_id)

        try:
            with self.database.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO oast_correlations (
                        token_id,
                        token_hash,
                        execution_id,
                        protocol,
                        status,
                        created_at,
                        expires_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        correlation.token_id,
                        correlation.token_hash,
                        correlation.execution_id,
                        correlation.protocol.value,
                        correlation.status.value,
                        correlation.created_at.isoformat(),
                        correlation.expires_at.isoformat(),
                        correlation.created_at.isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise OastCorrelationAlreadyExistsError(
                "OAST correlation token ID or token hash is already registered."
            ) from exc

        return correlation

    def get_by_token_id(
        self,
        token_id: str,
    ) -> OastCorrelation | None:
        """Return one registered correlation by token ID."""

        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM oast_correlations
                WHERE token_id = ?
                """,
                (token_id,),
            ).fetchone()

        if row is None:
            return None

        return self._from_row(row)

    def get_by_token_hash(
        self,
        token_hash: str,
    ) -> OastCorrelation | None:
        """Return one registered correlation by token hash."""

        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM oast_correlations
                WHERE token_hash = ?
                """,
                (token_hash,),
            ).fetchone()

        if row is None:
            return None

        return self._from_row(row)

    def list_for_execution(
        self,
        execution_id: str,
    ) -> tuple[OastCorrelation, ...]:
        """Return correlations associated with one execution."""

        self.database.get_execution(execution_id)

        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM oast_correlations
                WHERE execution_id = ?
                ORDER BY created_at ASC
                """,
                (execution_id,),
            ).fetchall()

        return tuple(self._from_row(row) for row in rows)

    def update_status(
        self,
        token_id: str,
        status: OastCorrelationStatus,
        *,
        updated_at: datetime,
    ) -> OastCorrelation | None:
        """Update a correlation status without altering token material."""

        if updated_at.tzinfo is None:
            raise ValueError("Status update time must be timezone-aware.")

        with self.database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE oast_correlations
                SET status = ?,
                    updated_at = ?
                WHERE token_id = ?
                """,
                (
                    status.value,
                    updated_at.isoformat(),
                    token_id,
                ),
            )

        if cursor.rowcount == 0:
            return None

        return self.get_by_token_id(token_id)

    @staticmethod
    def _validate_correlation(
        correlation: OastCorrelation,
    ) -> None:
        if not correlation.token_id.strip():
            raise ValueError("Correlation token ID is required.")

        if len(correlation.token_hash) != 64:
            raise ValueError(
                "Correlation token hash must be a SHA-256 hexadecimal value."
            )

        try:
            int(correlation.token_hash, 16)
        except ValueError as exc:
            raise ValueError(
                "Correlation token hash must be hexadecimal."
            ) from exc

        if correlation.created_at.tzinfo is None:
            raise ValueError(
                "Correlation creation time must be timezone-aware."
            )

        if correlation.expires_at.tzinfo is None:
            raise ValueError(
                "Correlation expiry time must be timezone-aware."
            )

        if correlation.expires_at <= correlation.created_at:
            raise ValueError(
                "Correlation expiry must be after creation."
            )

    @staticmethod
    def _from_row(
        row: sqlite3.Row,
    ) -> OastCorrelation:
        return OastCorrelation(
            token_id=str(row["token_id"]),
            token_hash=str(row["token_hash"]),
            execution_id=str(row["execution_id"]),
            protocol=OastProtocol(str(row["protocol"])),
            created_at=datetime.fromisoformat(str(row["created_at"])),
            expires_at=datetime.fromisoformat(str(row["expires_at"])),
            status=OastCorrelationStatus(str(row["status"])),
        )
