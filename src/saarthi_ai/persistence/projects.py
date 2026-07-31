from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, Field

from saarthi_ai.persistence.database import (
    DEFAULT_DATABASE_PATH,
    SaarthiDatabase,
)
from saarthi_ai.persistence.models import utc_now


class ProjectError(RuntimeError):
    """Base error for assessment project operations."""


class ProjectNotFoundError(ProjectError):
    """Raised when a requested project does not exist."""


class ProjectAlreadyExistsError(ProjectError):
    """Raised when a project slug is already in use."""


class ProjectCreate(BaseModel):
    """Input used to create an assessment project."""

    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2_000)
    owner: str | None = Field(default=None, max_length=200)


class ProjectRecord(BaseModel):
    """Persistent pentest project record."""

    project_id: str
    slug: str
    name: str
    description: str | None
    owner: str | None
    metadata: dict[str, object]
    created_at: datetime
    updated_at: datetime


def slugify(value: str) -> str:
    """Convert a project name into a safe CLI slug."""

    slug = value.strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")

    if not slug:
        raise ProjectError("Project name must contain at least one letter or number.")

    return slug[:100]


class ProjectRepository:
    """SQLite repository for Saarthi assessment projects."""

    def __init__(
        self,
        database_path: Path | str = DEFAULT_DATABASE_PATH,
    ) -> None:
        self.database_path = Path(database_path)
        self.database = SaarthiDatabase(self.database_path)

    def initialize(self) -> None:
        """Create the project table and initialize execution storage."""

        self.database.initialize()

        with self.database.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    project_id TEXT PRIMARY KEY,
                    slug TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    description TEXT,
                    owner TEXT,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_projects_slug
                    ON projects(slug);

                CREATE INDEX IF NOT EXISTS idx_projects_created_at
                    ON projects(created_at);
                """
            )

    def create_project(
        self,
        request: ProjectCreate,
    ) -> ProjectRecord:
        """Create a persistent assessment project."""

        slug = slugify(request.name)
        timestamp = utc_now()

        record = ProjectRecord(
            project_id=f"project-{uuid4()}",
            slug=slug,
            name=request.name.strip(),
            description=request.description,
            owner=request.owner,
            metadata={},
            created_at=timestamp,
            updated_at=timestamp,
        )

        try:
            with self.database.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO projects (
                        project_id,
                        slug,
                        name,
                        description,
                        owner,
                        metadata_json,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.project_id,
                        record.slug,
                        record.name,
                        record.description,
                        record.owner,
                        json.dumps(record.metadata),
                        record.created_at.isoformat(),
                        record.updated_at.isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ProjectAlreadyExistsError(f"Project '{slug}' already exists.") from exc

        return record

    def get_project(self, slug_or_id: str) -> ProjectRecord:
        """Retrieve a project by slug or identifier."""

        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM projects
                WHERE slug = ? OR project_id = ?
                """,
                (slug_or_id, slug_or_id),
            ).fetchone()

        if row is None:
            raise ProjectNotFoundError(f"Project '{slug_or_id}' was not found.")

        return self._project_from_row(row)

    def list_projects(self, limit: int = 100) -> list[ProjectRecord]:
        """Return recent assessment projects."""

        if limit < 1 or limit > 1_000:
            raise ProjectError("Project list limit must be between 1 and 1000.")

        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM projects
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [self._project_from_row(row) for row in rows]

    def list_project_executions(
        self,
        slug_or_id: str,
    ) -> list[object]:
        """Return executions associated with a project."""

        project = self.get_project(slug_or_id)
        executions = self.database.list_executions(limit=1_000)

        return [
            execution
            for execution in executions
            if execution.metadata.get("project_id") == project.project_id
        ]

    @staticmethod
    def _project_from_row(
        row: sqlite3.Row,
    ) -> ProjectRecord:
        """Convert a SQLite project row into a model."""

        return ProjectRecord(
            project_id=row["project_id"],
            slug=row["slug"],
            name=row["name"],
            description=row["description"],
            owner=row["owner"],
            metadata=json.loads(row["metadata_json"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )
