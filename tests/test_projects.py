from __future__ import annotations

from pathlib import Path

import pytest

from saarthi_ai.persistence.models import ExecutionCreate
from saarthi_ai.persistence.projects import (
    ProjectAlreadyExistsError,
    ProjectCreate,
    ProjectNotFoundError,
    ProjectRepository,
)


@pytest.fixture
def repository(tmp_path: Path) -> ProjectRepository:
    """Create an isolated project repository."""

    project_repository = ProjectRepository(tmp_path / "projects.db")
    project_repository.initialize()
    return project_repository


def test_create_and_get_project(
    repository: ProjectRepository,
) -> None:
    """Projects should be persisted and retrievable."""

    created = repository.create_project(
        ProjectCreate(
            name="Acme Web VAPT",
            description="Authorized staging assessment.",
            owner="Security Team",
        )
    )

    retrieved = repository.get_project(created.slug)

    assert retrieved.project_id == created.project_id
    assert retrieved.slug == "acme-web-vapt"
    assert retrieved.owner == "Security Team"


def test_duplicate_project_is_rejected(
    repository: ProjectRepository,
) -> None:
    """Duplicate project slugs should be rejected."""

    repository.create_project(ProjectCreate(name="Acme Web VAPT"))

    with pytest.raises(ProjectAlreadyExistsError):
        repository.create_project(ProjectCreate(name="Acme Web VAPT"))


def test_missing_project_is_rejected(
    repository: ProjectRepository,
) -> None:
    """Unknown projects should raise a clear error."""

    with pytest.raises(ProjectNotFoundError):
        repository.get_project("missing-project")


def test_list_projects(
    repository: ProjectRepository,
) -> None:
    """Project history should be listed."""

    repository.create_project(ProjectCreate(name="First Project"))
    repository.create_project(ProjectCreate(name="Second Project"))

    projects = repository.list_projects()

    assert len(projects) == 2


def test_project_execution_association(
    repository: ProjectRepository,
) -> None:
    """Executions should be associated through project metadata."""

    project = repository.create_project(ProjectCreate(name="Acme Web VAPT"))

    repository.database.create_execution(
        ExecutionCreate(
            assessment_name="Acme Assessment",
            asset_types=["web"],
            targets=["https://example.com/"],
            authorization_confirmed=True,
            metadata={
                "project_id": project.project_id,
                "project_slug": project.slug,
            },
        )
    )

    executions = repository.list_project_executions(project.slug)

    assert len(executions) == 1
    assert executions[0].metadata["project_id"] == project.project_id
