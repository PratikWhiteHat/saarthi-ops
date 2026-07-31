from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from saarthi_ai import cli
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.projects import ProjectRepository

runner = CliRunner()


def configure_test_storage(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Redirect CLI persistence into an isolated database."""

    database_path = tmp_path / "cli.db"

    def database_factory() -> SaarthiDatabase:
        database = SaarthiDatabase(database_path)
        database.initialize()
        return database

    def project_factory() -> ProjectRepository:
        repository = ProjectRepository(database_path)
        repository.initialize()
        return repository

    monkeypatch.setattr(
        cli,
        "get_database",
        database_factory,
    )
    monkeypatch.setattr(
        cli,
        "get_project_repository",
        project_factory,
    )


def test_project_create_and_list(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """The CLI should create and list projects."""

    configure_test_storage(monkeypatch, tmp_path)

    create_result = runner.invoke(
        cli.app,
        [
            "project",
            "create",
            "Acme Web VAPT",
            "--owner",
            "Security Team",
        ],
    )

    assert create_result.exit_code == 0
    assert "Project created" in create_result.stdout
    assert "acme-web-vapt" in create_result.stdout

    list_result = runner.invoke(
        cli.app,
        ["project", "list"],
    )

    assert list_result.exit_code == 0
    assert "Acme Web VAPT" in list_result.stdout


def test_assess_requires_authorization(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Assessment creation must require authorization."""

    configure_test_storage(monkeypatch, tmp_path)

    result = runner.invoke(
        cli.app,
        [
            "assess",
            "--url",
            "https://example.com",
        ],
    )

    assert result.exit_code == 1
    assert "Authorization required" in result.stdout


def test_create_authorized_assessment(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """The CLI should create a planned execution."""

    configure_test_storage(monkeypatch, tmp_path)

    project_result = runner.invoke(
        cli.app,
        [
            "project",
            "create",
            "Acme Web VAPT",
        ],
    )

    assert project_result.exit_code == 0

    result = runner.invoke(
        cli.app,
        [
            "assess",
            "--url",
            "https://example.com",
            "--project",
            "acme-web-vapt",
            "--authorized",
            "--active",
        ],
    )

    assert result.exit_code == 0
    assert "Assessment created" in result.stdout
    assert "State: planned" in result.stdout


def test_run_http_requires_explicit_approval(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """HTTP collection must require explicit CLI approval."""

    configure_test_storage(monkeypatch, tmp_path)

    database = cli.get_database()
    execution = database.create_execution(
        cli.ExecutionCreate(
            assessment_name="Authorized HTTP Test",
            asset_types=["web"],
            targets=["https://example.com/"],
            authorization_confirmed=True,
        )
    )

    result = runner.invoke(
        cli.app,
        [
            "execution",
            "run-http",
            execution.execution_id,
        ],
    )

    assert result.exit_code == 1
    assert "Approval required" in result.stdout


def test_run_http_command(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Approved HTTP collection should display tracked results."""

    from types import SimpleNamespace

    configure_test_storage(monkeypatch, tmp_path)

    database = cli.get_database()
    execution = database.create_execution(
        cli.ExecutionCreate(
            assessment_name="Authorized HTTP Test",
            asset_types=["web"],
            targets=["https://example.com/"],
            authorization_confirmed=True,
            metadata={
                "rate_limit_per_second": 2,
            },
        )
    )

    async def fake_tracked_collection(
        database,
        execution_id,
        request,
        *,
        actor,
    ):
        assert request.target == "https://example.com/"
        assert actor == "cli-http-collector"

        return SimpleNamespace(
            execution=SimpleNamespace(
                state=cli.ExecutionState.COMPLETED,
            ),
            collection=SimpleNamespace(
                status_code=200,
                final_url="https://example.com/",
                body_bytes_captured=5,
                body_truncated=False,
            ),
            evidence=SimpleNamespace(
                evidence_id="evidence-test",
                path="evidence/http/test.json",
            ),
        )

    monkeypatch.setattr(
        cli,
        "run_tracked_http_collection",
        fake_tracked_collection,
    )

    result = runner.invoke(
        cli.app,
        [
            "execution",
            "run-http",
            execution.execution_id,
            "--approved",
        ],
    )

    assert result.exit_code == 0
    assert "HTTP collection completed" in result.stdout
    assert "Execution state: completed" in result.stdout
    assert "Evidence ID: evidence-test" in result.stdout
