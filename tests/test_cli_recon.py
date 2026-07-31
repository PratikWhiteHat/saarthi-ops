from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from saarthi_ai import cli
from saarthi_ai.persistence.database import SaarthiDatabase

runner = CliRunner()


def configure_test_storage(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Redirect CLI persistence into an isolated database."""

    database_path = tmp_path / "cli-recon.db"

    def database_factory() -> SaarthiDatabase:
        database = SaarthiDatabase(database_path)
        database.initialize()
        return database

    monkeypatch.setattr(
        cli,
        "get_database",
        database_factory,
    )


def create_dns_execution() -> str:
    """Create an authorized execution for CLI DNS testing."""

    database = cli.get_database()

    execution = database.create_execution(
        cli.ExecutionCreate(
            assessment_name="Authorized DNS Test",
            asset_types=["web"],
            targets=["https://example.com"],
            authorization_confirmed=True,
            active_testing_allowed=True,
            intrusive_testing_allowed=False,
        )
    )

    return execution.execution_id


def test_recon_dns_requires_explicit_approval(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """DNS reconnaissance must require explicit CLI approval."""

    configure_test_storage(monkeypatch, tmp_path)
    execution_id = create_dns_execution()

    result = runner.invoke(
        cli.app,
        [
            "recon",
            "dns",
            "--execution",
            execution_id,
            "--domain",
            "example.com",
        ],
    )

    assert result.exit_code == 1
    assert "Approval required" in result.stdout


def test_recon_dns_command(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Approved DNS reconnaissance should display tracked results."""

    configure_test_storage(monkeypatch, tmp_path)
    execution_id = create_dns_execution()

    def fake_tracked_dns_collection(
        database,
        supplied_execution_id: str,
        domain: str,
    ):
        assert supplied_execution_id == execution_id
        assert domain == "example.com"

        return SimpleNamespace(
            execution=SimpleNamespace(
                state=cli.ExecutionState.COMPLETED,
            ),
            collection=SimpleNamespace(
                domain="example.com",
                nameserver="192.0.2.53",
                records={
                    "A": [
                        SimpleNamespace(
                            record_type="A",
                            value="192.0.2.10",
                            ttl=300,
                        )
                    ],
                    "AAAA": [],
                    "CNAME": [],
                    "MX": [],
                    "NS": [],
                    "TXT": [],
                },
            ),
            evidence=SimpleNamespace(
                evidence_id="evidence-dns-test",
                path="evidence/dns/test.json",
            ),
        )

    monkeypatch.setattr(
        cli,
        "run_tracked_dns_collection",
        fake_tracked_dns_collection,
    )

    result = runner.invoke(
        cli.app,
        [
            "recon",
            "dns",
            "--execution",
            execution_id,
            "--domain",
            "example.com",
            "--approved",
        ],
    )

    assert result.exit_code == 0
    assert "DNS collection completed" in result.stdout
    assert "Execution state: completed" in result.stdout
    assert "Domain: example.com" in result.stdout
    assert "Records captured: 1" in result.stdout
    assert "A: 1" in result.stdout
    assert "Evidence ID: evidence-dns-test" in result.stdout


def test_recon_dns_rejects_unknown_execution(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """DNS reconnaissance should report an unknown execution cleanly."""

    configure_test_storage(monkeypatch, tmp_path)

    result = runner.invoke(
        cli.app,
        [
            "recon",
            "dns",
            "--execution",
            "execution-does-not-exist",
            "--domain",
            "example.com",
            "--approved",
        ],
    )

    assert result.exit_code == 1
    assert "DNS collection failed" in result.stdout
