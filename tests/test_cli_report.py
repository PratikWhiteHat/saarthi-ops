"""CLI tests for `saarthi report` and `saarthi knowledge`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from saarthi_ai import cli
from saarthi_ai.exploit_confirmation.models import Severity
from saarthi_ai.knowledge.models import (
    BibleCatalog,
    BibleEntry,
    CoverageResult,
    CoverageStatus,
    EntryCoverage,
)
from saarthi_ai.persistence import bible_coverage_workflow, reporting_workflow
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import (
    EvidenceCreate,
    EvidenceType,
    ExecutionCreate,
)
from saarthi_ai.reporting import builder as report_builder

runner = CliRunner()
ORCHESTRATION_ID = "orchestration-cli-report"


def _catalog() -> BibleCatalog:
    return BibleCatalog(
        entries=[
            BibleEntry.build(
                number=1,
                title="Cross-Site Scripting (XSS)",
                rating="High",
                description="Reflected XSS.",
                security_risk="Session theft.",
                recommendation="Encode output.",
            )
        ]
    )


def _seed_db(database: SaarthiDatabase, tmp_path: Path) -> None:
    parent = database.create_execution(
        ExecutionCreate(
            assessment_name="CLI report",
            asset_types=["web"],
            targets=["https://target.test/"],
            authorization_confirmed=True,
            metadata={
                "orchestration_id": ORCHESTRATION_ID,
                "execution_role": "orchestration_parent",
                "target_domain": "target.test",
            },
        )
    )
    coverage = CoverageResult(
        target="https://target.test",
        catalog_size=1,
        coverage=[
            EntryCoverage(
                entry_id="cross-site-scripting-xss",
                title="Cross-Site Scripting (XSS)",
                severity=Severity.HIGH,
                status=CoverageStatus.CONFIRMED,
                source="ai",
            )
        ],
    )
    body = json.dumps(coverage.as_dict(), indent=2).encode("utf-8")
    path = tmp_path / "cov.json"
    path.write_bytes(body)
    database.add_evidence(
        parent.execution_id,
        EvidenceCreate(
            evidence_type=EvidenceType.BIBLE_COVERAGE_RESULT,
            source="bible-coverage",
            path=str(path),
            sha256="0" * 64,
            size_bytes=len(body),
            content_type="application/json",
        ),
    )


def test_knowledge_status_runs() -> None:
    result = runner.invoke(cli.app, ["knowledge", "status"])
    assert result.exit_code == 0
    assert "Knowledge pack" in result.stdout


def test_report_without_runs_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = SaarthiDatabase(tmp_path / "empty.db")
    database.initialize()
    monkeypatch.setattr(cli, "get_database", lambda: database)

    result = runner.invoke(cli.app, ["report"])
    assert result.exit_code == 1
    assert "No orchestration run" in result.stdout


def test_report_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = SaarthiDatabase(tmp_path / "run.db")
    database.initialize()
    _seed_db(database, tmp_path)

    monkeypatch.setattr(cli, "get_database", lambda: database)
    monkeypatch.setattr(bible_coverage_workflow, "load_bible_catalog", _catalog)
    monkeypatch.setattr(report_builder, "load_bible_catalog", _catalog)
    monkeypatch.setattr(reporting_workflow, "report_template_path", lambda: None)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        cli.app, ["report", "--no-ai", "--org", "Demo Corp"]
    )
    assert result.exit_code == 0, result.stdout
    assert "Report complete." in result.stdout
    assert "DOCX" in result.stdout

    reports = list((tmp_path / "evidence").rglob("assessment-report-*.docx"))
    assert reports, "expected a .docx report to be written"
    jsons = list((tmp_path / "evidence").rglob("assessment-report-*.json"))
    assert jsons
