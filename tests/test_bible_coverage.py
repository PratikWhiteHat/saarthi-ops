"""Phase 4E bible-coverage logic + tracked-workflow tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from saarthi_ai.knowledge.coverage import (
    EvidenceCorpus,
    apply_ai_classifications,
    classify_deterministic,
    parse_ai_classifications,
)
from saarthi_ai.knowledge.models import BibleCatalog, BibleEntry, CoverageStatus
from saarthi_ai.persistence import bible_coverage_workflow
from saarthi_ai.persistence.bible_coverage_workflow import run_tracked_bible_coverage
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceType,
    ExecutionCreate,
)

ORCHESTRATION_ID = "orchestration-4e-test"


def _catalog() -> BibleCatalog:
    return BibleCatalog(
        version="1",
        source="unit",
        entries=[
            BibleEntry.build(number=1, title="Cookie Flag HTTPOnly Not Set", rating="Low"),
            BibleEntry.build(number=2, title="Cross-Site Scripting (XSS)", rating="High"),
            BibleEntry.build(number=3, title="SQL Injection", rating="Critical"),
        ],
    )


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "4e.db")
    repository.initialize()
    return repository


def _parent(database: SaarthiDatabase) -> str:
    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Phase 4E",
            asset_types=["web"],
            targets=["https://target.test/"],
            authorization_confirmed=True,
            active_testing_allowed=True,
            metadata={
                "orchestration_id": ORCHESTRATION_ID,
                "execution_role": "orchestration_parent",
                "phase_code": "4A",
            },
        )
    )
    return execution.execution_id


def test_classify_deterministic_matches_keywords() -> None:
    corpus = EvidenceCorpus(
        target="https://target.test",
        finding_lines=["[4A] Cookie flag HTTPOnly not set on session cookie"],
    )
    result = classify_deterministic(_catalog(), corpus)
    assert result.catalog_size == 3
    assert result.ai_used is False
    by_id = {c.entry_id: c for c in result.coverage}
    assert by_id["cookie-flag-httponly-not-set"].status is CoverageStatus.LIKELY
    assert by_id["sql-injection"].status is CoverageStatus.NOT_OBSERVED


def test_parse_ai_classifications_filters_invalid() -> None:
    valid = {"cookie-flag-httponly-not-set", "sql-injection"}
    text = (
        "cookie-flag-httponly-not-set | confirmed | HTTPOnly missing\n"
        "sql-injection | manual | needs auth\n"
        "not-a-real-id | confirmed | ignore me\n"
        "garbage line without pipe\n"
    )
    verdicts = parse_ai_classifications(text, valid)
    assert verdicts["cookie-flag-httponly-not-set"][0] is CoverageStatus.CONFIRMED
    assert verdicts["sql-injection"][0] is CoverageStatus.MANUAL_REVIEW
    assert "not-a-real-id" not in verdicts


def test_apply_ai_classifications_overlay() -> None:
    corpus = EvidenceCorpus(finding_lines=["cookie httponly flag"])
    det = classify_deterministic(_catalog(), corpus)
    merged = apply_ai_classifications(
        det,
        {"sql-injection": (CoverageStatus.CONFIRMED, "sqlmap confirmed")},
    )
    assert merged.ai_used is True
    by_id = {c.entry_id: c for c in merged.coverage}
    assert by_id["sql-injection"].status is CoverageStatus.CONFIRMED
    assert by_id["sql-injection"].source == "ai"


def test_coverage_result_actionable_and_counts() -> None:
    corpus = EvidenceCorpus(finding_lines=["cookie httponly flag"])
    result = apply_ai_classifications(
        classify_deterministic(_catalog(), corpus),
        {"sql-injection": (CoverageStatus.CONFIRMED, "x")},
    )
    statuses = {c.status for c in result.actionable}
    assert CoverageStatus.NOT_OBSERVED not in statuses
    assert result.status_counts["confirmed"] == 1


def test_run_tracked_bible_coverage_persists(
    database: SaarthiDatabase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execution_id = _parent(database)
    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.FINDING_CREATED,
        actor="test",
        message="Cookie flag HTTPOnly not set on session cookie",
        details={"severity": "low"},
    )
    monkeypatch.setattr(
        bible_coverage_workflow, "load_bible_catalog", _catalog
    )

    tracked = run_tracked_bible_coverage(
        database,
        execution_id,
        orchestration_id=ORCHESTRATION_ID,
        evidence_root=tmp_path / "cov",
        ai_verdicts={"sql-injection": (CoverageStatus.CONFIRMED, "confirmed")},
    )

    assert tracked.catalog_available is True
    assert tracked.evidence is not None
    assert tracked.evidence.evidence_type is EvidenceType.BIBLE_COVERAGE_RESULT
    assert Path(tracked.evidence_path).exists()
    assert tracked.evidence.metadata["confirmed"] == 1
    assert tracked.evidence.metadata["ai_used"] is True

    events = database.list_audit_events(execution_id)
    assert any(e.event_type is AuditEventType.TOOL_STARTED for e in events)
    assert any(e.event_type is AuditEventType.TOOL_COMPLETED for e in events)
    assert any(
        e.event_type is AuditEventType.FINDING_CREATED and "[4E]" in e.message
        for e in events
    )


def test_run_tracked_bible_coverage_no_catalog(
    database: SaarthiDatabase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execution_id = _parent(database)

    def _raise() -> BibleCatalog:
        from saarthi_ai.knowledge.loader import BibleNotAvailableError

        raise BibleNotAvailableError("no pack")

    monkeypatch.setattr(bible_coverage_workflow, "load_bible_catalog", _raise)

    tracked = run_tracked_bible_coverage(
        database,
        execution_id,
        orchestration_id=ORCHESTRATION_ID,
        evidence_root=tmp_path / "cov",
    )
    assert tracked.catalog_available is False
    assert tracked.evidence is None
