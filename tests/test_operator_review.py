"""Human review records stay separate from AI evidence and target execution."""

from __future__ import annotations

from pathlib import Path

import pytest
from textual.widgets import Input

from saarthi_ai.analysis.operator_review import (
    OperatorVerdict,
    latest_operator_reviews,
    latest_quality_analysis,
    load_quality_analysis,
    operator_review_counts,
    record_operator_review,
)
from saarthi_ai.analysis.quality import (
    AnalystVerdict,
    FinalDisposition,
    QualityAnalysisResult,
    QualityFinding,
    ReviewDisposition,
    Severity,
    SourceCitation,
    persist_quality_analysis,
)
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import AuditEventType, ExecutionCreate
from saarthi_ai.tui.app import FindingReviewScreen, SaarthiDashboard


def _saved_analysis(tmp_path: Path):
    database = SaarthiDatabase(tmp_path / "saarthi.db")
    database.initialize()
    parent = database.create_execution(
        ExecutionCreate(
            assessment_name="Review test",
            asset_types=["url"],
            targets=["https://example.test/"],
            authorization_confirmed=True,
        )
    )
    result = QualityAnalysisResult(
        orchestration_id="orchestration-review-test",
        target="https://example.test/",
        generated_at="2026-09-24T00:00:00+00:00",
        source_reference_count=1,
        sources=(SourceCitation(
            reference_id="evidence-one",
            phase_code="4A",
            source_type="http_metadata",
            summary="Observed response header.",
        ),),
        facts=(),
        findings=(QualityFinding(
            finding_id="C1",
            title="Header needs review",
            severity=Severity.LOW,
            analyst_verdict=AnalystVerdict.UNCONFIRMED,
            review_disposition=ReviewDisposition.PARTIAL,
            final_disposition=FinalDisposition.NEEDS_CONFIRMATION,
            confidence=50,
            statement="A response header may need attention.",
            evidence_refs=("evidence-one",),
            missing_evidence=("Check the configuration.",),
        ),),
    )
    evidence = persist_quality_analysis(
        database,
        parent.execution_id,
        result,
        evidence_root=tmp_path / "ai-quality",
    )
    return database, evidence


def test_reviews_are_append_only_and_do_not_change_ai_analysis(tmp_path):
    database, evidence = _saved_analysis(tmp_path)
    before = Path(evidence.path).read_bytes()

    record_operator_review(
        database, evidence, "C1", OperatorVerdict.NEEDS_EVIDENCE,
        "The configuration is not available yet.",
    )
    record_operator_review(
        database, evidence, "C1", OperatorVerdict.FALSE_POSITIVE,
        "The setting was verified separately.",
    )

    reviews = latest_operator_reviews(database, evidence.execution_id, evidence.evidence_id)
    assert reviews["C1"].verdict is OperatorVerdict.FALSE_POSITIVE
    assert operator_review_counts(database) == {
        OperatorVerdict.CONFIRMED: 0,
        OperatorVerdict.FALSE_POSITIVE: 1,
        OperatorVerdict.NEEDS_EVIDENCE: 0,
    }
    assert Path(evidence.path).read_bytes() == before
    assert (
        load_quality_analysis(evidence).findings[0].final_disposition
        is FinalDisposition.NEEDS_CONFIRMATION
    )
    assert len([
        event for event in database.list_audit_events(evidence.execution_id)
        if event.event_type is AuditEventType.FINDING_REVIEWED
    ]) == 2


def test_review_requires_matching_finding_reason_and_digest(tmp_path):
    database, evidence = _saved_analysis(tmp_path)
    with pytest.raises(ValueError, match="absent"):
        record_operator_review(
            database, evidence, "invented", OperatorVerdict.CONFIRMED, "Checked."
        )
    with pytest.raises(ValueError, match="reason"):
        record_operator_review(database, evidence, "C1", OperatorVerdict.CONFIRMED, " ")
    Path(evidence.path).write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="digest"):
        record_operator_review(database, evidence, "C1", OperatorVerdict.CONFIRMED, "Checked.")
    assert latest_quality_analysis(database) is None


def test_interim_findings_are_not_offered_for_operator_verdict(tmp_path):
    database, evidence = _saved_analysis(tmp_path)
    result = load_quality_analysis(evidence).model_copy(
        update={"analysis_stage": "interim"}
    )
    interim = persist_quality_analysis(
        database,
        evidence.execution_id,
        result,
        evidence_root=tmp_path / "ai-quality",
    )
    assert interim.metadata["analysis_stage"] == "interim"
    assert interim.step_id == "live-ai-quality"
    # The older final result is still the most recent reviewable result.
    assert latest_quality_analysis(database)[0].evidence_id == evidence.evidence_id


@pytest.mark.asyncio
async def test_tui_review_screen_saves_operator_verdict(tmp_path):
    database, evidence = _saved_analysis(tmp_path)
    app = SaarthiDashboard(database_path=database.database_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("f")
        await pilot.pause()
        assert isinstance(app.screen, FindingReviewScreen)
        app.screen.query_one("#finding-review-note", Input).value = "Reviewed the cited header."
        await pilot.click("#review-confirm")
        await pilot.pause()

        reviews = latest_operator_reviews(database, evidence.execution_id, evidence.evidence_id)
        assert reviews["C1"].verdict is OperatorVerdict.CONFIRMED
        await pilot.press("escape")
        assert not isinstance(app.screen, FindingReviewScreen)
