"""Tests for AI-assisted run analysis (digest + prompt + model call)."""

from __future__ import annotations

import pytest

from saarthi_ai.analysis import (
    AnalysisError,
    analyze_run,
    build_analysis_prompt,
    gather_run_digest,
)
from saarthi_ai.analysis.engine import ANALYST_SYSTEM_PROMPT
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import AuditEventType, ExecutionCreate


def _seed_run(tmp_path):
    database = SaarthiDatabase(tmp_path / "analysis.db")
    database.initialize()

    database.create_execution(
        ExecutionCreate(
            assessment_name="Analysis test",
            asset_types=["url"],
            targets=["https://app.example.com/item?id=1"],
            authorization_confirmed=True,
            active_testing_allowed=True,
            intrusive_testing_allowed=True,
            metadata={
                "execution_role": "orchestration_parent",
                "orchestration_id": "orchestration-analysis-1",
                "target_domain": "app.example.com",
            },
        )
    )
    child = database.create_execution(
        ExecutionCreate(
            assessment_name="Analysis test",
            asset_types=["url"],
            targets=["https://app.example.com/item?id=1"],
            authorization_confirmed=True,
            active_testing_allowed=True,
            intrusive_testing_allowed=True,
            metadata={
                "execution_role": "orchestration_child",
                "orchestration_id": "orchestration-analysis-1",
                "phase_code": "6C-sqlmap",
            },
        )
    )
    database.add_audit_event(
        child.execution_id,
        event_type=AuditEventType.FINDING_CREATED,
        actor="test",
        message="SQL injection confirmed on parameter id.",
        details={"parameter": "id", "technique": "time-based", "dbms": "MySQL"},
    )
    return database


def test_gather_digest_collects_findings_and_phases(tmp_path):
    database = _seed_run(tmp_path)

    digest = gather_run_digest(database)

    assert digest.orchestration_id == "orchestration-analysis-1"
    assert digest.target == "https://app.example.com/item?id=1"
    assert ("6C-sqlmap", digest.phases[0][1]) == digest.phases[0]
    assert any("SQL injection confirmed" in f for f in digest.findings)


def test_build_prompt_includes_target_and_findings(tmp_path):
    database = _seed_run(tmp_path)
    digest = gather_run_digest(database)

    prompt = build_analysis_prompt(digest)

    assert "https://app.example.com/item?id=1" in prompt
    assert "SQL injection confirmed" in prompt
    assert "Triage this evidence" in prompt


def test_gather_digest_empty_db_raises(tmp_path):
    database = SaarthiDatabase(tmp_path / "empty.db")
    database.initialize()

    with pytest.raises(AnalysisError):
        gather_run_digest(database)


@pytest.mark.asyncio
async def test_analyze_run_uses_analyst_prompt_and_longer_output(tmp_path):
    database = _seed_run(tmp_path)
    digest = gather_run_digest(database)

    captured = {}

    class FakeClient:
        async def chat(self, messages, *, system_prompt=None, num_predict=150):
            captured["system_prompt"] = system_prompt
            captured["num_predict"] = num_predict
            captured["user"] = messages[0].content
            return "AI triage: 1 High SQLi on id.", None

    content = await analyze_run(FakeClient(), digest)

    assert content == "AI triage: 1 High SQLi on id."
    assert captured["system_prompt"] == ANALYST_SYSTEM_PROMPT
    assert captured["num_predict"] > 150
    assert "SQL injection confirmed" in captured["user"]


def _child_execution(database):

    child = database.list_executions(limit=50)
    child = [
        e
        for e in child
        if (e.metadata or {}).get("execution_role") == "orchestration_child"
    ][0]
    return child


def test_gather_phase_digest_and_prompt(tmp_path):
    from saarthi_ai.analysis import build_phase_prompt, gather_phase_digest

    database = _seed_run(tmp_path)
    child = _child_execution(database)

    digest = gather_phase_digest(
        database, child, target="https://app.example.com/item?id=1"
    )

    assert digest.phase_code == "6C-sqlmap"
    assert any("SQL injection confirmed" in f for f in digest.findings)

    prompt = build_phase_prompt(digest)
    assert "6C-sqlmap" in prompt
    assert "SQL injection confirmed" in prompt
    assert "live suggestions" in prompt


@pytest.mark.asyncio
async def test_suggest_for_phase_uses_advisor_prompt(tmp_path):
    from saarthi_ai.analysis import gather_phase_digest, suggest_for_phase
    from saarthi_ai.analysis.engine import PHASE_ADVISOR_SYSTEM_PROMPT

    database = _seed_run(tmp_path)
    child = _child_execution(database)
    digest = gather_phase_digest(
        database, child, target="https://app.example.com/item?id=1"
    )

    captured = {}

    class FakeClient:
        async def chat(self, messages, *, system_prompt=None, num_predict=150):
            captured["system_prompt"] = system_prompt
            captured["num_predict"] = num_predict
            return "- Try enumerating databases on `id`.", None

    text = await suggest_for_phase(FakeClient(), digest)

    assert "enumerating databases" in text
    assert captured["system_prompt"] == PHASE_ADVISOR_SYSTEM_PROMPT
    assert captured["num_predict"] > 150
