"""Tests for the evidence-grounded, multi-pass AI quality layer."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from saarthi_ai.analysis.quality import (
    EXTRACTOR_SYSTEM_PROMPT,
    FinalDisposition,
    QualityAnalysisError,
    SourceReference,
    analyze_run_quality,
    persist_quality_analysis,
    render_quality_analysis,
)
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import EvidenceType, ExecutionCreate


def _digest():
    return SimpleNamespace(
        orchestration_id="orchestration-quality-1",
        parent_execution_id="execution-parent",
        target="https://app.example.com/item?id=1",
        parent_state="completed",
        source_references=(
            SourceReference("event-1", "6C", "finding_created", "id changed response"),
            SourceReference("evidence-1", "6C", "tool_output", "DBMS marker observed"),
        ),
    )


class FakeClient:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    async def chat(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        return next(self.responses), None


@pytest.mark.asyncio
async def test_quality_result_records_actual_skill_context_by_pass_and_citations():
    class TraceClient(FakeClient):
        async def chat(self, messages, **kwargs):
            pass_number = len(self.calls)
            if pass_number == 1:
                kwargs["skill_trace"].append("hunt-sqli")
            if pass_number == 2:
                kwargs["skill_trace"].append("triage-validation")
            return await super().chat(messages, **kwargs)

    client = TraceClient([
        '{"facts":[{"fact_id":"F1","statement":"A response changed.",'
        '"evidence_refs":["event-1"]}]}',
        '{"findings":[{"finding_id":"C1","title":"Needs review",'
        '"statement":"The change needs confirmation.",'
        '"evidence_refs":["event-1"],"fact_ids":["F1"],'
        '"missing_evidence":["Independent confirmation."]}]}',
        '{"reviews":[{"finding_id":"C1","disposition":"partial",'
        '"supported_evidence_refs":["event-1"],'
        '"rationale":"[hunt-sqli] calls for independent evidence.",'
        '"missing_evidence":["Independent confirmation."]}]}',
        '{"skills":['
        '{"skill_id":"hunt-sqli","status":"evidence_found",'
        '"evidence_refs":["invented-source"],"reason":"No SQL-specific result."},'
        '{"skill_id":"triage-validation","status":"evidence_found",'
        '"evidence_refs":["[event-1]"],"reason":"Observation needs review."}]}',
    ])

    result = await analyze_run_quality(client, _digest())

    assert [item.skill_ids for item in result.skills_by_pass] == [
        (), ("hunt-sqli",), ("triage-validation",), ()
    ]
    assert result.pass_count == 4
    assert [item.status.value for item in result.skill_assessments] == [
        "insufficient_evidence", "evidence_found",
    ]
    assert result.skill_assessments[1].evidence_refs == ("event-1",)
    assert result.skill_assessments[0].evidence_refs == ()
    assert any("Skill hunt-sqli discarded invalid citation" in warning
               for warning in result.warnings)
    assert result.sources[0].reference_id == "event-1"
    view = render_quality_analysis(result)
    assert "Skills supplied to model (not proof of influence)" in view
    assert "hunt-sqli" in view
    assert "Enabled-skill evidence review" in view
    assert "Skill refs mentioned for this finding (model claim): hunt-sqli" in view
    assert (
        "Skill refs mentioned for this finding (model claim): "
        "hunt-sqli, triage-validation"
    ) not in view
    assert "event-1 [6C/finding_created]: id changed response" in view
    assert "Missing evidence: Independent confirmation." in view


@pytest.mark.asyncio
async def test_skill_review_batches_preserve_valid_results_when_one_skill_fails():
    skill_ids = (
        "hunt-sqli", "hunt-xss", "hunt-cors", "hunt-csrf", "hunt-clickjacking",
        "triage-validation",
    )

    class BatchClient:
        def __init__(self):
            self.calls = []

        async def chat(self, messages, **kwargs):
            self.calls.append((messages, kwargs))
            if len(self.calls) == 1:
                return (
                    '{"facts":[{"fact_id":"F1","statement":"Observation.",'
                    '"evidence_refs":["event-1"]}]}', None,
                )
            if len(self.calls) == 2:
                kwargs["skill_trace"].extend(skill_ids)
                return '{"findings":[]}', None
            if len(self.calls) == 3:
                return '{"reviews":[]}', None
            batch = kwargs["skill_ids"]
            kwargs["skill_trace"].extend(batch)
            if "hunt-xss" in batch:
                return "not JSON", None
            return json.dumps({"skills": [
                {"skill_id": skill_id, "status": "insufficient_evidence",
                 "evidence_refs": [], "reason": "No confirming evidence."}
                for skill_id in batch
            ]}), None

    client = BatchClient()
    result = await analyze_run_quality(client, _digest())

    status_by_skill = {
        item.skill_id: item.status.value for item in result.skill_assessments
    }
    assert len(status_by_skill) == 6
    assert status_by_skill["hunt-xss"] == "not_evaluated"
    assert all(status_by_skill[item] == "insufficient_evidence"
               for item in skill_ids if item != "hunt-xss")
    assert any("hunt-xss review returned invalid" in item for item in result.warnings)
    coverage_calls = client.calls[3:]
    assert all(len(call[1]["skill_ids"]) <= 3 for call in coverage_calls)
    assert all(call[1]["skill_context_char_limit"] == 2_400 for call in coverage_calls)


@pytest.mark.asyncio
async def test_quality_analysis_runs_three_json_grounded_passes():
    client = FakeClient(
        [
            json.dumps(
                {
                    "facts": [
                        {
                            "fact_id": "F1",
                            "statement": "The id parameter changed the response.",
                            "evidence_refs": ["event-1", "invented-ref"],
                            "phase_codes": ["6C"],
                        },
                        {
                            "fact_id": "F2",
                            "statement": "This fact is fabricated.",
                            "evidence_refs": ["missing-ref"],
                        },
                    ]
                }
            ),
            json.dumps(
                {
                    "findings": [
                        {
                            "finding_id": "C1",
                            "title": "Possible SQL injection",
                            "severity": "high",
                            "verdict": "likely",
                            "statement": "The parameter may be injectable.",
                            "fact_ids": ["F1"],
                            "evidence_refs": ["evidence-1"],
                            "alternative_explanations": [],
                            "missing_evidence": [],
                            "remediation": "Use parameterized queries.",
                        }
                    ]
                }
            ),
            json.dumps(
                {
                    "reviews": [
                        {
                            "finding_id": "C1",
                            "disposition": "supported",
                            "supported_evidence_refs": ["event-1", "evidence-1"],
                            "contradictory_evidence_refs": [],
                            "missing_evidence": [],
                            "rationale": "Two independent local records support it.",
                        }
                    ]
                }
            ),
        ]
    )

    result = await analyze_run_quality(client, _digest())

    assert len(client.calls) == 3
    assert all(call[1]["json_mode"] is True for call in client.calls)
    assert "UNTRUSTED DATA" in EXTRACTOR_SYSTEM_PROMPT
    assert len(result.facts) == 1
    assert result.findings[0].final_disposition is FinalDisposition.LIKELY
    assert result.findings[0].evidence_refs == ("evidence-1", "event-1")
    assert any("invented-ref" in warning for warning in result.warnings)
    assert any("F2" in warning and "dropped" in warning for warning in result.warnings)


@pytest.mark.asyncio
async def test_quality_analysis_discloses_missing_consolidated_scanner_evidence():
    digest = _digest()
    digest.auto_validation_status = "missing"
    client = FakeClient([
        '{"facts":[]}', '{"findings":[]}', '{"reviews":[]}',
    ])

    result = await analyze_run_quality(client, digest)

    assert result.auto_validation_status == "missing"
    assert any("scanner coverage cannot be confirmed" in item for item in result.warnings)
    assert "Consolidated scanner evidence: missing" in render_quality_analysis(result)


@pytest.mark.asyncio
async def test_bracketed_known_citations_are_grounded_but_unknown_ids_are_rejected():
    client = FakeClient([
        json.dumps({"facts": [
            {"fact_id": "F1", "statement": "A response changed.",
             "evidence_refs": ["[event-1]"]},
            {"fact_id": "F2", "statement": "An ungrounded claim.",
             "evidence_refs": ["[event-missing]"]},
        ]}),
        json.dumps({"findings": [{
            "finding_id": "C1", "title": "Review needed",
            "statement": "The change needs confirmation.",
            "fact_ids": ["F1"], "evidence_refs": ["[evidence-1]"],
        }]}),
        json.dumps({"reviews": [{
            "finding_id": "C1", "disposition": "partial",
            "supported_evidence_refs": ["[event-1]"],
        }]}),
    ])

    result = await analyze_run_quality(client, _digest())

    assert [fact.fact_id for fact in result.facts] == ["F1"]
    assert result.facts[0].evidence_refs == ("event-1",)
    assert set(result.findings[0].evidence_refs) == {"event-1", "evidence-1"}
    assert any("event-missing" in warning for warning in result.warnings)
    assert not any("[event-1]" in warning for warning in result.warnings)
    assert client.calls[0][1]["include_enabled_skills"] is False
    assert all(call[1]["include_enabled_skills"] is True for call in client.calls[1:])


@pytest.mark.asyncio
async def test_quality_analysis_rejects_malformed_json():
    client = FakeClient(["not JSON"] * 8)

    with pytest.raises(QualityAnalysisError, match="bounded evidence-batch retries"):
        await analyze_run_quality(client, _digest())
    assert len(client.calls) == 8
    assert client.calls[1][1]["num_predict"] > client.calls[0][1]["num_predict"]


@pytest.mark.asyncio
async def test_quality_analysis_recovers_from_truncated_extractor_json():
    client = FakeClient([
        '{"facts":[{"fact_id":"F1","statement":"Observed',
        '{"facts":[{"fact_id":"F1","statement":"A response changed.",'
        '"evidence_refs":["event-1"]}]}',
        '{"findings":[]}',
        '{"reviews":[]}',
    ])

    result = await analyze_run_quality(client, _digest())

    assert len(result.facts) == 1
    assert result.facts[0].evidence_refs == ("event-1",)
    assert result.findings == ()
    assert len(client.calls) == 4
    assert "compact, complete JSON" in client.calls[1][1]["system_prompt"]


@pytest.mark.asyncio
async def test_quality_analysis_batches_sources_after_full_extractor_failure():
    digest = _digest()
    digest.source_references = tuple(
        SourceReference(f"event-{index}", "4A", "tool_output", f"Observation {index}")
        for index in range(1, 13)
    )
    client = FakeClient([
        "not JSON",
        '{"facts":[{"fact_id":"F1"',
        '{"facts":[{"fact_id":"F1","statement":"First observation.",'
        '"evidence_refs":["event-1"]}]}',
        '{"facts":[{"fact_id":"F1","statement":"Last observation.",'
        '"evidence_refs":["event-12"]}]}',
        '{"findings":[]}',
        '{"reviews":[]}',
    ])

    result = await analyze_run_quality(client, digest)

    assert [fact.fact_id for fact in result.facts] == ["F1", "F2"]
    assert result.facts[0].evidence_refs == ("event-1",)
    assert result.facts[1].evidence_refs == ("event-12",)
    assert any("smaller evidence batches" in warning for warning in result.warnings)
    assert not any("coverage is incomplete" in warning for warning in result.warnings)
    assert "[event-11]" not in client.calls[2][0][0].content
    assert "[event-12]" in client.calls[3][0][0].content


@pytest.mark.asyncio
async def test_large_run_extracts_in_small_batches_without_skill_context():
    digest = _digest()
    digest.source_references = tuple(
        SourceReference(f"event-{index}", "4A", "tool_output", f"Observation {index}")
        for index in range(1, 26)
    )
    client = FakeClient([
        '{"facts":[]}', '{"facts":[]}', '{"facts":[]}',
        '{"findings":[]}', '{"reviews":[]}',
    ])

    result = await analyze_run_quality(client, digest)

    assert len(client.calls) == 5
    assert all(call[1]["use_skills"] is False for call in client.calls[:3])
    assert all(call[1]["use_skills"] is True for call in client.calls[3:])
    assert all(call[0][0].content.count("phase=4A") <= 10 for call in client.calls[:3])
    assert result.source_reference_count == 25
    assert any("smaller evidence batches" in warning for warning in result.warnings)


@pytest.mark.asyncio
async def test_partial_batch_coverage_is_visible_and_never_fabricated():
    client = FakeClient([
        "not JSON", "not JSON",  # full context
        "not JSON", "not JSON",  # two-source batch
        '{"facts":[{"fact_id":"F1","statement":"Response observed.",'
        '"evidence_refs":["event-1"]}]}',
        "not JSON", "not JSON",  # second single source is skipped
        '{"findings":[]}', '{"reviews":[]}',
    ])

    result = await analyze_run_quality(client, _digest())

    assert [fact.evidence_refs for fact in result.facts] == [("event-1",)]
    assert any("reviewed 1/2" in warning for warning in result.warnings)
    assert "coverage is incomplete" in render_quality_analysis(result)


@pytest.mark.asyncio
async def test_quality_analysis_normalizes_single_string_list_fields():
    client = FakeClient(
        [
            json.dumps(
                {
                    "facts": {
                        "fact_id": "F1",
                        "statement": "A DNS record is an anomaly.",
                        "evidence_refs": "event-1",
                        "phase_codes": "3A",
                    }
                }
            ),
            json.dumps(
                {
                    "findings": {
                        "finding_id": "C1",
                        "title": "DNS anomaly",
                        "severity": "info",
                        "verdict": "unconfirmed",
                        "statement": "The record needs review.",
                        "fact_ids": "F1",
                        "evidence_refs": "event-1",
                        "alternative_explanations": "A normal provider record.",
                        "missing_evidence": "Asset-owner confirmation.",
                    }
                }
            ),
            json.dumps(
                {
                    "reviews": {
                        "finding_id": "C1",
                        "disposition": "partial",
                        "supported_evidence_refs": "event-1",
                        "missing_evidence": "Asset-owner confirmation.",
                        "rationale": "The observation is real but impact is unknown.",
                    }
                }
            ),
        ]
    )

    result = await analyze_run_quality(client, _digest())

    assert result.facts[0].evidence_refs == ("event-1",)
    assert result.findings[0].alternative_explanations == (
        "A normal provider record.",
    )


@pytest.mark.asyncio
async def test_quality_analysis_resolves_unique_bare_uuid_citations():
    full_reference = "event-57a42a0b-0b67-4543-bc06-85ca3d7ed4d0"
    digest = _digest()
    digest.source_references = (
        SourceReference(
            full_reference,
            "3A",
            "finding_created",
            "DNS anomaly",
        ),
    )
    client = FakeClient(
        [
            json.dumps(
                {
                    "facts": [
                        {
                            "fact_id": "F1",
                            "statement": "A DNS anomaly was recorded.",
                            "evidence_refs": [
                                "57a42a0b-0b67-4543-bc06-85ca3d7ed4d0"
                            ],
                        }
                    ]
                }
            ),
            '{"findings":[]}',
            '{"reviews":[]}',
        ]
    )

    result = await analyze_run_quality(client, digest)

    assert result.facts[0].evidence_refs == (full_reference,)
    assert not result.warnings


@pytest.mark.asyncio
async def test_critical_review_can_downgrade_an_analyst_claim():
    client = FakeClient(
        [
            json.dumps(
                {
                    "facts": [
                        {
                            "fact_id": "F1",
                            "statement": "The response changed.",
                            "evidence_refs": ["event-1"],
                        }
                    ]
                }
            ),
            json.dumps(
                {
                    "findings": [
                        {
                            "finding_id": "C1",
                            "title": "Claimed vulnerability",
                            "severity": "high",
                            "verdict": "confirmed",
                            "statement": "A vulnerability exists.",
                            "fact_ids": ["F1"],
                            "evidence_refs": ["event-1"],
                        }
                    ]
                }
            ),
            json.dumps(
                {
                    "reviews": [
                        {
                            "finding_id": "C1",
                            "disposition": "unsupported",
                            "supported_evidence_refs": ["event-1"],
                            "missing_evidence": ["No reproducible proof."],
                            "rationale": "A changed response does not prove impact.",
                        }
                    ]
                }
            ),
        ]
    )

    result = await analyze_run_quality(client, _digest())

    finding = result.findings[0]
    assert finding.final_disposition is FinalDisposition.UNSUPPORTED
    assert finding.confidence < 40


def test_quality_result_is_persisted_as_hash_linked_evidence(tmp_path):
    database = SaarthiDatabase(tmp_path / "quality.db")
    database.initialize()
    parent = database.create_execution(
        ExecutionCreate(
            assessment_name="Quality test",
            asset_types=["url"],
            targets=["https://app.example.com/item?id=1"],
            authorization_confirmed=True,
        )
    )
    digest = _digest()
    digest.parent_execution_id = parent.execution_id

    # Use the validated model returned by the pipeline to cover serialization.
    client = FakeClient(
        [
            '{"facts":[]}',
            '{"findings":[]}',
            '{"reviews":[]}',
        ]
    )

    import asyncio

    result = asyncio.run(analyze_run_quality(client, digest))
    record = persist_quality_analysis(
        database,
        parent.execution_id,
        result,
        evidence_root=tmp_path / "evidence",
    )

    assert record.evidence_type is EvidenceType.AI_QUALITY_ANALYSIS
    assert record.sha256
    assert record.size_bytes and record.size_bytes > 0
    assert json.loads(Path(record.path).read_text())["pass_count"] == 3
    assert record.metadata["skill_ids_supplied"] == []
    assert record.metadata["skill_ids_by_pass"] == {
        "extractor": [], "analyst": [], "reviewer": [],
    }
    assert record.metadata["disposition_counts"]["confirmed"] == 0
