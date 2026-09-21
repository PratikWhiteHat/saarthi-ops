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
async def test_quality_analysis_rejects_malformed_json():
    client = FakeClient(["not JSON"])

    with pytest.raises(QualityAnalysisError):
        await analyze_run_quality(client, _digest())


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
