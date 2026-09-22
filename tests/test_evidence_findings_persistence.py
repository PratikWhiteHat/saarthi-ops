"""Phase 6H evidence-integrity and finding-consolidation tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.evidence_findings_workflow import (
    run_tracked_evidence_findings,
)
from saarthi_ai.persistence.models import (
    EvidenceCreate,
    EvidenceType,
    ExecutionCreate,
)

ORCHESTRATION_ID = "orchestration-6h-test"
TARGET = "https://app.example.test/item?id=1"


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "6h.db")
    repository.initialize()
    return repository


def _parent(database: SaarthiDatabase) -> str:
    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Phase 6H",
            asset_types=["web"],
            targets=[TARGET],
            authorization_confirmed=True,
            active_testing_allowed=False,
            intrusive_testing_allowed=False,
            metadata={
                "orchestration_id": ORCHESTRATION_ID,
                "execution_role": "orchestration_parent",
            },
        )
    )
    return execution.execution_id


def _json_evidence(
    database: SaarthiDatabase,
    execution_id: str,
    tmp_path: Path,
    *,
    name: str,
    evidence_type: EvidenceType,
    payload: dict,
    sha256: str | None = None,
) -> None:
    body = json.dumps(payload).encode("utf-8")
    path = tmp_path / name
    path.write_bytes(body)
    database.add_evidence(
        execution_id,
        EvidenceCreate(
            evidence_type=evidence_type,
            source=name,
            path=str(path),
            sha256=sha256 or hashlib.sha256(body).hexdigest(),
            size_bytes=len(body),
            content_type="application/json",
            step_id=name,
            tool_name="test",
        ),
    )


def test_persists_hash_verified_redacted_bundle(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = _parent(database)
    secret = "must-not-survive-6h"
    _json_evidence(
        database,
        execution_id,
        tmp_path,
        name="6e.json",
        evidence_type=EvidenceType.EXPLOIT_CONFIRMATION_RESULT,
        payload={
            "findings": [
                {
                    "finding_id": "finding-6e-1",
                    "kind": "authorization_control_failure",
                    "severity": "high",
                    "target": TARGET,
                    "verdict": "confirmed_impact",
                    "proof": ["bounded response differential"],
                    "raw_secret": secret,
                }
            ]
        },
    )
    _json_evidence(
        database,
        execution_id,
        tmp_path,
        name="ai.json",
        evidence_type=EvidenceType.AI_QUALITY_ANALYSIS,
        payload={
            "findings": [
                {
                    "finding_id": "finding-ai-1",
                    "title": "Missing defensive response control",
                    "severity": "medium",
                    "final_disposition": "supported",
                    "confidence": 88,
                    "statement": "Observed in verified response metadata.",
                    "remediation": "Add and test the missing control.",
                    "evidence_refs": ["source-ref-1"],
                }
            ]
        },
    )
    _json_evidence(
        database,
        execution_id,
        tmp_path,
        name="tampered.json",
        evidence_type=EvidenceType.CLEANUP_MANIFEST,
        payload={"items": []},
        sha256="0" * 64,
    )

    tracked = run_tracked_evidence_findings(
        database,
        execution_id,
        orchestration_id=ORCHESTRATION_ID,
        evidence_root=tmp_path / "6h",
    )

    assert tracked.evidence.evidence_type is EvidenceType.EVIDENCE_FINDINGS_BUNDLE
    assert tracked.bundle.verified_evidence_count == 2
    assert tracked.bundle.rejected_evidence_count == 1
    assert len(tracked.bundle.findings) == 2
    assert tracked.bundle.confirmed_finding_count == 2
    assert tracked.evidence.metadata["critical"] == 0
    assert tracked.evidence.metadata["high"] == 1

    persisted = Path(tracked.evidence_path).read_text(encoding="utf-8")
    assert secret not in persisted
    payload = json.loads(persisted)
    rejected = [
        item for item in payload["evidence"] if item["integrity"] == "rejected"
    ]
    assert len(rejected) == 1
    assert rejected[0]["reason"] == "SHA-256 mismatch"

    messages = [
        event.message for event in database.list_audit_events(execution_id)
    ]
    assert any(
        "[6H] Evidence and findings consolidation started" in message
        for message in messages
    )
    assert any(
        "[6H] Consolidated 3 evidence record(s)" in message
        for message in messages
    )


def test_missing_file_is_rejected_without_aborting(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id = _parent(database)
    database.add_evidence(
        execution_id,
        EvidenceCreate(
            evidence_type=EvidenceType.NOTE,
            source="missing",
            path=str(tmp_path / "missing.json"),
            sha256="1" * 64,
            content_type="application/json",
        ),
    )

    tracked = run_tracked_evidence_findings(
        database,
        execution_id,
        orchestration_id=ORCHESTRATION_ID,
        evidence_root=tmp_path / "6h",
    )

    assert tracked.bundle.verified_evidence_count == 0
    assert tracked.bundle.rejected_evidence_count == 1
    assert tracked.bundle.findings == ()
    assert tracked.evidence.metadata["classification"] == "evidence_consolidated"
