"""Phase 6G — persistent cleanup-manifest runner tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from saarthi_ai.persistence.cleanup_workflow import run_tracked_cleanup
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import (
    EvidenceCreate,
    EvidenceType,
    ExecutionCreate,
)

ORCHESTRATION_ID = "orchestration-6g-test"


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "6g.db")
    repository.initialize()
    return repository


def _parent(database: SaarthiDatabase) -> str:
    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Phase 6G",
            asset_types=["web"],
            targets=["http://t/"],
            authorization_confirmed=True,
            active_testing_allowed=True,
            intrusive_testing_allowed=False,
            metadata={
                "orchestration_id": ORCHESTRATION_ID,
                "execution_role": "orchestration_parent",
            },
        )
    )
    return execution.execution_id


def _add(database: SaarthiDatabase, execution_id: str, evidence_type, path, meta=None):
    database.add_evidence(
        execution_id,
        EvidenceCreate(
            evidence_type=evidence_type,
            source="x",
            path=path,
            sha256="0" * 64,
            size_bytes=1,
            content_type="application/json",
            step_id="s",
            tool_name="t",
            metadata=meta or {},
        ),
    )


def test_persists_signal_keys_and_audits(
    database: SaarthiDatabase, tmp_path: Path
) -> None:
    execution_id = _parent(database)
    _add(database, execution_id, EvidenceType.SQLMAP_EXTERNAL_RESULT, "/e/s.txt")
    _add(
        database,
        execution_id,
        EvidenceType.UPLOAD_EXTERNAL_RESULT,
        "/e/up.json",
        {"uploaded_url": "http://t/uploads/x.txt"},
    )

    tracked = run_tracked_cleanup(
        database,
        execution_id,
        orchestration_id=ORCHESTRATION_ID,
        evidence_root=tmp_path / "6g",
    )

    assert tracked.evidence.evidence_type is EvidenceType.CLEANUP_MANIFEST
    meta = tracked.evidence.metadata
    assert meta["footprint"] == "target_footprint_present"
    assert meta["reversible_count"] == 1
    assert meta["target_artifacts"] == 1

    six_g = [
        e.message
        for e in database.list_audit_events(execution_id)
        if "[6G]" in e.message
    ]
    # started + one per item (2) + completed
    assert len(six_g) == 4


def test_clean_run_asserts_no_footprint(
    database: SaarthiDatabase, tmp_path: Path
) -> None:
    execution_id = _parent(database)
    _add(database, execution_id, EvidenceType.POST_EXPLOITATION_SIMULATION, "/e/6f.json")

    tracked = run_tracked_cleanup(
        database,
        execution_id,
        orchestration_id=ORCHESTRATION_ID,
        evidence_root=tmp_path / "6g",
    )
    assert tracked.manifest.items == ()
    assert tracked.evidence.metadata["footprint"] == "no_target_footprint"


def test_persisted_manifest_is_redacted(
    database: SaarthiDatabase, tmp_path: Path
) -> None:
    """Persisted manifest carries locations/actions only — never file contents."""

    execution_id = _parent(database)
    _add(database, execution_id, EvidenceType.SQLMAP_EXTERNAL_RESULT, "/e/s.txt")

    tracked = run_tracked_cleanup(
        database,
        execution_id,
        orchestration_id=ORCHESTRATION_ID,
        evidence_root=tmp_path / "6g",
    )
    parsed = json.loads(Path(tracked.evidence_path).read_text(encoding="utf-8"))
    assert set(parsed) >= {
        "target",
        "item_count",
        "footprint",
        "reversible_count",
        "operator_action_count",
        "items",
    }
    # Only metadata/location fields per item — no arbitrary content key.
    for item in parsed["items"]:
        assert set(item) <= {
            "item_id",
            "artifact_type",
            "location",
            "reversibility",
            "action",
            "source_evidence_type",
            "detail",
            "target",
            "is_target_side",
        }
