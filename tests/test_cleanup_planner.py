"""Phase 6G — cleanup manifest aggregator + model rollup tests."""

from __future__ import annotations

from types import SimpleNamespace

from saarthi_ai.cleanup.models import (
    CleanupArtifactType,
    FootprintAssertion,
    Reversibility,
    RollbackAction,
    make_cleanup_id,
)
from saarthi_ai.cleanup.planner import build_cleanup_manifest


def _ev(evidence_type: str, path: str = "", metadata: dict | None = None):
    return SimpleNamespace(
        evidence_type=evidence_type, path=path, metadata=metadata or {}
    )


def test_make_cleanup_id_is_deterministic() -> None:
    assert make_cleanup_id("live_auth_session", "user-b") == make_cleanup_id(
        "live_auth_session", "user-b"
    )
    assert make_cleanup_id("live_auth_session", "user-b") != make_cleanup_id(
        "target_artifact", "user-b"
    )


def test_non_destructive_run_leaves_no_footprint() -> None:
    records = [
        _ev("dns_result"),
        _ev("crawl_result"),
        _ev("controlled_validation_observation"),
        _ev("exploit_confirmation_result", "/e/6e.json"),
        _ev("post_exploitation_simulation", "/e/6f.json"),
    ]
    manifest = build_cleanup_manifest(target="http://t/", evidence_records=records)
    assert manifest.items == ()
    assert manifest.footprint is FootprintAssertion.NO_TARGET_FOOTPRINT


def test_mixed_run_classification_and_footprint() -> None:
    records = [
        _ev("sqlmap_external_result", "/e/sqlmap/out.txt"),
        _ev("authenticated_workflow_result", "/e/6d.json"),
        _ev(
            "upload_external_result",
            "/e/up.json",
            {"uploaded_url": "http://t/uploads/x.txt"},
        ),
        _ev("upload_external_result", "/e/up2.json", {}),
    ]
    manifest = build_cleanup_manifest(target="http://t/", evidence_records=records)
    by_type = {i.artifact_type: i for i in manifest.items}

    assert (
        by_type[CleanupArtifactType.LOCAL_SENSITIVE_EVIDENCE].action
        is RollbackAction.SECURE_DISPOSE
    )
    assert (
        by_type[CleanupArtifactType.LIVE_AUTH_SESSION].action
        is RollbackAction.INVALIDATE_SESSION
    )
    target_item = by_type[CleanupArtifactType.TARGET_ARTIFACT]
    assert target_item.action is RollbackAction.DELETE_TARGET_ARTIFACT
    assert target_item.reversibility is Reversibility.AUTO_REVERSIBLE
    assert target_item.location == "http://t/uploads/x.txt"

    # One target-side artifact -> footprint present.
    assert manifest.footprint is FootprintAssertion.TARGET_FOOTPRINT_PRESENT
    assert manifest.reversible_count == 1
    assert manifest.operator_action_count == 3


def test_file_uploaded_flag_without_url_needs_operator() -> None:
    records = [
        _ev("upload_external_result", "/e/up.json", {"file_uploaded": True}),
    ]
    manifest = build_cleanup_manifest(target="http://t/", evidence_records=records)
    (item,) = manifest.items
    assert item.artifact_type is CleanupArtifactType.TARGET_ARTIFACT
    assert item.reversibility is Reversibility.OPERATOR_ACTION
    assert manifest.footprint is FootprintAssertion.TARGET_FOOTPRINT_PRESENT


def test_dedupes_duplicate_evidence() -> None:
    records = [
        _ev("sqlmap_external_result", "/e/sqlmap/out.txt"),
        _ev("sqlmap_external_result", "/e/sqlmap/out.txt"),
    ]
    manifest = build_cleanup_manifest(target="http://t/", evidence_records=records)
    assert len(manifest.items) == 1


def test_empty_records() -> None:
    manifest = build_cleanup_manifest(target="http://t/", evidence_records=[])
    assert manifest.items == ()
    assert manifest.footprint is FootprintAssertion.NO_TARGET_FOOTPRINT
