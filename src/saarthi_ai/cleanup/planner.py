"""Phase 6G planner — deterministic cleanup-manifest aggregation.

Reads the run's evidence catalog and classifies each record into a cleanup item
(local sensitive artifact, external-result import, live auth session, or a rare
target-side artifact) with the recommended rollback action and reversibility.
No network I/O; executes nothing. The manifest's footprint stays
NO_TARGET_FOOTPRINT unless an actual target-side artifact is found.
"""

from __future__ import annotations

from collections.abc import Iterable

from saarthi_ai.cleanup.models import (
    CleanupArtifactType,
    CleanupItem,
    CleanupManifest,
    Reversibility,
    RollbackAction,
    make_cleanup_id,
)

# Metadata keys that signal a file was actually placed ON the target.
_UPLOADED_URL_KEYS = ("uploaded_url", "stored_url", "resource_url", "file_url")


def _evidence_type_value(evidence: object) -> str:
    raw = getattr(evidence, "evidence_type", "")
    return getattr(raw, "value", raw) or ""


def _uploaded_target_url(metadata: dict) -> str | None:
    for key in _UPLOADED_URL_KEYS:
        value = metadata.get(key)
        if value:
            return str(value)
    if metadata.get("file_uploaded") is True:
        # A submission happened but no URL was captured — flag for review.
        return ""
    return None


def _classify(
    evidence_type: str,
    path: str,
    metadata: dict,
    target: str,
) -> CleanupItem | None:
    """Map one evidence record to a cleanup item, or None if it leaves nothing."""

    if evidence_type == "sqlmap_external_result":
        return CleanupItem(
            item_id=make_cleanup_id(
                CleanupArtifactType.LOCAL_SENSITIVE_EVIDENCE.value, path
            ),
            artifact_type=CleanupArtifactType.LOCAL_SENSITIVE_EVIDENCE,
            location=path,
            reversibility=Reversibility.OPERATOR_ACTION,
            action=RollbackAction.SECURE_DISPOSE,
            source_evidence_type=evidence_type,
            detail=(
                "imported sqlmap output may contain extracted rows — dispose "
                "or retain per the engagement data policy"
            ),
        )

    if evidence_type == "upload_external_result":
        uploaded = _uploaded_target_url(metadata)
        if uploaded is not None:
            location = uploaded or path
            return CleanupItem(
                item_id=make_cleanup_id(
                    CleanupArtifactType.TARGET_ARTIFACT.value, location
                ),
                artifact_type=CleanupArtifactType.TARGET_ARTIFACT,
                location=location,
                reversibility=(
                    Reversibility.AUTO_REVERSIBLE
                    if uploaded
                    else Reversibility.OPERATOR_ACTION
                ),
                action=RollbackAction.DELETE_TARGET_ARTIFACT,
                source_evidence_type=evidence_type,
                detail="a test file was uploaded to the target — remove it",
                target=target,
            )
        return CleanupItem(
            item_id=make_cleanup_id(
                CleanupArtifactType.EXTERNAL_RESULT_IMPORT.value, path
            ),
            artifact_type=CleanupArtifactType.EXTERNAL_RESULT_IMPORT,
            location=path,
            reversibility=Reversibility.OPERATOR_ACTION,
            action=RollbackAction.SECURE_DISPOSE,
            source_evidence_type=evidence_type,
            detail="imported upload-test result — dispose per data policy",
        )

    if evidence_type == "authenticated_workflow_result":
        return CleanupItem(
            item_id=make_cleanup_id(
                CleanupArtifactType.LIVE_AUTH_SESSION.value, target or path
            ),
            artifact_type=CleanupArtifactType.LIVE_AUTH_SESSION,
            location=target or path,
            reversibility=Reversibility.OPERATOR_ACTION,
            action=RollbackAction.INVALIDATE_SESSION,
            source_evidence_type=evidence_type,
            detail=(
                "authenticated sessions were established with operator-supplied "
                "credentials — log out / invalidate the tokens"
            ),
            target=target or None,
        )

    return None


def build_cleanup_manifest(
    *,
    target: str,
    evidence_records: Iterable[object] = (),
) -> CleanupManifest:
    """Build a deterministic cleanup manifest from a run's evidence records."""

    items: list[CleanupItem] = []
    seen: set[str] = set()

    for evidence in evidence_records:
        item = _classify(
            _evidence_type_value(evidence),
            getattr(evidence, "path", None) or "",
            getattr(evidence, "metadata", None) or {},
            target,
        )
        if item is None or item.item_id in seen:
            continue
        seen.add(item.item_id)
        items.append(item)

    return CleanupManifest(target=target, items=tuple(items))


__all__ = ["build_cleanup_manifest"]
