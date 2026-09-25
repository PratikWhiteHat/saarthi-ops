"""Persistent Phase 6G cleanup/rollback-manifest runner.

Reads the whole run's evidence catalog, builds a deterministic cleanup manifest
(footprint assertion + residual artifacts + rollback actions), and persists a
redacted CLEANUP_MANIFEST with digest signal keys + [6G] audit. Pure
aggregation — no network, no target-side action (that is the separate,
approval-gated executor).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from saarthi_ai.cleanup.models import CleanupManifest
from saarthi_ai.cleanup.planner import build_cleanup_manifest
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceCreate,
    EvidenceRecord,
    EvidenceType,
)


@dataclass
class TrackedCleanupResult:
    manifest: CleanupManifest
    evidence: EvidenceRecord | None
    evidence_path: str


def _gather_run_evidence(
    database: SaarthiDatabase,
    orchestration_id: str,
) -> tuple[str, list[EvidenceRecord]]:
    """Collect the run's target + every evidence record across its executions."""

    target = ""
    records: list[EvidenceRecord] = []
    try:
        executions = database.list_executions(limit=1_000)
    except Exception:
        return target, records
    for execution in executions:
        meta = execution.metadata or {}
        if meta.get("orchestration_id") != orchestration_id:
            continue
        if meta.get("execution_role") == "orchestration_parent" and (
            execution.targets
        ):
            target = str(execution.targets[0])
        records.extend(database.list_evidence(execution.execution_id))
    return target, records


def run_tracked_cleanup(
    database: SaarthiDatabase,
    execution_id: str,
    *,
    orchestration_id: str,
    evidence_root: Path,
    actor: str = "6g-cleanup-rollback",
) -> TrackedCleanupResult:
    """Build the run's cleanup manifest and persist it. No target-side action."""

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_STARTED,
        actor=actor,
        message="[6G] Cleanup/rollback manifest started.",
        details={
            "phase_code": "6G",
            "tool": "cleanup-rollback",
            "orchestration_id": orchestration_id,
        },
    )

    target, records = _gather_run_evidence(database, orchestration_id)
    manifest = build_cleanup_manifest(target=target, evidence_records=records)

    for item in manifest.items:
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_OUTPUT,
            actor=actor,
            message=(
                f"[6G] {item.artifact_type.value} -> {item.action.value} "
                f"({item.reversibility.value}) @ {item.location}"
            ),
            details={
                "phase_code": "6G",
                "tool": "cleanup-rollback",
                "item_id": item.item_id,
                "artifact_type": item.artifact_type.value,
                "action": item.action.value,
                "reversibility": item.reversibility.value,
                "is_target_side": item.is_target_side,
            },
        )

    body = json.dumps(manifest.as_dict(), indent=2).encode("utf-8")
    sha = hashlib.sha256(body).hexdigest()
    evidence_root.mkdir(parents=True, exist_ok=True)
    path = evidence_root / f"cleanup-manifest-{sha[:12]}.json"
    path.write_bytes(body)

    types = manifest.artifact_type_counts
    evidence = database.add_evidence(
        execution_id,
        EvidenceCreate(
            evidence_type=EvidenceType.CLEANUP_MANIFEST,
            source="cleanup-rollback",
            path=str(path),
            sha256=sha,
            size_bytes=len(body),
            content_type="application/json",
            step_id="phase6g-cleanup-rollback-001",
            tool_name="cleanup-rollback",
            metadata={
                "classification": manifest.footprint.value,
                "status": "completed",
                "count": len(manifest.items),
                "footprint": manifest.footprint.value,
                "reversible_count": manifest.reversible_count,
                "operator_action_count": manifest.operator_action_count,
                "target_artifacts": types.get("target_artifact", 0),
            },
        ),
        actor=actor,
    )

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_COMPLETED,
        actor=actor,
        message=(
            f"[6G] Cleanup manifest completed: {len(manifest.items)} item(s); "
            f"footprint {manifest.footprint.value}; "
            f"{manifest.reversible_count} auto-reversible."
        ),
        details={
            "phase_code": "6G",
            "tool": "cleanup-rollback",
            "count": len(manifest.items),
            "footprint": manifest.footprint.value,
            "evidence_id": evidence.evidence_id,
        },
    )

    return TrackedCleanupResult(
        manifest=manifest,
        evidence=evidence,
        evidence_path=str(path),
    )


__all__ = ["TrackedCleanupResult", "run_tracked_cleanup"]
