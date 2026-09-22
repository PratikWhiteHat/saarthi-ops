"""Persistent Phase 6H evidence-and-findings consolidation workflow."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from saarthi_ai.evidence_findings.builder import build_evidence_findings_bundle
from saarthi_ai.evidence_findings.models import EvidenceFindingsBundle
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceCreate,
    EvidenceRecord,
    EvidenceType,
)


@dataclass
class TrackedEvidenceFindingsResult:
    bundle: EvidenceFindingsBundle
    evidence: EvidenceRecord
    evidence_path: str


def _gather_run(
    database: SaarthiDatabase,
    orchestration_id: str,
) -> tuple[str, list[EvidenceRecord]]:
    target = ""
    records: list[EvidenceRecord] = []
    for execution in database.list_executions(limit=1_000):
        metadata = execution.metadata or {}
        if metadata.get("orchestration_id") != orchestration_id:
            continue
        if metadata.get("execution_role") == "orchestration_parent" and execution.targets:
            target = str(execution.targets[0])
        records.extend(database.list_evidence(execution.execution_id))
    return target, records


def run_tracked_evidence_findings(
    database: SaarthiDatabase,
    execution_id: str,
    *,
    orchestration_id: str,
    evidence_root: Path,
    actor: str = "6h-evidence-findings",
) -> TrackedEvidenceFindingsResult:
    """Verify the run evidence, index findings and persist the 6H bundle."""

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_STARTED,
        actor=actor,
        message="[6H] Evidence and findings consolidation started.",
        details={"phase_code": "6H", "tool": "evidence-findings"},
    )
    target, records = _gather_run(database, orchestration_id)
    bundle = build_evidence_findings_bundle(
        target=target,
        evidence_records=records,
    )
    body = json.dumps(bundle.as_dict(), indent=2).encode("utf-8")
    sha = hashlib.sha256(body).hexdigest()
    evidence_root.mkdir(parents=True, exist_ok=True)
    path = evidence_root / f"evidence-findings-{sha[:12]}.json"
    path.write_bytes(body)

    classification = (
        "findings_consolidated" if bundle.findings else "evidence_consolidated"
    )
    evidence = database.add_evidence(
        execution_id,
        EvidenceCreate(
            evidence_type=EvidenceType.EVIDENCE_FINDINGS_BUNDLE,
            source="evidence-findings",
            path=str(path),
            sha256=sha,
            size_bytes=len(body),
            content_type="application/json",
            step_id="phase6h-evidence-findings-001",
            tool_name="evidence-findings",
            metadata={
                "classification": classification,
                "status": "completed",
                "count": len(bundle.findings),
                "confirmed_count": bundle.confirmed_finding_count,
                "evidence_count": len(bundle.evidence),
                "verified_evidence_count": bundle.verified_evidence_count,
                "rejected_evidence_count": bundle.rejected_evidence_count,
                "critical": bundle.severity_counts.get("critical", 0),
                "high": bundle.severity_counts.get("high", 0),
            },
        ),
        actor=actor,
    )
    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_COMPLETED,
        actor=actor,
        message=(
            f"[6H] Consolidated {len(bundle.evidence)} evidence record(s) and "
            f"{len(bundle.findings)} finding(s); "
            f"{bundle.rejected_evidence_count} evidence record(s) rejected."
        ),
        details={
            "phase_code": "6H",
            "tool": "evidence-findings",
            "evidence_id": evidence.evidence_id,
            "evidence_count": len(bundle.evidence),
            "verified_evidence_count": bundle.verified_evidence_count,
            "rejected_evidence_count": bundle.rejected_evidence_count,
            "finding_count": len(bundle.findings),
            "confirmed_count": bundle.confirmed_finding_count,
        },
    )
    return TrackedEvidenceFindingsResult(
        bundle=bundle,
        evidence=evidence,
        evidence_path=str(path),
    )


__all__ = ["TrackedEvidenceFindingsResult", "run_tracked_evidence_findings"]
