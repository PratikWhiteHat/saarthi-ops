"""Persistent Phase 6D authenticated-workflow runner.

Runs the authenticated-workflow engine, persists a REDACTED result (session
fingerprints + findings only — no credentials/tokens), and emits ``[6D]`` audit
events. Evidence metadata uses the digest signal keys (classification/status/
count) so the AI triage surfaces it automatically.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from saarthi_ai.controlled_validation.authenticated.engine import (
    AuthWorkflowResult,
    run_authenticated_workflow,
)
from saarthi_ai.controlled_validation.authenticated.models import (
    AuthWorkflowConfig,
)
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceCreate,
    EvidenceRecord,
    EvidenceType,
)


@dataclass
class TrackedAuthWorkflowResult:
    result: AuthWorkflowResult
    evidence: EvidenceRecord | None
    evidence_path: str


def result_payload(result: AuthWorkflowResult) -> dict:
    return {
        "target": result.target,
        "logins_ok": result.logins_ok,
        "logins_failed": result.logins_failed,
        "sessions": list(result.sessions),  # already-redacted fingerprints
        "findings": [
            {
                "kind": f.kind,
                "severity": f.severity,
                "classification": f.classification,
                "detail": f.detail,
                "principal": f.principal,
                "victim": f.victim,
                "url": f.url,
            }
            for f in result.findings
        ],
    }


def run_tracked_authenticated_workflow(
    database: SaarthiDatabase,
    execution_id: str,
    config: AuthWorkflowConfig,
    *,
    actor: str = "6d-authenticated-workflow",
    evidence_root: Path,
) -> TrackedAuthWorkflowResult:
    """Run 6D for a validated config and persist redacted evidence + audit."""

    def log(line: str) -> None:
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_OUTPUT,
            actor=actor,
            message=line,
            details={"phase_code": "6D", "tool": "authenticated-workflow"},
        )

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_STARTED,
        actor=actor,
        message="[6D] Authenticated workflow started.",
        details={
            "phase_code": "6D",
            "tool": "authenticated-workflow",
            "target": config.target_url,
            "principals": len(config.principals),
        },
    )

    result = run_authenticated_workflow(config, on_log=log)

    body = json.dumps(result_payload(result), indent=2).encode("utf-8")
    sha = hashlib.sha256(body).hexdigest()
    evidence_root.mkdir(parents=True, exist_ok=True)
    path = evidence_root / f"authenticated-workflow-{sha[:12]}.json"
    path.write_bytes(body)

    high = sum(1 for f in result.findings if f.severity == "high")
    classification = (
        "broken_authz" if high else "findings" if result.findings else "clean"
    )

    evidence = database.add_evidence(
        execution_id,
        EvidenceCreate(
            evidence_type=EvidenceType.AUTHENTICATED_WORKFLOW_RESULT,
            source="authenticated-workflow",
            path=str(path),
            sha256=sha,
            size_bytes=len(body),
            content_type="application/json",
            step_id="phase6d-authenticated-001",
            tool_name="authenticated-workflow",
            metadata={
                "classification": classification,
                "status": "completed",
                "count": len(result.findings),
                "high_severity_count": high,
                "logins_ok": result.logins_ok,
                "logins_failed": result.logins_failed,
            },
        ),
        actor=actor,
    )

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_COMPLETED,
        actor=actor,
        message=(
            f"[6D] Authenticated workflow completed: "
            f"{len(result.findings)} finding(s), {high} high."
        ),
        details={
            "phase_code": "6D",
            "tool": "authenticated-workflow",
            "findings": len(result.findings),
            "high": high,
            "classification": classification,
            "evidence_id": evidence.evidence_id,
        },
    )

    return TrackedAuthWorkflowResult(
        result=result,
        evidence=evidence,
        evidence_path=str(path),
    )


__all__ = ["TrackedAuthWorkflowResult",
    "result_payload",
    "run_tracked_authenticated_workflow",
]
