"""Deterministic Phase 6H consolidation over persisted evidence records."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path

from saarthi_ai.evidence_findings.models import (
    ConsolidatedFinding,
    EvidenceFindingsBundle,
    EvidenceIntegrity,
    EvidenceReference,
)
from saarthi_ai.persistence.models import EvidenceRecord, EvidenceType

MAX_EVIDENCE_BYTES = 20_000_000


def _verified_payload(record: EvidenceRecord) -> tuple[dict | None, str]:
    if not record.sha256:
        return None, "SHA-256 is missing"
    path = Path(record.path)
    try:
        if not path.is_file():
            return None, "evidence path is not a regular file"
        if path.stat().st_size > MAX_EVIDENCE_BYTES:
            return None, "evidence exceeds the Phase 6H size limit"
        body = path.read_bytes()
    except OSError as exc:
        return None, f"evidence could not be read: {exc}"
    if hashlib.sha256(body).hexdigest() != record.sha256:
        return None, "SHA-256 mismatch"
    if record.content_type != "application/json":
        return {}, ""
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"invalid JSON: {exc}"
    if not isinstance(payload, dict):
        return None, "JSON root is not an object"
    return payload, ""


def _text(value: object, limit: int = 1_000) -> str:
    return str(value or "")[:limit]


def _tuple_strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(_text(item, 200) for item in value[:30] if item)


def _exploit_findings(payload: dict, evidence_id: str) -> list[ConsolidatedFinding]:
    output: list[ConsolidatedFinding] = []
    for item in payload.get("findings", []) or []:
        if not isinstance(item, dict):
            continue
        proof = _tuple_strings(item.get("proof"))
        output.append(
            ConsolidatedFinding(
                finding_id=_text(item.get("finding_id"), 200),
                source="phase-6e",
                title=_text(item.get("kind"), 200),
                severity=_text(item.get("severity"), 30) or "info",
                verdict=_text(item.get("verdict"), 60) or "unconfirmed",
                target=_text(item.get("target"), 2_048),
                impact="; ".join(proof)[:1_000],
                evidence_refs=(evidence_id,),
            )
        )
    return output


def _ai_findings(payload: dict, evidence_id: str, target: str) -> list[ConsolidatedFinding]:
    output: list[ConsolidatedFinding] = []
    for item in payload.get("findings", []) or []:
        if not isinstance(item, dict):
            continue
        references = _tuple_strings(item.get("evidence_refs"))
        output.append(
            ConsolidatedFinding(
                finding_id=_text(item.get("finding_id"), 200),
                source="ai-quality-review",
                title=_text(item.get("title"), 300),
                severity=_text(item.get("severity"), 30) or "info",
                verdict=(
                    _text(item.get("final_disposition"), 60)
                    or _text(item.get("verdict"), 60)
                    or "unconfirmed"
                ),
                target=target,
                confidence=(
                    int(item["confidence"])
                    if isinstance(item.get("confidence"), int | float)
                    else None
                ),
                impact=_text(item.get("statement"), 1_000),
                remediation=_text(item.get("remediation"), 1_000),
                evidence_refs=tuple(dict.fromkeys((evidence_id, *references))),
            )
        )
    return output


def build_evidence_findings_bundle(
    *,
    target: str,
    evidence_records: Iterable[EvidenceRecord],
) -> EvidenceFindingsBundle:
    """Verify evidence and consolidate structured findings without raw data."""

    references: list[EvidenceReference] = []
    findings: list[ConsolidatedFinding] = []
    seen_findings: set[tuple[str, str]] = set()

    for record in evidence_records:
        payload, reason = _verified_payload(record)
        integrity = (
            EvidenceIntegrity.VERIFIED
            if payload is not None
            else EvidenceIntegrity.REJECTED
        )
        references.append(
            EvidenceReference(
                evidence_id=record.evidence_id,
                evidence_type=record.evidence_type.value,
                source=record.source,
                sha256=record.sha256,
                integrity=integrity,
                reason=reason,
            )
        )
        if payload is None:
            continue
        candidates: list[ConsolidatedFinding] = []
        if record.evidence_type is EvidenceType.EXPLOIT_CONFIRMATION_RESULT:
            candidates = _exploit_findings(payload, record.evidence_id)
        elif record.evidence_type is EvidenceType.AI_QUALITY_ANALYSIS:
            candidates = _ai_findings(payload, record.evidence_id, target)
        for finding in candidates:
            key = (finding.source, finding.finding_id)
            if not finding.finding_id or key in seen_findings:
                continue
            seen_findings.add(key)
            findings.append(finding)

    return EvidenceFindingsBundle(
        target=target,
        evidence=tuple(references),
        findings=tuple(findings),
    )


__all__ = ["build_evidence_findings_bundle"]
