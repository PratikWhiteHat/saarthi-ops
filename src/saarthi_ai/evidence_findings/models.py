"""Redacted models for the Phase 6H evidence-and-findings bundle."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import StrEnum


class EvidenceIntegrity(StrEnum):
    VERIFIED = "verified"
    REJECTED = "rejected"


@dataclass(frozen=True)
class EvidenceReference:
    evidence_id: str
    evidence_type: str
    source: str
    sha256: str | None
    integrity: EvidenceIntegrity
    reason: str = ""

    def as_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "source": self.source,
            "sha256": self.sha256,
            "integrity": self.integrity.value,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ConsolidatedFinding:
    finding_id: str
    source: str
    title: str
    severity: str
    verdict: str
    target: str
    confidence: int | None = None
    impact: str = ""
    remediation: str = ""
    evidence_refs: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "source": self.source,
            "title": self.title,
            "severity": self.severity,
            "verdict": self.verdict,
            "target": self.target,
            "confidence": self.confidence,
            "impact": self.impact,
            "remediation": self.remediation,
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class EvidenceFindingsBundle:
    target: str
    evidence: tuple[EvidenceReference, ...] = ()
    findings: tuple[ConsolidatedFinding, ...] = ()

    @property
    def verified_evidence_count(self) -> int:
        return sum(
            item.integrity is EvidenceIntegrity.VERIFIED
            for item in self.evidence
        )

    @property
    def rejected_evidence_count(self) -> int:
        return sum(
            item.integrity is EvidenceIntegrity.REJECTED
            for item in self.evidence
        )

    @property
    def confirmed_finding_count(self) -> int:
        return sum(
            item.verdict in {"confirmed", "confirmed_impact", "supported"}
            for item in self.findings
        )

    @property
    def evidence_type_counts(self) -> dict[str, int]:
        return dict(Counter(item.evidence_type for item in self.evidence))

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = Counter(item.severity for item in self.findings)
        return dict(counts)

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "evidence_count": len(self.evidence),
            "verified_evidence_count": self.verified_evidence_count,
            "rejected_evidence_count": self.rejected_evidence_count,
            "evidence_type_counts": self.evidence_type_counts,
            "finding_count": len(self.findings),
            "confirmed_finding_count": self.confirmed_finding_count,
            "severity_counts": self.severity_counts,
            "findings": [item.as_dict() for item in self.findings],
            "evidence": [item.as_dict() for item in self.evidence],
        }
