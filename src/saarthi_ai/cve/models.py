"""Small, explicit records for locally cached vulnerability intelligence."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    description: str
    published: str | None
    modified: str | None
    cvss_score: float | None
    cvss_severity: str | None
    cvss_version: str | None
    exploited_in_wild: bool = False
    kev_date_added: str | None = None
    kev_due_date: str | None = None
    kev_required_action: str | None = None
    ransomware_use: str | None = None
    exploit_reference: bool = False


@dataclass(frozen=True)
class CpeMatch:
    cve_id: str
    criteria: str
    vulnerable: bool
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None
    complex_configuration: bool = False


@dataclass(frozen=True)
class CveCandidate:
    cve: CveRecord
    observed_cpe: str
    matching_criteria: str
    priority_score: int
    applicability: str
    reason: str


__all__ = ["CpeMatch", "CveCandidate", "CveRecord"]
