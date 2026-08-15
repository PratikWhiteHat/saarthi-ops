"""Models for the Phase 8A assessment report."""

from __future__ import annotations

from pydantic import BaseModel, Field

from saarthi_ai.exploit_confirmation.models import Severity, severity_rank

# CVSS band + priority label per severity, matching the report's priority
# matrix (P1 Critical … P5 Informational).
_PRIORITY_BANDS: dict[Severity, tuple[str, str, str]] = {
    Severity.CRITICAL: ("P1", "Critical", "9.0-10.0"),
    Severity.HIGH: ("P2", "High", "7.0-8.9"),
    Severity.MEDIUM: ("P3", "Medium", "4.0-6.9"),
    Severity.LOW: ("P4", "Low", "0.1-3.9"),
    Severity.INFO: ("P5", "Informational", "0.0"),
}


def priority_band(severity: Severity) -> tuple[str, str, str]:
    """Return (priority, label, cvss_range) for a severity."""

    return _PRIORITY_BANDS[severity]


def severity_label(severity: Severity) -> str:
    """Return the clean, report-facing label for a severity."""

    return _PRIORITY_BANDS[severity][1]


def severity_rating_key() -> list[dict[str, str]]:
    """Return the P1-P5 severity/priority rating key for the report appendix."""

    order = (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    )
    key: list[dict[str, str]] = []
    for severity in order:
        priority, label, cvss_range = _PRIORITY_BANDS[severity]
        key.append(
            {
                "priority": priority,
                "rating": label,
                "cvss_range": cvss_range,
            }
        )
    return key


# Remediation effort buckets keyed on finding-type intent. Config/hygiene fixes
# are quick; input-validation classes are moderate; architectural/authorization
# classes usually need design work.
_LOW_EFFORT_TOKENS = (
    "cookie", "httponly", "secure flag", "samesite", "header", "banner",
    "version disclosure", "tls", "ssl", "clickjack", "x-frame", "cache-control",
    "verbose error", "directory listing", "autocomplete",
)
_HIGH_EFFORT_TOKENS = (
    "authentication", "authorization", "access control", "idor", "bola",
    "bfla", "privilege", "business logic", "account takeover", "sso", "oauth",
    "saml", "session management", "architecture", "deserial",
)


def estimate_effort(title: str, severity: Severity) -> str:
    """Estimate remediation effort (Low/Medium/High) for a finding."""

    haystack = title.lower()
    if any(token in haystack for token in _HIGH_EFFORT_TOKENS):
        return "High"
    if any(token in haystack for token in _LOW_EFFORT_TOKENS):
        return "Low"
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "High"
    if severity is Severity.MEDIUM:
        return "Medium"
    return "Low"


DEFAULT_METHODOLOGY = (
    "The assessment followed Saarthi's evidence-driven, permission-gated "
    "methodology: reconnaissance and asset discovery, safe unauthenticated and "
    "authenticated checks, controlled low-risk validation, approval-gated "
    "attack validation with post-exploitation impact simulation, reversible "
    "cleanup, and evidence-based reporting. Every active action was logged, "
    "scoped to authorized targets, and reversible. Findings below are mapped to "
    "a curated vulnerability library for consistent, repeatable write-ups."
)


class ReportFinding(BaseModel):
    """A single detailed finding rendered into the report."""

    finding_id: str = Field(min_length=1)
    number: int = Field(ge=1)
    title: str
    severity: Severity
    rating_label: str = ""
    exploited_verified: bool = False
    affected_urls: list[str] = Field(default_factory=list)
    description: str = ""
    security_risk: str = ""
    recommendation: str = ""
    references: str = ""
    proof_of_concept: str = ""
    cvss_vector: str = ""
    cvss_score: float = 0.0
    remediation_effort: str = ""
    source: str = Field(
        default="bible-coverage",
        description="Where the finding came from (bible-coverage, 6E, etc.).",
    )
    coverage_status: str = ""

    @property
    def display_rating(self) -> str:
        """Return the detailed-table rating (raw library rating if present)."""

        return self.rating_label or severity_label(self.severity)

    @property
    def summary_rating(self) -> str:
        """Return the clean severity label shown in the summary table."""

        return severity_label(self.severity)

    @property
    def section_id(self) -> str:
        """Return the detailed-finding section id used in the summary table."""

        return f"5.{self.number}"


class RemediationItem(BaseModel):
    """One prioritized entry in the remediation roadmap table."""

    priority: str
    number: int
    title: str
    severity: Severity
    recommendation: str = ""
    effort: str = "Medium"
    section_id: str = ""


class EngagementMeta(BaseModel):
    """Vendor/engagement metadata filled into the report template."""

    org_name: str = "ORGNAME"
    app_name: str = "APPNAME"
    company: str = "Your Security Team"
    company_short: str = ""
    author: str = "Saarthi Operator"
    reviewer: str = ""
    classification: str = "Confidential"
    status_label: str = "FINAL"
    test_type: str = "Gray"
    report_date: str = ""
    scope_urls: list[str] = Field(default_factory=list)
    document_ref: str = ""
    version: str = "1.0"

    def resolved_company_short(self) -> str:
        return self.company_short or self.company


class ReportModel(BaseModel):
    """The complete, renderable assessment report."""

    engagement: EngagementMeta
    orchestration_id: str = ""
    target: str = ""
    executive_summary: str = ""
    overall_posture: str = "Needs Improvement"
    findings: list[ReportFinding] = Field(default_factory=list)
    methodology: str = ""
    tools_used: list[str] = Field(default_factory=list)
    ai_narrative_used: bool = False

    @property
    def severity_counts(self) -> dict[str, int]:
        """Count findings per severity label (all five levels present)."""

        counts = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def highest_severity(self) -> Severity:
        """Return the worst severity across findings (INFO if none)."""

        worst = Severity.INFO
        for finding in self.findings:
            if severity_rank(finding.severity) > severity_rank(worst):
                worst = finding.severity
        return worst

    @property
    def sorted_findings(self) -> list[ReportFinding]:
        """Return findings ordered worst-severity-first, then by number."""

        return sorted(
            self.findings,
            key=lambda f: (-severity_rank(f.severity), f.number),
        )

    @property
    def remediation_roadmap(self) -> list[RemediationItem]:
        """Return a prioritized remediation roadmap (worst severity first)."""

        roadmap: list[RemediationItem] = []
        for finding in self.sorted_findings:
            priority = priority_band(finding.severity)[0]
            roadmap.append(
                RemediationItem(
                    priority=priority,
                    number=finding.number,
                    title=finding.title,
                    severity=finding.severity,
                    recommendation=finding.recommendation,
                    effort=finding.remediation_effort
                    or estimate_effort(finding.title, finding.severity),
                    section_id=finding.section_id,
                )
            )
        return roadmap

    def as_dict(self) -> dict:
        """Return a JSON-serializable representation."""

        return self.model_dump(mode="json")


__all__ = [
    "DEFAULT_METHODOLOGY",
    "EngagementMeta",
    "RemediationItem",
    "ReportFinding",
    "ReportModel",
    "estimate_effort",
    "priority_band",
    "severity_label",
    "severity_rating_key",
]
