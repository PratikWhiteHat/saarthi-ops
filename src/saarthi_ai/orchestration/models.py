"""Models for the Phase 5 assessment orchestrator."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class OrchestrationStatus(StrEnum):
    """Overall workflow status."""

    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class OrchestrationPhaseOutcome(StrEnum):
    """Outcome recorded for one orchestration phase."""

    COMPLETED = "completed"
    NOT_APPLICABLE = "not_applicable"
    SKIPPED = "skipped"
    FAILED = "failed"


class OrchestrationPhase(StrEnum):
    """Supported automatic workflow phases."""

    DNS = "3A"
    SUBDOMAINS = "3B"
    HTTP_INTELLIGENCE = "3C"
    CRAWL = "3D"
    JAVASCRIPT = "3E"
    SECURITY_HEADERS = "4A-security-headers"
    CORS = "4A-cors"
    BLIND_VALIDATION = "4B"
    OAST_MANAGER = "4C"
    CONFIRMATION = "4D"
    BIBLE_COVERAGE = "4E-bible-coverage"
    ATTACK_HYPOTHESIS = "6A"
    NUCLEI = "6C-nuclei"
    NUCLEI_PREVIEW = "6C-nuclei-preview"
    SQLMAP_PREVIEW = "6C-sqlmap-preview"
    SAFE_VALIDATOR = "6C-safe-validator"
    AUTHENTICATED_WORKFLOW = "6D-authenticated-workflow"
    EXPLOIT_CONFIRMATION = "6E-exploit-confirmation"
    POST_EXPLOITATION = "6F-post-exploitation"
    CLEANUP = "6G-cleanup-rollback"
    REPORT = "8A-report"


class OrchestrationContext(BaseModel):
    """Persistent identifiers shared by parent and child executions."""

    orchestration_id: str = Field(min_length=1, max_length=200)
    parent_execution_id: str = Field(min_length=1, max_length=200)
    target_url: str = Field(min_length=1, max_length=2_048)
    target_domain: str = Field(min_length=1, max_length=253)
    project_id: str | None = None
    project_slug: str | None = None
    status: OrchestrationStatus = OrchestrationStatus.CREATED


class OrchestrationPhaseResult(BaseModel):
    """Structured outcome produced by one orchestration phase."""

    phase: OrchestrationPhase
    outcome: OrchestrationPhaseOutcome = (
        OrchestrationPhaseOutcome.COMPLETED
    )
    required: bool = True

    execution_id: str | None = None
    evidence_id: str | None = None
    evidence_path: str | None = None

    reason: str | None = Field(
        default=None,
        max_length=2_000,
    )
    error_summary: str | None = Field(
        default=None,
        max_length=2_000,
    )
    metrics: dict[str, int | float | str | bool | None] = Field(
        default_factory=dict,
    )

    @property
    def completed(self) -> bool:
        """Return whether this phase completed successfully."""

        return self.outcome is OrchestrationPhaseOutcome.COMPLETED

    @property
    def skipped(self) -> bool:
        """Return whether this phase was intentionally skipped."""

        return self.outcome is OrchestrationPhaseOutcome.SKIPPED

    @property
    def not_applicable(self) -> bool:
        """Return whether prerequisites made this phase inapplicable."""

        return (
            self.outcome
            is OrchestrationPhaseOutcome.NOT_APPLICABLE
        )

    @property
    def failed(self) -> bool:
        """Return whether this phase failed."""

        return self.outcome is OrchestrationPhaseOutcome.FAILED


def calculate_orchestration_status(
    phase_results: list[OrchestrationPhaseResult],
) -> OrchestrationStatus:
    """Calculate the overall workflow status from child phase outcomes."""

    if not phase_results:
        return OrchestrationStatus.FAILED

    required_failed = any(
        result.required and result.failed
        for result in phase_results
    )

    if required_failed:
        return OrchestrationStatus.FAILED

    optional_incomplete = any(
        not result.required
        and result.outcome
        in {
            OrchestrationPhaseOutcome.SKIPPED,
            OrchestrationPhaseOutcome.FAILED,
        }
        for result in phase_results
    )

    if optional_incomplete:
        return OrchestrationStatus.PARTIAL

    return OrchestrationStatus.COMPLETED


class InitialReconResult(BaseModel):
    """Results from the first automated 3A and 3B workflow slice."""

    context: OrchestrationContext
    dns: OrchestrationPhaseResult
    subdomains: OrchestrationPhaseResult


class ReconPipelineResult(BaseModel):
    """Results from the automated Phase 3A through 3C workflow."""

    context: OrchestrationContext
    dns: OrchestrationPhaseResult
    subdomains: OrchestrationPhaseResult
    http_intelligence: OrchestrationPhaseResult


class DiscoveryPipelineResult(BaseModel):
    """Results from the automated Phase 3A through 3D workflow."""

    context: OrchestrationContext
    dns: OrchestrationPhaseResult
    subdomains: OrchestrationPhaseResult
    http_intelligence: OrchestrationPhaseResult
    crawl: OrchestrationPhaseResult


class IntelligencePipelineResult(BaseModel):
    """Results from the automated Phase 3A through 3E workflow."""

    context: OrchestrationContext
    dns: OrchestrationPhaseResult
    subdomains: OrchestrationPhaseResult
    http_intelligence: OrchestrationPhaseResult
    crawl: OrchestrationPhaseResult
    javascript: OrchestrationPhaseResult


class AssessmentPipelineResult(BaseModel):
    """Results from the automated Phase 3A through 4A workflow."""

    context: OrchestrationContext
    dns: OrchestrationPhaseResult
    subdomains: OrchestrationPhaseResult
    http_intelligence: OrchestrationPhaseResult
    crawl: OrchestrationPhaseResult
    javascript: OrchestrationPhaseResult
    security_headers: OrchestrationPhaseResult
    cors: OrchestrationPhaseResult

    @property
    def phase_results(self) -> list[OrchestrationPhaseResult]:
        """Return all phase outcomes in execution order."""

        return [
            self.dns,
            self.subdomains,
            self.http_intelligence,
            self.crawl,
            self.javascript,
            self.security_headers,
            self.cors,
        ]

    @property
    def calculated_status(self) -> OrchestrationStatus:
        """Calculate the overall status from the phase outcomes."""

        return calculate_orchestration_status(self.phase_results)


class Phase6ChainResult(BaseModel):
    """Results from the permission-gated Phase 6C safe chain."""

    context: OrchestrationContext
    phase_results: list[OrchestrationPhaseResult]

    @property
    def calculated_status(self) -> OrchestrationStatus:
        """Calculate the aggregate status of the Phase 6C chain."""

        return calculate_orchestration_status(self.phase_results)
