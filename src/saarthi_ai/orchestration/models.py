"""Models for the Phase 5 assessment orchestrator."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class OrchestrationStatus(StrEnum):
    """Overall workflow status."""

    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
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
    """Result identifiers produced by one child phase."""

    phase: OrchestrationPhase
    execution_id: str
    evidence_id: str
    evidence_path: str


class InitialReconResult(BaseModel):
    """Results from the first automated 3A and 3B workflow slice."""

    context: OrchestrationContext
    dns: OrchestrationPhaseResult
    subdomains: OrchestrationPhaseResult
