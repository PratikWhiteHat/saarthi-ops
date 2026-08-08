from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ExecutionState(StrEnum):
    """Lifecycle states for a Saarthi assessment execution."""

    CREATED = "created"
    VALIDATED = "validated"
    PLANNED = "planned"
    AWAITING_APPROVAL = "awaiting_approval"
    RUNNING = "running"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AuditEventType(StrEnum):
    """Auditable events generated during an execution."""

    EXECUTION_CREATED = "execution_created"
    STATE_CHANGED = "state_changed"
    APPROVAL_RECORDED = "approval_recorded"
    TOOL_PREPARED = "tool_prepared"
    TOOL_STARTED = "tool_started"
    TOOL_OUTPUT = "tool_output"
    TOOL_COMPLETED = "tool_completed"
    TOOL_FAILED = "tool_failed"
    EVIDENCE_ADDED = "evidence_added"
    FINDING_CREATED = "finding_created"
    EXECUTION_CANCELLED = "execution_cancelled"


class EvidenceType(StrEnum):
    """Evidence categories stored in the evidence catalog."""

    HTTP_METADATA = "http_metadata"
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    DNS_RESULT = "dns_result"
    SUBDOMAIN_RESULT = "subdomain_result"
    HTTP_INTELLIGENCE_RESULT = "http_intelligence_result"
    CRAWL_RESULT = "crawl_result"
    JAVASCRIPT_INTELLIGENCE_RESULT = "javascript_intelligence_result"
    DIRECT_CHECK_RESULT = "direct_check_result"
    BLIND_VALIDATION_RESULT = "blind_validation_result"
    OAST_OBSERVATION = "oast_observation"
    CONFIRMATION_RESULT = "confirmation_result"
    ATTACK_HYPOTHESIS_SET = "attack_hypothesis_set"
    CONTROLLED_VALIDATION_PLAN = "controlled_validation_plan"
    CONTROLLED_VALIDATION_OBSERVATION = (
        "controlled_validation_observation"
    )
    CONTROLLED_NUCLEI_PREVIEW = "controlled_nuclei_preview"
    CONTROLLED_NUCLEI_PREPARATION = (
        "controlled_nuclei_preparation"
    )
    CONTROLLED_NUCLEI_EXECUTION = (
        "controlled_nuclei_execution"
    )
    CONTROLLED_SQLMAP_PREVIEW = "controlled_sqlmap_preview"
    SQLMAP_HANDOFF_MANIFEST = "sqlmap_handoff_manifest"
    SQLMAP_EXTERNAL_RESULT = "sqlmap_external_result"
    AUTHENTICATED_WORKFLOW_RESULT = "authenticated_workflow_result"
    UPLOAD_VALIDATION_PLAN = "upload_validation_plan"
    UPLOAD_EXTERNAL_RESULT = "upload_external_result"
    TLS_RESULT = "tls_result"
    TOOL_OUTPUT = "tool_output"
    SCREENSHOT = "screenshot"
    FILE = "file"
    NOTE = "note"


class ExecutionCreate(BaseModel):
    """Input used to create an assessment execution."""

    assessment_name: str = Field(min_length=1, max_length=200)
    plan_version: str = Field(default="0.1.0", min_length=1, max_length=50)
    asset_types: list[str] = Field(min_length=1)
    targets: list[str] = Field(min_length=1)
    authorization_confirmed: bool
    active_testing_allowed: bool = False
    intrusive_testing_allowed: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExecutionRecord(BaseModel):
    """Persistent assessment execution record."""

    execution_id: str
    assessment_name: str
    plan_version: str
    state: ExecutionState
    asset_types: list[str]
    targets: list[str]
    authorization_confirmed: bool
    active_testing_allowed: bool
    intrusive_testing_allowed: bool
    metadata: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None
    failure_reason: str | None = None


class StateTransitionRequest(BaseModel):
    """Requested execution-state transition."""

    new_state: ExecutionState
    actor: str = Field(default="system", min_length=1, max_length=100)
    reason: str | None = Field(default=None, max_length=1_000)


class AuditEventRecord(BaseModel):
    """Immutable execution audit event."""

    event_id: str
    execution_id: str
    event_type: AuditEventType
    actor: str
    message: str
    details: dict[str, Any]
    created_at: datetime


class EvidenceCreate(BaseModel):
    """Input used to register evidence."""

    evidence_type: EvidenceType
    source: str = Field(min_length=1, max_length=200)
    path: str = Field(min_length=1, max_length=2_048)
    sha256: str | None = Field(default=None, max_length=64)
    size_bytes: int | None = Field(default=None, ge=0)
    content_type: str | None = Field(default=None, max_length=200)
    step_id: str | None = Field(default=None, max_length=100)
    tool_name: str | None = Field(default=None, max_length=100)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvidenceRecord(BaseModel):
    """Persistent evidence-catalog entry."""

    evidence_id: str
    execution_id: str
    evidence_type: EvidenceType
    source: str
    path: str
    sha256: str | None
    size_bytes: int | None
    content_type: str | None
    step_id: str | None
    tool_name: str | None
    metadata: dict[str, Any]
    created_at: datetime


def utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp."""

    return datetime.now(UTC)
