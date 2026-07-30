from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from saarthi_ai.assessments.planning import ExecutionLevel
from saarthi_ai.assessments.schemas import AssessmentRequest, AssetType


class ExecutionStatus(StrEnum):
    """Possible states for a planned assessment step."""

    READY = "ready"
    AWAITING_APPROVAL = "awaiting_approval"
    BLOCKED = "blocked"


class ToolDefinition(BaseModel):
    """A controlled tool registered with Saarthi."""

    name: str
    description: str
    supported_asset_types: list[AssetType]
    timeout_seconds: int = Field(ge=1, le=3_600)
    supports_dry_run: bool = True


class ToolInvocationPreview(BaseModel):
    """Structured tool invocation that has not been executed."""

    tool: str
    step_id: str
    execution_level: ExecutionLevel
    target_values: list[str]
    arguments: dict[str, Any]
    timeout_seconds: int
    rate_limit_per_second: int


class StepExecutionPreviewRequest(BaseModel):
    """Request to evaluate a planned assessment step."""

    assessment: AssessmentRequest
    step_id: str = Field(min_length=1, max_length=100)
    approval_granted: bool = False
    dry_run: bool = True


class StepExecutionPreviewResponse(BaseModel):
    """Approval and invocation status for one assessment step."""

    execution_id: str
    status: ExecutionStatus
    assessment_name: str
    plan_version: str
    step_id: str
    step_title: str
    enabled: bool
    approval_required: bool
    approval_granted: bool
    selected_tool: str | None
    invocation: ToolInvocationPreview | None
    evidence_requirements: list[str]
    blocked_reason: str | None
