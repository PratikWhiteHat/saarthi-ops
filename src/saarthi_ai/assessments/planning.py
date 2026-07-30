from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from saarthi_ai.assessments.schemas import AssetType, ValidatedTarget


class PlanPhase(StrEnum):
    """Phases used in a Saarthi VAPT assessment plan."""

    SCOPE = "scope"
    RECONNAISSANCE = "reconnaissance"
    ATTACK_SURFACE = "attack_surface"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input_validation"
    CONFIGURATION = "configuration"
    EVIDENCE = "evidence"
    REPORTING = "reporting"


class ExecutionLevel(StrEnum):
    """Execution levels controlled by assessment authorization."""

    PASSIVE = "passive"
    ACTIVE = "active"
    INTRUSIVE = "intrusive"


class PlanStep(BaseModel):
    """One structured step in a VAPT assessment plan."""

    id: str = Field(min_length=1, max_length=100)
    phase: PlanPhase
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=10, max_length=2_000)
    execution_level: ExecutionLevel
    approval_required: bool
    enabled: bool
    blocked_reason: str | None = None
    target_values: list[str]
    tool_candidates: list[str] = Field(default_factory=list)
    evidence_requirements: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)


class AssessmentPlanResponse(BaseModel):
    """Structured VAPT assessment plan."""

    assessment_name: str
    plan_version: str
    asset_types: list[AssetType]
    targets: list[ValidatedTarget]
    permitted_execution_levels: list[str]
    rate_limit_per_second: int
    steps: list[PlanStep]
