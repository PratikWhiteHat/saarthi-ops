from __future__ import annotations

from uuid import uuid4

from saarthi_ai.assessments.planner import build_assessment_plan
from saarthi_ai.assessments.planning import PlanStep
from saarthi_ai.assessments.scope import validate_assessment
from saarthi_ai.execution.models import (
    ExecutionStatus,
    StepExecutionPreviewRequest,
    StepExecutionPreviewResponse,
    ToolDefinition,
    ToolInvocationPreview,
)
from saarthi_ai.execution.registry import TOOL_REGISTRY


class ExecutionPreviewError(ValueError):
    """Raised when a step cannot be prepared for execution."""


def find_step(
    steps: list[PlanStep],
    step_id: str,
) -> PlanStep:
    """Find a planned step by its identifier."""

    for step in steps:
        if step.id == step_id:
            return step

    raise ExecutionPreviewError(f"Assessment plan does not contain step '{step_id}'.")


def select_tool(
    step: PlanStep,
    asset_types: set[str],
) -> ToolDefinition | None:
    """Choose the first registered tool compatible with the step."""

    if not step.tool_candidates:
        return None

    for tool_name in step.tool_candidates:
        tool = TOOL_REGISTRY.get(tool_name)

        if tool is None:
            continue

        supported_types = {asset_type.value for asset_type in tool.supported_asset_types}

        if asset_types & supported_types:
            return tool

    raise ExecutionPreviewError(f"No registered compatible tool was found for step '{step.id}'.")


def determine_status(
    step: PlanStep,
    *,
    approval_granted: bool,
) -> tuple[ExecutionStatus, str | None]:
    """Determine whether a step is blocked, awaiting approval, or ready."""

    if not step.enabled:
        return (
            ExecutionStatus.BLOCKED,
            step.blocked_reason or "The assessment step is disabled.",
        )

    if step.approval_required and not approval_granted:
        return (
            ExecutionStatus.AWAITING_APPROVAL,
            "Explicit approval is required before this step can run.",
        )

    return ExecutionStatus.READY, None


def build_invocation(
    step: PlanStep,
    tool: ToolDefinition,
    *,
    rate_limit_per_second: int,
) -> ToolInvocationPreview:
    """Create a structured invocation without running a command."""

    return ToolInvocationPreview(
        tool=tool.name,
        step_id=step.id,
        execution_level=step.execution_level,
        target_values=step.target_values,
        arguments={
            "targets": step.target_values,
            "rate_limit_per_second": rate_limit_per_second,
            "preserve_evidence": True,
            "destructive_testing": False,
        },
        timeout_seconds=tool.timeout_seconds,
        rate_limit_per_second=rate_limit_per_second,
    )


def preview_step_execution(
    request: StepExecutionPreviewRequest,
) -> StepExecutionPreviewResponse:
    """Validate and preview one controlled VAPT assessment step."""

    if not request.dry_run:
        raise ExecutionPreviewError(
            "Real tool execution is not enabled in this milestone. Use dry_run=true."
        )

    validated = validate_assessment(request.assessment)
    plan = build_assessment_plan(request.assessment, validated)
    step = find_step(plan.steps, request.step_id)

    asset_types = {asset_type.value for asset_type in plan.asset_types}

    tool = select_tool(step, asset_types)
    status, blocked_reason = determine_status(
        step,
        approval_granted=request.approval_granted,
    )

    invocation: ToolInvocationPreview | None = None

    if status is ExecutionStatus.READY and tool is not None:
        invocation = build_invocation(
            step,
            tool,
            rate_limit_per_second=plan.rate_limit_per_second,
        )

    return StepExecutionPreviewResponse(
        execution_id=f"preview-{uuid4()}",
        status=status,
        assessment_name=plan.assessment_name,
        plan_version=plan.plan_version,
        step_id=step.id,
        step_title=step.title,
        enabled=step.enabled,
        approval_required=step.approval_required,
        approval_granted=request.approval_granted,
        selected_tool=tool.name if tool is not None else None,
        invocation=invocation,
        evidence_requirements=step.evidence_requirements,
        blocked_reason=blocked_reason,
    )
