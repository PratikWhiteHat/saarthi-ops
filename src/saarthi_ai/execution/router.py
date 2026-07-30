from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from saarthi_ai.assessments.planner import (
    UnsupportedPlannerTargetError,
)
from saarthi_ai.assessments.scope import ScopeValidationError
from saarthi_ai.execution.models import (
    StepExecutionPreviewRequest,
    StepExecutionPreviewResponse,
)
from saarthi_ai.execution.service import (
    ExecutionPreviewError,
    preview_step_execution,
)

router = APIRouter(
    prefix="/v1/assessments/execution",
    tags=["execution"],
)


@router.post(
    "/preview",
    response_model=StepExecutionPreviewResponse,
    status_code=status.HTTP_200_OK,
)
async def preview_execution_endpoint(
    request: StepExecutionPreviewRequest,
) -> StepExecutionPreviewResponse:
    """Preview a controlled assessment step without executing a tool."""

    try:
        return preview_step_execution(request)
    except (
        ExecutionPreviewError,
        ScopeValidationError,
        UnsupportedPlannerTargetError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
