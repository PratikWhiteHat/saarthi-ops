from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from saarthi_ai.assessments.planner import (
    UnsupportedPlannerTargetError,
    build_assessment_plan,
)
from saarthi_ai.assessments.planning import AssessmentPlanResponse
from saarthi_ai.assessments.schemas import (
    AssessmentRequest,
    AssessmentValidationResponse,
)
from saarthi_ai.assessments.scope import (
    ScopeValidationError,
    validate_assessment,
)

router = APIRouter(
    prefix="/v1/assessments",
    tags=["assessments"],
)


@router.post(
    "/validate",
    response_model=AssessmentValidationResponse,
    status_code=status.HTTP_200_OK,
)
async def validate_assessment_endpoint(
    request: AssessmentRequest,
) -> AssessmentValidationResponse:
    """Validate and normalize an authorized assessment request."""

    try:
        return validate_assessment(request)
    except ScopeValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.post(
    "/plan",
    response_model=AssessmentPlanResponse,
    status_code=status.HTTP_200_OK,
)
async def create_assessment_plan_endpoint(
    request: AssessmentRequest,
) -> AssessmentPlanResponse:
    """Validate an assessment and create its Web/API VAPT plan."""

    try:
        validated = validate_assessment(request)
        return build_assessment_plan(request, validated)
    except (
        ScopeValidationError,
        UnsupportedPlannerTargetError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
