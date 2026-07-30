from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

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
    """Validate an authorized assessment request and normalize its targets."""

    try:
        return validate_assessment(request)
    except ScopeValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
