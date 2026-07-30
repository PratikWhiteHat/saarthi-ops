from __future__ import annotations

import pytest

from saarthi_ai.assessments.planner import (
    UnsupportedPlannerTargetError,
    build_assessment_plan,
)
from saarthi_ai.assessments.schemas import (
    AssessmentRequest,
    AssessmentTarget,
    AssetType,
)
from saarthi_ai.assessments.scope import validate_assessment


def test_web_plan_blocks_unapproved_intrusive_steps() -> None:
    """Intrusive web steps must be disabled without approval."""

    request = AssessmentRequest(
        name="Web VAPT",
        targets=[
            AssessmentTarget(
                asset_type=AssetType.WEB,
                value="https://example.com",
            )
        ],
        authorization_confirmed=True,
        allow_active_testing=True,
        allow_intrusive_testing=False,
    )

    validated = validate_assessment(request)
    plan = build_assessment_plan(request, validated)

    authorization_step = next(step for step in plan.steps if step.id == "web-authorization-001")

    assert authorization_step.enabled is False
    assert authorization_step.blocked_reason is not None


def test_api_plan_enables_intrusive_steps_when_approved() -> None:
    """Approved intrusive API steps should be enabled."""

    request = AssessmentRequest(
        name="API VAPT",
        targets=[
            AssessmentTarget(
                asset_type=AssetType.API,
                value="https://api.example.com",
            )
        ],
        authorization_confirmed=True,
        allow_active_testing=True,
        allow_intrusive_testing=True,
    )

    validated = validate_assessment(request)
    plan = build_assessment_plan(request, validated)

    object_authorization_step = next(
        step for step in plan.steps if step.id == "api-object-authorization-001"
    )

    assert object_authorization_step.enabled is True
    assert object_authorization_step.approval_required is True


def test_planner_rejects_network_target() -> None:
    """The current planner should reject unsupported IP targets."""

    request = AssessmentRequest(
        name="Network VAPT",
        targets=[
            AssessmentTarget(
                asset_type=AssetType.IP,
                value="192.0.2.10",
            )
        ],
        authorization_confirmed=True,
    )

    validated = validate_assessment(request)

    with pytest.raises(UnsupportedPlannerTargetError):
        build_assessment_plan(request, validated)
