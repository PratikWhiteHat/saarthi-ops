from __future__ import annotations

import pytest

from saarthi_ai.assessments.schemas import (
    AssessmentRequest,
    AssessmentTarget,
    AssetType,
)
from saarthi_ai.execution.models import (
    ExecutionStatus,
    StepExecutionPreviewRequest,
)
from saarthi_ai.execution.service import (
    ExecutionPreviewError,
    preview_step_execution,
)


def build_web_request(
    *,
    active: bool = True,
    intrusive: bool = False,
) -> AssessmentRequest:
    """Create a reusable authorized web assessment."""

    return AssessmentRequest(
        name="Authorized Web VAPT",
        targets=[
            AssessmentTarget(
                asset_type=AssetType.WEB,
                value="https://example.com",
            )
        ],
        authorization_confirmed=True,
        allow_active_testing=active,
        allow_intrusive_testing=intrusive,
    )


def test_passive_step_is_ready_without_approval() -> None:
    """Passive reconnaissance should be ready immediately."""

    result = preview_step_execution(
        StepExecutionPreviewRequest(
            assessment=build_web_request(),
            step_id="recon-001",
        )
    )

    assert result.status is ExecutionStatus.READY
    assert result.selected_tool == "httpx"
    assert result.invocation is not None


def test_active_step_waits_for_approval() -> None:
    """Active discovery must wait for explicit step approval."""

    result = preview_step_execution(
        StepExecutionPreviewRequest(
            assessment=build_web_request(),
            step_id="web-attack-surface-001",
            approval_granted=False,
        )
    )

    assert result.status is ExecutionStatus.AWAITING_APPROVAL
    assert result.invocation is None


def test_active_step_is_ready_after_approval() -> None:
    """Approved active discovery should produce an invocation preview."""

    result = preview_step_execution(
        StepExecutionPreviewRequest(
            assessment=build_web_request(),
            step_id="web-attack-surface-001",
            approval_granted=True,
        )
    )

    assert result.status is ExecutionStatus.READY
    assert result.invocation is not None


def test_unapproved_intrusive_step_is_blocked() -> None:
    """An engagement without intrusive permission must block the step."""

    result = preview_step_execution(
        StepExecutionPreviewRequest(
            assessment=build_web_request(),
            step_id="web-authorization-001",
            approval_granted=True,
        )
    )

    assert result.status is ExecutionStatus.BLOCKED
    assert result.invocation is None


def test_real_execution_is_not_enabled() -> None:
    """This milestone must reject non-dry-run requests."""

    with pytest.raises(ExecutionPreviewError):
        preview_step_execution(
            StepExecutionPreviewRequest(
                assessment=build_web_request(),
                step_id="recon-001",
                dry_run=False,
            )
        )
