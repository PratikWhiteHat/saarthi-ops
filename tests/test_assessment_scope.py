from __future__ import annotations

import pytest
from pydantic import ValidationError

from saarthi_ai.assessments.schemas import (
    AssessmentRequest,
    AssessmentTarget,
    AssetType,
)
from saarthi_ai.assessments.scope import (
    ScopeValidationError,
    validate_assessment,
)


def test_validate_web_assessment() -> None:
    """An authorized web target should be normalized."""

    request = AssessmentRequest(
        name="Authorized Web VAPT",
        targets=[
            AssessmentTarget(
                asset_type=AssetType.WEB,
                value="https://Example.com",
            )
        ],
        authorization_confirmed=True,
        allow_active_testing=True,
    )

    result = validate_assessment(request)

    assert result.valid is True
    assert result.targets[0].normalized_value == ("https://example.com/")
    assert result.permitted_execution_levels == [
        "passive",
        "active",
    ]


def test_authorization_is_required() -> None:
    """Assessment creation must require authorization."""

    with pytest.raises(ValidationError):
        AssessmentRequest(
            name="Unauthorized Test",
            targets=[
                AssessmentTarget(
                    asset_type=AssetType.IP,
                    value="192.0.2.10",
                )
            ],
            authorization_confirmed=False,
        )


def test_intrusive_testing_requires_active_approval() -> None:
    """Intrusive approval cannot exist without active approval."""

    with pytest.raises(ValidationError):
        AssessmentRequest(
            name="Invalid Testing Policy",
            targets=[
                AssessmentTarget(
                    asset_type=AssetType.API,
                    value="https://api.example.com",
                )
            ],
            authorization_confirmed=True,
            allow_active_testing=False,
            allow_intrusive_testing=True,
        )


def test_ip_address_is_normalized() -> None:
    """Individual IP targets should be validated."""

    request = AssessmentRequest(
        name="Authorized Network VAPT",
        targets=[
            AssessmentTarget(
                asset_type=AssetType.IP,
                value="192.0.2.10",
            )
        ],
        authorization_confirmed=True,
    )

    result = validate_assessment(request)

    assert result.targets[0].normalized_value == "192.0.2.10"


def test_invalid_android_file_is_rejected() -> None:
    """Android assessments must receive an APK file."""

    request = AssessmentRequest(
        name="Android VAPT",
        targets=[
            AssessmentTarget(
                asset_type=AssetType.ANDROID,
                value="application.zip",
            )
        ],
        authorization_confirmed=True,
    )

    with pytest.raises(ScopeValidationError):
        validate_assessment(request)


def test_excluded_target_is_rejected() -> None:
    """A target explicitly listed as excluded must be blocked."""

    request = AssessmentRequest(
        name="Scoped Web VAPT",
        targets=[
            AssessmentTarget(
                asset_type=AssetType.WEB,
                value="https://excluded.example.com",
            )
        ],
        authorization_confirmed=True,
        excluded_targets=[
            "https://excluded.example.com",
        ],
    )

    with pytest.raises(ScopeValidationError):
        validate_assessment(request)
