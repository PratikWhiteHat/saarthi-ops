from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, field_validator, model_validator


class AssetType(StrEnum):
    """Asset types supported by the assessment intake engine."""

    WEB = "web"
    API = "api"
    IP = "ip"
    CIDR = "cidr"
    ANDROID = "android"
    IOS = "ios"


class AssessmentTarget(BaseModel):
    """One authorized assessment target."""

    asset_type: AssetType
    value: str = Field(min_length=1, max_length=2_048)
    label: str | None = Field(default=None, max_length=100)

    @field_validator("value")
    @classmethod
    def clean_value(cls, value: str) -> str:
        """Remove unnecessary whitespace from a target."""

        cleaned = value.strip()

        if not cleaned:
            raise ValueError("Target value cannot be empty.")

        return cleaned


class AssessmentRequest(BaseModel):
    """Authorized VAPT assessment intake request."""

    name: str = Field(min_length=3, max_length=150)
    targets: list[AssessmentTarget] = Field(
        min_length=1,
        max_length=100,
    )
    authorization_confirmed: bool
    allow_active_testing: bool = False
    allow_intrusive_testing: bool = False
    rate_limit_per_second: int = Field(default=2, ge=1, le=20)
    excluded_targets: list[str] = Field(
        default_factory=list,
        max_length=100,
    )
    notes: str | None = Field(default=None, max_length=5_000)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        """Normalize the assessment name."""

        return value.strip()

    @field_validator("excluded_targets")
    @classmethod
    def clean_exclusions(cls, values: list[str]) -> list[str]:
        """Normalize and remove empty exclusion entries."""

        return sorted({value.strip() for value in values if value.strip()})

    @model_validator(mode="after")
    def validate_authorization(self) -> AssessmentRequest:
        """Enforce authorization and testing-level relationships."""

        if not self.authorization_confirmed:
            raise ValueError("Explicit authorization must be confirmed.")

        if self.allow_intrusive_testing and not self.allow_active_testing:
            raise ValueError("Intrusive testing requires active testing approval.")

        return self


class ValidatedTarget(BaseModel):
    """A normalized target accepted by the scope engine."""

    asset_type: AssetType
    original_value: str
    normalized_value: str
    label: str | None = None


class AssessmentValidationResponse(BaseModel):
    """Result returned by the assessment scope engine."""

    valid: bool
    assessment_name: str
    targets: list[ValidatedTarget]
    excluded_targets: list[str]
    permitted_execution_levels: list[str]
    rate_limit_per_second: int
