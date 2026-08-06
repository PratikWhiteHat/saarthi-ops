"""Domain models for Phase 6 controlled attack validation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ControlledValidationRisk(StrEnum):
    """Safety classification assigned to a validation action."""

    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    DESTRUCTIVE = "destructive"


class ControlledValidationDecision(StrEnum):
    """Policy decision for a controlled validation request."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    MANUAL_ONLY = "manual_only"


class ControlledValidationAction(StrEnum):
    """Supported Phase 6 validation actions.

    Phase 6B defines policy classifications only. It performs no network
    requests, payload execution, subprocess execution, or state changes.
    """

    RESPONSE_DIFFERENTIAL = "response_differential"
    INPUT_HANDLING_OBSERVATION = "input_handling_observation"
    CLICKJACKING_HEADER_VALIDATION = (
        "clickjacking_header_validation"
    )
    HTTP_PARAMETER_SURFACE_VALIDATION = (
        "http_parameter_surface_validation"
    )
    SESSION_COOKIE_ATTRIBUTE_VALIDATION = (
        "session_cookie_attribute_validation"
    )
    CSRF_PROTECTION_SURFACE_VALIDATION = (
        "csrf_protection_surface_validation"
    )
    API_DATA_EXPOSURE_SURFACE_VALIDATION = (
        "api_data_exposure_surface_validation"
    )
    FILE_UPLOAD_SURFACE_VALIDATION = (
        "file_upload_surface_validation"
    )
    INJECTION_SURFACE_VALIDATION = (
        "injection_surface_validation"
    )
    BROWSER_ATTACK_SURFACE_VALIDATION = (
        "browser_attack_surface_validation"
    )
    AUTHORIZATION_BOUNDARY = "authorization_boundary"
    STATE_CHANGE_VALIDATION = "state_change_validation"
    FILE_PROCESSING_VALIDATION = "file_processing_validation"
    DESTRUCTIVE_VALIDATION = "destructive_validation"


@dataclass(frozen=True)
class ControlledValidationRequest:
    """One operator-requested controlled validation action."""

    execution_id: str
    target_url: str
    action: ControlledValidationAction
    authorized: bool
    active_testing: bool
    intrusive_testing: bool = False
    explicitly_approved: bool = False
    reversible: bool = True
    requested_requests: int = 1
    source_execution_id: str | None = None
    source_hypothesis_evidence_id: str | None = None
    source_hypothesis_id: str | None = None


@dataclass(frozen=True)
class ControlledValidationPolicyResult:
    """Fail-closed policy outcome for a validation request."""

    decision: ControlledValidationDecision
    risk: ControlledValidationRisk
    reason: str

    @property
    def allowed(self) -> bool:
        """Return whether automated execution is permitted."""

        return self.decision is ControlledValidationDecision.ALLOW
