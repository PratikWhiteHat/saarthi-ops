"""Controlled-validation policy and execution contracts."""

from saarthi_ai.controlled_validation.api_exposure import (
    ApiExposureClassification,
    ApiExposureValidationResult,
    analyze_api_exposure_surface,
)
from saarthi_ai.controlled_validation.browser_surface import (
    BROWSER_SURFACE_TYPES,
    BrowserSurfaceClassification,
    BrowserSurfaceSignal,
    BrowserSurfaceValidationResult,
    analyze_browser_surface,
)
from saarthi_ai.controlled_validation.clickjacking import (
    ClickjackingClassification,
    ClickjackingValidationResult,
    analyze_clickjacking_protection,
)
from saarthi_ai.controlled_validation.csrf_surface import (
    CsrfSurfaceClassification,
    CsrfSurfaceValidationResult,
    analyze_csrf_surface,
)
from saarthi_ai.controlled_validation.executor import (
    ALLOWED_METHODS,
    DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    EXECUTABLE_ACTIONS,
    MAX_RESPONSE_BYTES,
    MAX_TIMEOUT_SECONDS,
    ControlledValidationExecutionDecision,
    ControlledValidationExecutionPolicy,
    ControlledValidationExecutionRequest,
    evaluate_controlled_validation_execution,
)
from saarthi_ai.controlled_validation.injection_surface import (
    INJECTION_TYPES,
    InjectionSurfaceClassification,
    InjectionSurfaceSignal,
    InjectionSurfaceValidationResult,
    analyze_injection_surface,
)
from saarthi_ai.controlled_validation.models import (
    ControlledValidationAction,
    ControlledValidationDecision,
    ControlledValidationPolicyResult,
    ControlledValidationRequest,
    ControlledValidationRisk,
)
from saarthi_ai.controlled_validation.observation import (
    DEFAULT_USER_AGENT,
    ControlledValidationObservationResult,
    execute_bounded_observation,
)
from saarthi_ai.controlled_validation.parameter_surface import (
    ParameterSurfaceClassification,
    ParameterSurfaceValidationResult,
    analyze_parameter_surface,
)
from saarthi_ai.controlled_validation.policy import (
    MAX_CONTROLLED_REQUESTS,
    evaluate_controlled_validation,
)
from saarthi_ai.controlled_validation.session_cookie import (
    CookieAttributeObservation,
    SessionCookieClassification,
    SessionCookieValidationResult,
    analyze_session_cookie_attributes,
)
from saarthi_ai.controlled_validation.upload_surface import (
    UploadSurfaceClassification,
    UploadSurfaceValidationResult,
    analyze_upload_surface,
)
from saarthi_ai.controlled_validation.validator_registry import (
    PHASE_6_VALIDATOR_REGISTRY,
    ValidationLevel,
    ValidatorDefinition,
    ValidatorModuleSummary,
    ValidatorStatus,
    list_phase6_validators,
    summarize_phase6_validator_modules,
)

__all__ = [
    "ALLOWED_METHODS",
    "ApiExposureClassification",
    "ApiExposureValidationResult",
    "BROWSER_SURFACE_TYPES",
    "BrowserSurfaceClassification",
    "BrowserSurfaceSignal",
    "BrowserSurfaceValidationResult",
    "DEFAULT_MAX_RESPONSE_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_USER_AGENT",
    "EXECUTABLE_ACTIONS",
    "MAX_CONTROLLED_REQUESTS",
    "MAX_RESPONSE_BYTES",
    "MAX_TIMEOUT_SECONDS",
    "INJECTION_TYPES",
    "InjectionSurfaceClassification",
    "InjectionSurfaceSignal",
    "InjectionSurfaceValidationResult",
    "ParameterSurfaceClassification",
    "ParameterSurfaceValidationResult",
    "PHASE_6_VALIDATOR_REGISTRY",
    "ControlledValidationAction",
    "ClickjackingClassification",
    "ClickjackingValidationResult",
    "ControlledValidationDecision",
    "ControlledValidationExecutionDecision",
    "ControlledValidationExecutionPolicy",
    "ControlledValidationExecutionRequest",
    "ControlledValidationObservationResult",
    "ControlledValidationPolicyResult",
    "ControlledValidationRequest",
    "ControlledValidationRisk",
    "CookieAttributeObservation",
    "CsrfSurfaceClassification",
    "CsrfSurfaceValidationResult",
    "SessionCookieClassification",
    "SessionCookieValidationResult",
    "UploadSurfaceClassification",
    "UploadSurfaceValidationResult",
    "ValidationLevel",
    "ValidatorDefinition",
    "ValidatorModuleSummary",
    "ValidatorStatus",
    "evaluate_controlled_validation",
    "evaluate_controlled_validation_execution",
    "execute_bounded_observation",
    "analyze_clickjacking_protection",
    "analyze_api_exposure_surface",
    "analyze_browser_surface",
    "analyze_csrf_surface",
    "analyze_injection_surface",
    "analyze_parameter_surface",
    "analyze_session_cookie_attributes",
    "analyze_upload_surface",
    "list_phase6_validators",
    "summarize_phase6_validator_modules",
]
