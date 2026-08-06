"""Fail-closed execution contract for Phase 6C low-risk validation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlparse

from saarthi_ai.controlled_validation.models import (
    ControlledValidationAction,
    ControlledValidationDecision,
    ControlledValidationRequest,
)
from saarthi_ai.controlled_validation.policy import (
    MAX_CONTROLLED_REQUESTS,
    evaluate_controlled_validation,
)

DEFAULT_TIMEOUT_SECONDS = 8.0
MAX_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 128 * 1024
MAX_REQUEST_BODY_BYTES = 16 * 1024

ALLOWED_METHODS = frozenset({"GET", "HEAD", "POST"})
POST_CONTENT_TYPES = frozenset(
    {
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "text/plain",
        "application/xml",
        "text/xml",
    }
)
EXECUTABLE_ACTIONS = frozenset(
    {
        ControlledValidationAction.RESPONSE_DIFFERENTIAL,
        ControlledValidationAction.INPUT_HANDLING_OBSERVATION,
        ControlledValidationAction.CLICKJACKING_HEADER_VALIDATION,
        ControlledValidationAction.HTTP_PARAMETER_SURFACE_VALIDATION,
        ControlledValidationAction.SESSION_COOKIE_ATTRIBUTE_VALIDATION,
        ControlledValidationAction.CSRF_PROTECTION_SURFACE_VALIDATION,
        ControlledValidationAction.API_DATA_EXPOSURE_SURFACE_VALIDATION,
        ControlledValidationAction.FILE_UPLOAD_SURFACE_VALIDATION,
        ControlledValidationAction.INJECTION_SURFACE_VALIDATION,
        ControlledValidationAction.BROWSER_ATTACK_SURFACE_VALIDATION,
        ControlledValidationAction.SERVER_PARSER_SURFACE_VALIDATION,
    }
)

PROHIBITED_HEADER_NAMES = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
    }
)


class ControlledValidationExecutionDecision(StrEnum):
    """Phase 6C executor-gate decision."""

    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class ControlledValidationExecutionRequest:
    """One proposed bounded Phase 6C HTTP observation."""

    validation: ControlledValidationRequest
    method: str = "GET"
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    follow_redirects: bool = False
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes | None = None


@dataclass(frozen=True)
class ControlledValidationExecutionPolicy:
    """Fail-closed result for the Phase 6C execution gate."""

    decision: ControlledValidationExecutionDecision
    reason: str
    method: str
    request_budget: int
    timeout_seconds: float
    max_response_bytes: int
    follow_redirects: bool

    @property
    def allowed(self) -> bool:
        return (
            self.decision
            is ControlledValidationExecutionDecision.ALLOW
        )


def _result(
    request: ControlledValidationExecutionRequest,
    decision: ControlledValidationExecutionDecision,
    reason: str,
) -> ControlledValidationExecutionPolicy:
    return ControlledValidationExecutionPolicy(
        decision=decision,
        reason=reason,
        method=request.method.strip().upper(),
        request_budget=request.validation.requested_requests,
        timeout_seconds=request.timeout_seconds,
        max_response_bytes=request.max_response_bytes,
        follow_redirects=request.follow_redirects,
    )


def evaluate_controlled_validation_execution(
    request: ControlledValidationExecutionRequest,
) -> ControlledValidationExecutionPolicy:
    """Validate a Phase 6C proposal without making a network request."""

    validation = request.validation
    method = request.method.strip().upper()
    parsed = urlparse(validation.target_url)

    base_policy = evaluate_controlled_validation(validation)

    if base_policy.decision is not ControlledValidationDecision.ALLOW:
        return _result(
            request,
            ControlledValidationExecutionDecision.DENY,
            f"Controlled-validation policy denied execution: "
            f"{base_policy.reason}",
        )

    if validation.action not in EXECUTABLE_ACTIONS:
        return _result(
            request,
            ControlledValidationExecutionDecision.DENY,
            "Only registered low-risk response, input-handling, and "
            "clickjacking header, and HTTP parameter-surface "
            "observations are executable.",
        )

    if method not in ALLOWED_METHODS:
        return _result(
            request,
            ControlledValidationExecutionDecision.DENY,
            "Only GET, HEAD, and POST requests are allowed.",
        )

    if (
        validation.action
        in {
            ControlledValidationAction.SESSION_COOKIE_ATTRIBUTE_VALIDATION,
            ControlledValidationAction.CSRF_PROTECTION_SURFACE_VALIDATION,
            ControlledValidationAction.API_DATA_EXPOSURE_SURFACE_VALIDATION,
            ControlledValidationAction.FILE_UPLOAD_SURFACE_VALIDATION,
            ControlledValidationAction.INJECTION_SURFACE_VALIDATION,
            ControlledValidationAction.BROWSER_ATTACK_SURFACE_VALIDATION,
            ControlledValidationAction.SERVER_PARSER_SURFACE_VALIDATION,
        }
        and method not in {"GET", "POST"}
    ):
        return _result(
            request,
            ControlledValidationExecutionDecision.DENY,
            "This validator requires exactly one GET or controlled POST.",
        )

    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return _result(
            request,
            ControlledValidationExecutionDecision.DENY,
            "A credential-free absolute HTTP or HTTPS target is required.",
        )

    if validation.requested_requests < 1:
        return _result(
            request,
            ControlledValidationExecutionDecision.DENY,
            "At least one request is required.",
        )

    if validation.requested_requests > MAX_CONTROLLED_REQUESTS:
        return _result(
            request,
            ControlledValidationExecutionDecision.DENY,
            f"Request budget exceeds the maximum of "
            f"{MAX_CONTROLLED_REQUESTS}.",
        )

    if request.follow_redirects:
        return _result(
            request,
            ControlledValidationExecutionDecision.DENY,
            "Redirect following is disabled for the initial executor.",
        )

    body = request.body or b""
    if method in {"GET", "HEAD"} and body:
        return _result(
            request,
            ControlledValidationExecutionDecision.DENY,
            "GET and HEAD request bodies are not allowed.",
        )
    if method == "POST" and not body:
        return _result(
            request,
            ControlledValidationExecutionDecision.DENY,
            "POST requires one operator-supplied baseline request body.",
        )
    if len(body) > MAX_REQUEST_BODY_BYTES:
        return _result(
            request,
            ControlledValidationExecutionDecision.DENY,
            f"POST body exceeds the {MAX_REQUEST_BODY_BYTES}-byte limit.",
        )

    if not 0 < request.timeout_seconds <= MAX_TIMEOUT_SECONDS:
        return _result(
            request,
            ControlledValidationExecutionDecision.DENY,
            f"Timeout must be greater than zero and no more than "
            f"{MAX_TIMEOUT_SECONDS:g} seconds.",
        )

    if not 0 < request.max_response_bytes <= MAX_RESPONSE_BYTES:
        return _result(
            request,
            ControlledValidationExecutionDecision.DENY,
            "Response capture limit must be between 1 and "
            f"{MAX_RESPONSE_BYTES} bytes.",
        )

    supplied_header_names = {
        name.strip().lower()
        for name, _ in request.headers
    }
    prohibited = sorted(
        supplied_header_names.intersection(PROHIBITED_HEADER_NAMES)
    )

    if prohibited:
        return _result(
            request,
            ControlledValidationExecutionDecision.DENY,
            "Credential-bearing headers are prohibited: "
            f"{', '.join(prohibited)}.",
        )
    if method == "POST":
        content_types = [
            value
            for name, value in request.headers
            if name.strip().lower() == "content-type"
        ]
        if len(content_types) != 1:
            return _result(
                request,
                ControlledValidationExecutionDecision.DENY,
                "POST requires exactly one Content-Type header.",
            )
        media_type = content_types[0].split(";", 1)[0].strip().lower()
        if media_type not in POST_CONTENT_TYPES:
            return _result(
                request,
                ControlledValidationExecutionDecision.DENY,
                "POST Content-Type is outside the controlled allowlist.",
            )
        if (
            media_type == "multipart/form-data"
            and "boundary=" not in content_types[0].lower()
        ):
            return _result(
                request,
                ControlledValidationExecutionDecision.DENY,
                "Multipart POST requires an explicit boundary.",
            )

    return _result(
        request,
        ControlledValidationExecutionDecision.ALLOW,
        "Phase 6C proposal satisfies the bounded low-risk execution "
        "contract. No request has been executed.",
    )
