"""Bounded HTTP observation adapter for Phase 6C low-risk validation."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

import httpx

from saarthi_ai.controlled_validation.api_exposure import (
    ApiExposureValidationResult,
    analyze_api_exposure_surface,
)
from saarthi_ai.controlled_validation.browser_surface import (
    BrowserSurfaceValidationResult,
    analyze_browser_surface,
)
from saarthi_ai.controlled_validation.csrf_surface import (
    CsrfSurfaceValidationResult,
    analyze_csrf_surface,
)
from saarthi_ai.controlled_validation.executor import (
    ControlledValidationExecutionDecision,
    ControlledValidationExecutionPolicy,
    ControlledValidationExecutionRequest,
    evaluate_controlled_validation_execution,
)
from saarthi_ai.controlled_validation.injection_surface import (
    InjectionSurfaceValidationResult,
    analyze_injection_surface,
)
from saarthi_ai.controlled_validation.models import (
    ControlledValidationAction,
)
from saarthi_ai.controlled_validation.server_parser_surface import (
    ServerParserSurfaceValidationResult,
    analyze_server_parser_surface,
)
from saarthi_ai.controlled_validation.session_cookie import (
    SessionCookieValidationResult,
    analyze_session_cookie_attributes,
)
from saarthi_ai.controlled_validation.upload_surface import (
    UploadSurfaceValidationResult,
    analyze_upload_surface,
)
from saarthi_ai.execution.http_collector import (
    read_limited_body,
    sanitize_headers,
)

DEFAULT_USER_AGENT = "Saarthi-AI/0.6 controlled-validation"


@dataclass(frozen=True)
class ControlledValidationObservationResult:
    """Structured result from one bounded HTTP observation."""

    policy: ControlledValidationExecutionPolicy
    request_attempted: bool
    response_received: bool
    method: str
    target_url: str
    final_url: str | None = None
    status_code: int = 0
    http_version: str | None = None
    content_type: str | None = None
    response_headers: dict[str, str] | None = None
    body_bytes_captured: int = 0
    body_truncated: bool = False
    body_sha256: str | None = None
    session_cookie_analysis: (
        SessionCookieValidationResult | None
    ) = None
    csrf_surface_analysis: CsrfSurfaceValidationResult | None = None
    api_exposure_analysis: ApiExposureValidationResult | None = None
    upload_surface_analysis: UploadSurfaceValidationResult | None = None
    injection_surface_analysis: (
        InjectionSurfaceValidationResult | None
    ) = None
    browser_surface_analysis: BrowserSurfaceValidationResult | None = None
    server_parser_surface_analysis: (
        ServerParserSurfaceValidationResult | None
    ) = None
    error_type: str | None = None
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        """Return whether the bounded request received a response."""

        return (
            self.policy.decision
            is ControlledValidationExecutionDecision.ALLOW
            and self.request_attempted
            and self.response_received
            and self.error is None
        )


def _denied_result(
    request: ControlledValidationExecutionRequest,
    policy: ControlledValidationExecutionPolicy,
) -> ControlledValidationObservationResult:
    return ControlledValidationObservationResult(
        policy=policy,
        request_attempted=False,
        response_received=False,
        method=policy.method,
        target_url=request.validation.target_url,
        error_type="policy_denied",
        error=policy.reason,
    )


def _error_result(
    request: ControlledValidationExecutionRequest,
    policy: ControlledValidationExecutionPolicy,
    error: httpx.HTTPError,
) -> ControlledValidationObservationResult:
    return ControlledValidationObservationResult(
        policy=policy,
        request_attempted=True,
        response_received=False,
        method=policy.method,
        target_url=request.validation.target_url,
        error_type=type(error).__name__,
        error=str(error),
    )


async def execute_bounded_observation(
    request: ControlledValidationExecutionRequest,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> ControlledValidationObservationResult:
    """Perform exactly one approved GET or HEAD observation."""

    policy = evaluate_controlled_validation_execution(request)

    if not policy.allowed:
        return _denied_result(request, policy)

    timeout = httpx.Timeout(
        timeout=policy.timeout_seconds,
        connect=policy.timeout_seconds,
        read=policy.timeout_seconds,
        write=policy.timeout_seconds,
        pool=policy.timeout_seconds,
    )
    limits = httpx.Limits(
        max_connections=1,
        max_keepalive_connections=0,
    )

    request_headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "*/*",
    }
    request_headers.update(
        {
            name.strip(): value
            for name, value in request.headers
        }
    )

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
            headers=request_headers,
        ) as client:
            async with client.stream(
                policy.method,
                request.validation.target_url,
            ) as response:
                if policy.method == "HEAD":
                    body = b""
                    truncated = False
                else:
                    body, truncated = await read_limited_body(
                        response,
                        max_body_bytes=policy.max_response_bytes,
                    )

                return ControlledValidationObservationResult(
                    policy=policy,
                    request_attempted=True,
                    response_received=True,
                    method=policy.method,
                    target_url=request.validation.target_url,
                    final_url=str(response.url),
                    status_code=response.status_code,
                    http_version=response.http_version,
                    content_type=response.headers.get(
                        "content-type"
                    ),
                    response_headers=sanitize_headers(
                        response.headers
                    ),
                    body_bytes_captured=len(body),
                    body_truncated=truncated,
                    body_sha256=sha256(body).hexdigest(),
                    session_cookie_analysis=(
                        analyze_session_cookie_attributes(
                            tuple(
                                response.headers.get_list(
                                    "set-cookie"
                                )
                            )
                        )
                        if (
                            request.validation.action
                            is ControlledValidationAction
                            .SESSION_COOKIE_ATTRIBUTE_VALIDATION
                        )
                        else None
                    ),
                    csrf_surface_analysis=(
                        analyze_csrf_surface(
                            target_url=request.validation.target_url,
                            status_code=response.status_code,
                            content_type=response.headers.get(
                                "content-type"
                            ),
                            body=body,
                            body_truncated=truncated,
                            set_cookie_headers=tuple(
                                response.headers.get_list(
                                    "set-cookie"
                                )
                            ),
                        )
                        if (
                            request.validation.action
                            is ControlledValidationAction
                            .CSRF_PROTECTION_SURFACE_VALIDATION
                        )
                        else None
                    ),
                    api_exposure_analysis=(
                        analyze_api_exposure_surface(
                            status_code=response.status_code,
                            content_type=response.headers.get(
                                "content-type"
                            ),
                            body=body,
                            body_truncated=truncated,
                        )
                        if (
                            request.validation.action
                            is ControlledValidationAction
                            .API_DATA_EXPOSURE_SURFACE_VALIDATION
                        )
                        else None
                    ),
                    upload_surface_analysis=(
                        analyze_upload_surface(
                            target_url=request.validation.target_url,
                            status_code=response.status_code,
                            content_type=response.headers.get(
                                "content-type"
                            ),
                            body=body,
                            body_truncated=truncated,
                        )
                        if (
                            request.validation.action
                            is ControlledValidationAction
                            .FILE_UPLOAD_SURFACE_VALIDATION
                        )
                        else None
                    ),
                    injection_surface_analysis=(
                        analyze_injection_surface(
                            target_url=request.validation.target_url,
                            status_code=response.status_code,
                            content_type=response.headers.get(
                                "content-type"
                            ),
                            body=body,
                            body_truncated=truncated,
                        )
                        if (
                            request.validation.action
                            is ControlledValidationAction
                            .INJECTION_SURFACE_VALIDATION
                        )
                        else None
                    ),
                    browser_surface_analysis=(
                        analyze_browser_surface(
                            target_url=request.validation.target_url,
                            status_code=response.status_code,
                            content_type=response.headers.get(
                                "content-type"
                            ),
                            headers=sanitize_headers(response.headers),
                            body=body,
                            body_truncated=truncated,
                        )
                        if (
                            request.validation.action
                            is ControlledValidationAction
                            .BROWSER_ATTACK_SURFACE_VALIDATION
                        )
                        else None
                    ),
                    server_parser_surface_analysis=(
                        analyze_server_parser_surface(
                            target_url=request.validation.target_url,
                            status_code=response.status_code,
                            content_type=response.headers.get(
                                "content-type"
                            ),
                            body=body,
                            body_truncated=truncated,
                        )
                        if (
                            request.validation.action
                            is ControlledValidationAction
                            .SERVER_PARSER_SURFACE_VALIDATION
                        )
                        else None
                    ),
                )
    except (
        httpx.TimeoutException,
        httpx.NetworkError,
        httpx.ProtocolError,
    ) as exc:
        return _error_result(request, policy, exc)
