"""Header-only Phase 6C.2 clickjacking protection analysis."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum


class ClickjackingClassification(StrEnum):
    """Bounded protection classification, not a vulnerability finding."""

    PROTECTED = "protected"
    POTENTIALLY_EXPOSED = "potentially_exposed"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class ClickjackingValidationResult:
    """Safe summary derived only from HTTP response metadata."""

    validator_id: str
    classification: ClickjackingClassification
    reason: str
    protection_sources: tuple[str, ...]
    csp_frame_ancestors: tuple[str, ...]
    x_frame_options: str | None
    response_status_code: int
    content_type: str | None
    header_only: bool = True
    exploit_page_generated: bool = False
    browser_launched: bool = False
    payload_generated: bool = False


def _frame_ancestors(
    content_security_policy: str | None,
) -> tuple[str, ...]:
    if not content_security_policy:
        return ()

    for directive in content_security_policy.split(";"):
        tokens = directive.strip().split()
        if (
            tokens
            and tokens[0].lower() == "frame-ancestors"
        ):
            return tuple(token.lower() for token in tokens[1:])

    return ()


def analyze_clickjacking_protection(
    *,
    status_code: int,
    content_type: str | None,
    headers: Mapping[str, str] | None,
) -> ClickjackingValidationResult:
    """Classify framing controls without rendering or sending a payload."""

    normalized_headers = {
        str(name).strip().lower(): str(value).strip()
        for name, value in (headers or {}).items()
    }
    csp_sources = _frame_ancestors(
        normalized_headers.get("content-security-policy")
    )
    x_frame_options = normalized_headers.get("x-frame-options")
    normalized_xfo = (
        x_frame_options.upper()
        if x_frame_options is not None
        else None
    )
    protection_sources: list[str] = []

    if not 200 <= status_code < 300:
        classification = ClickjackingClassification.INCONCLUSIVE
        reason = (
            "The response status does not represent a successfully "
            "retrieved page, so framing protection is inconclusive."
        )
    elif (
        content_type is None
        or "html" not in content_type.lower()
    ):
        classification = ClickjackingClassification.INCONCLUSIVE
        reason = (
            "The response is not HTML and is not treated as a "
            "frameable application page."
        )
    elif csp_sources and "*" not in csp_sources:
        classification = ClickjackingClassification.PROTECTED
        protection_sources.append("csp_frame_ancestors")
        reason = (
            "Content-Security-Policy defines a restrictive "
            "frame-ancestors directive."
        )
    elif normalized_xfo in {"DENY", "SAMEORIGIN"}:
        classification = ClickjackingClassification.PROTECTED
        protection_sources.append("x_frame_options")
        reason = (
            "X-Frame-Options defines a recognized framing restriction."
        )
    elif "*" in csp_sources:
        classification = (
            ClickjackingClassification.POTENTIALLY_EXPOSED
        )
        reason = (
            "Content-Security-Policy permits framing from any origin."
        )
    elif normalized_xfo is not None:
        classification = ClickjackingClassification.INCONCLUSIVE
        reason = (
            "X-Frame-Options is present but does not use DENY or "
            "SAMEORIGIN."
        )
    else:
        classification = (
            ClickjackingClassification.POTENTIALLY_EXPOSED
        )
        reason = (
            "No frame-ancestors directive or recognized "
            "X-Frame-Options restriction was observed."
        )

    return ClickjackingValidationResult(
        validator_id="6C.2-clickjacking-header-validation",
        classification=classification,
        reason=reason,
        protection_sources=tuple(protection_sources),
        csp_frame_ancestors=csp_sources,
        x_frame_options=x_frame_options,
        response_status_code=status_code,
        content_type=content_type,
    )
