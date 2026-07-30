from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from saarthi_ai.assessments.schemas import (
    AssessmentRequest,
    AssessmentTarget,
    AssessmentValidationResponse,
    AssetType,
    ValidatedTarget,
)


class ScopeValidationError(ValueError):
    """Raised when a target fails scope validation."""


def normalize_url(value: str) -> str:
    """Validate and normalize a web or API URL."""

    parsed = urlsplit(value)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ScopeValidationError("Web and API targets must use HTTP or HTTPS.")

    if not parsed.hostname:
        raise ScopeValidationError(f"Target URL does not contain a valid hostname: {value}")

    scheme = parsed.scheme.lower()
    network_location = parsed.netloc.lower()
    path = parsed.path or "/"

    return urlunsplit(
        (
            scheme,
            network_location,
            path,
            parsed.query,
            "",
        )
    )


def normalize_ip(value: str) -> str:
    """Validate and normalize an individual IP address."""

    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ScopeValidationError(f"Invalid IP address: {value}") from exc


def normalize_cidr(value: str) -> str:
    """Validate and normalize a network range."""

    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise ScopeValidationError(f"Invalid CIDR range: {value}") from exc


def normalize_mobile_file(
    value: str,
    *,
    required_extension: str,
) -> str:
    """Validate a mobile application filename or path."""

    suffix = Path(value).suffix.lower()

    if suffix != required_extension:
        raise ScopeValidationError(
            f"Expected a {required_extension} application file, but received: {value}"
        )

    return value


def normalize_target(target: AssessmentTarget) -> str:
    """Normalize a target according to its declared asset type."""

    if target.asset_type in {AssetType.WEB, AssetType.API}:
        return normalize_url(target.value)

    if target.asset_type is AssetType.IP:
        return normalize_ip(target.value)

    if target.asset_type is AssetType.CIDR:
        return normalize_cidr(target.value)

    if target.asset_type is AssetType.ANDROID:
        return normalize_mobile_file(
            target.value,
            required_extension=".apk",
        )

    if target.asset_type is AssetType.IOS:
        return normalize_mobile_file(
            target.value,
            required_extension=".ipa",
        )

    raise ScopeValidationError(f"Unsupported asset type: {target.asset_type}")


def build_execution_levels(
    request: AssessmentRequest,
) -> list[str]:
    """Return the testing levels approved for the engagement."""

    levels = ["passive"]

    if request.allow_active_testing:
        levels.append("active")

    if request.allow_intrusive_testing:
        levels.append("intrusive")

    return levels


def validate_assessment(
    request: AssessmentRequest,
) -> AssessmentValidationResponse:
    """Validate and normalize an authorized assessment request."""

    exclusions = set(request.excluded_targets)
    seen_targets: set[str] = set()
    validated_targets: list[ValidatedTarget] = []

    for target in request.targets:
        normalized = normalize_target(target)

        if target.value in exclusions or normalized in exclusions:
            raise ScopeValidationError(f"Target is explicitly excluded: {target.value}")

        duplicate_key = f"{target.asset_type.value}:{normalized}"

        if duplicate_key in seen_targets:
            raise ScopeValidationError(f"Duplicate target detected: {target.value}")

        seen_targets.add(duplicate_key)

        validated_targets.append(
            ValidatedTarget(
                asset_type=target.asset_type,
                original_value=target.value,
                normalized_value=normalized,
                label=target.label,
            )
        )

    return AssessmentValidationResponse(
        valid=True,
        assessment_name=request.name,
        targets=validated_targets,
        excluded_targets=request.excluded_targets,
        permitted_execution_levels=build_execution_levels(request),
        rate_limit_per_second=request.rate_limit_per_second,
    )
