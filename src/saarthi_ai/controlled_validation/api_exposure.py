"""Aggregate-only Phase 6C.7 API data-exposure surface analysis."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

MAX_JSON_NODES = 5_000
MAX_JSON_DEPTH = 20
_NORMALIZE_KEY = re.compile(r"[^a-z0-9]")
_CATEGORY_MARKERS: dict[str, frozenset[str]] = {
    "credential_material": frozenset(
        {
            "password",
            "passwd",
            "pwd",
            "token",
            "accesstoken",
            "refreshtoken",
            "secret",
            "apikey",
            "privatekey",
            "clientsecret",
            "sessionid",
        }
    ),
    "government_identity": frozenset(
        {
            "ssn",
            "socialsecuritynumber",
            "nationalid",
            "passportnumber",
            "driverlicensenumber",
        }
    ),
    "financial_data": frozenset(
        {
            "creditcard",
            "cardnumber",
            "cvv",
            "bankaccount",
            "iban",
            "routingnumber",
        }
    ),
    "personal_contact": frozenset(
        {
            "email",
            "emailaddress",
            "phone",
            "phonenumber",
            "mobile",
            "address",
            "dateofbirth",
            "dob",
        }
    ),
}


class ApiExposureClassification(StrEnum):
    """Conservative aggregate classification, not a data-leak finding."""

    REVIEW_RECOMMENDED = "review_recommended"
    NO_SENSITIVE_FIELD_SIGNALS = "no_sensitive_field_signals"
    NOT_APPLICABLE = "not_applicable"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class ApiExposureValidationResult:
    """Bounded JSON analysis with original keys and values discarded."""

    validator_id: str
    classification: ApiExposureClassification
    reason: str
    nodes_inspected: int
    maximum_depth_observed: int
    sensitive_category_counts: tuple[tuple[str, int], ...]
    analysis_truncated: bool
    parse_error: bool
    json_keys_discarded: bool = True
    json_values_discarded: bool = True
    raw_json_stored: bool = False
    request_body_sent: bool = False
    authentication_used: bool = False
    payload_generated: bool = False


def _category_for_key(key: str) -> str | None:
    normalized = _NORMALIZE_KEY.sub("", key.lower())
    for category, markers in _CATEGORY_MARKERS.items():
        if normalized in markers:
            return category
    return None


def analyze_api_exposure_surface(
    *,
    status_code: int,
    content_type: str | None,
    body: bytes,
    body_truncated: bool,
) -> ApiExposureValidationResult:
    """Parse bounded JSON without retaining original keys or values."""

    if content_type is None or "json" not in content_type.lower():
        return ApiExposureValidationResult(
            validator_id="6C.7-api-data-exposure-surface-validation",
            classification=ApiExposureClassification.NOT_APPLICABLE,
            reason="The response Content-Type is not JSON.",
            nodes_inspected=0,
            maximum_depth_observed=0,
            sensitive_category_counts=(),
            analysis_truncated=False,
            parse_error=False,
        )

    try:
        document = json.loads(body)
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError):
        return ApiExposureValidationResult(
            validator_id="6C.7-api-data-exposure-surface-validation",
            classification=ApiExposureClassification.INCONCLUSIVE,
            reason="The bounded response could not be parsed as JSON.",
            nodes_inspected=0,
            maximum_depth_observed=0,
            sensitive_category_counts=(),
            analysis_truncated=body_truncated,
            parse_error=True,
        )

    stack: list[tuple[Any, int]] = [(document, 0)]
    nodes_inspected = 0
    maximum_depth = 0
    category_counts: dict[str, int] = {}
    analysis_truncated = body_truncated

    while stack:
        value, depth = stack.pop()
        if (
            nodes_inspected >= MAX_JSON_NODES
            or depth > MAX_JSON_DEPTH
        ):
            analysis_truncated = True
            break

        nodes_inspected += 1
        maximum_depth = max(maximum_depth, depth)

        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(key, str):
                    category = _category_for_key(key)
                    if category is not None:
                        category_counts[category] = (
                            category_counts.get(category, 0) + 1
                        )
                stack.append((child, depth + 1))
        elif isinstance(value, list):
            stack.extend(
                (child, depth + 1)
                for child in value
            )

    if not 200 <= status_code < 300 or analysis_truncated:
        classification = ApiExposureClassification.INCONCLUSIVE
        reason = (
            "The JSON response was incomplete, outside a successful "
            "status, or exceeded bounded analysis limits."
        )
    elif category_counts:
        classification = (
            ApiExposureClassification.REVIEW_RECOMMENDED
        )
        reason = (
            "Sensitive field-name categories were observed; authorization "
            "context and necessity require manual review."
        )
    else:
        classification = (
            ApiExposureClassification.NO_SENSITIVE_FIELD_SIGNALS
        )
        reason = (
            "No configured sensitive field-name category was observed "
            "in the bounded JSON structure."
        )

    return ApiExposureValidationResult(
        validator_id="6C.7-api-data-exposure-surface-validation",
        classification=classification,
        reason=reason,
        nodes_inspected=nodes_inspected,
        maximum_depth_observed=maximum_depth,
        sensitive_category_counts=tuple(
            sorted(category_counts.items())
        ),
        analysis_truncated=analysis_truncated,
        parse_error=False,
    )
