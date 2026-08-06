"""Tests for aggregate-only Phase 6C.7 API exposure analysis."""

from __future__ import annotations

import json

from saarthi_ai.controlled_validation.api_exposure import (
    MAX_JSON_DEPTH,
    ApiExposureClassification,
    analyze_api_exposure_surface,
)


def analyze(
    value: object,
    *,
    status_code: int = 200,
    content_type: str | None = "application/json",
    body_truncated: bool = False,
):
    return analyze_api_exposure_surface(
        status_code=status_code,
        content_type=content_type,
        body=json.dumps(value).encode(),
        body_truncated=body_truncated,
    )


def test_sensitive_field_categories_are_counted_without_retention() -> None:
    secret_value = "never-retain-this-api-token"
    result = analyze(
        {
            "access_token": secret_value,
            "profile": {
                "email_address": "private@example.com",
                "passport_number": "discard-me",
            },
        }
    )

    assert (
        result.classification
        is ApiExposureClassification.REVIEW_RECOMMENDED
    )
    assert dict(result.sensitive_category_counts) == {
        "credential_material": 1,
        "government_identity": 1,
        "personal_contact": 1,
    }
    assert result.json_keys_discarded is True
    assert result.json_values_discarded is True
    assert result.raw_json_stored is False
    assert result.request_body_sent is False
    assert result.authentication_used is False
    assert result.payload_generated is False
    rendered = repr(result)
    assert secret_value not in rendered
    assert "access_token" not in rendered
    assert "private@example.com" not in rendered


def test_benign_json_has_no_sensitive_field_signals() -> None:
    result = analyze({"status": "ok", "items": [{"id": 1}]})

    assert (
        result.classification
        is ApiExposureClassification.NO_SENSITIVE_FIELD_SIGNALS
    )
    assert result.sensitive_category_counts == ()
    assert result.analysis_truncated is False


def test_non_json_response_is_not_applicable() -> None:
    result = analyze(
        {"email": "discard"},
        content_type="text/html",
    )

    assert (
        result.classification
        is ApiExposureClassification.NOT_APPLICABLE
    )
    assert result.nodes_inspected == 0


def test_invalid_or_truncated_json_is_inconclusive() -> None:
    invalid = analyze_api_exposure_surface(
        status_code=200,
        content_type="application/json",
        body=b"{",
        body_truncated=False,
    )
    truncated = analyze(
        {"status": "ok"},
        body_truncated=True,
    )

    assert (
        invalid.classification
        is ApiExposureClassification.INCONCLUSIVE
    )
    assert invalid.parse_error is True
    assert (
        truncated.classification
        is ApiExposureClassification.INCONCLUSIVE
    )
    assert truncated.analysis_truncated is True


def test_depth_limit_fails_closed() -> None:
    value: object = "leaf"
    for _ in range(MAX_JSON_DEPTH + 2):
        value = {"child": value}

    result = analyze(value)

    assert result.analysis_truncated is True
    assert (
        result.classification
        is ApiExposureClassification.INCONCLUSIVE
    )
