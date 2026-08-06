"""Tests for value-redacted Phase 6C.4 cookie attribute analysis."""

from __future__ import annotations

from saarthi_ai.controlled_validation.session_cookie import (
    MAX_COOKIE_HEADER_CHARACTERS,
    MAX_COOKIE_HEADERS,
    SessionCookieClassification,
    analyze_session_cookie_attributes,
)


def test_hardened_cookie_discards_name_and_value() -> None:
    secret_value = "super-secret-session-token"
    result = analyze_session_cookie_attributes(
        (
            "__Host-session="
            f"{secret_value}; Secure; HttpOnly; "
            "SameSite=Strict; Path=/",
        )
    )

    assert (
        result.classification
        is SessionCookieClassification.HARDENED
    )
    assert result.cookie_count == 1
    assert result.cookies_with_issues == 0
    assert result.cookie_values_discarded is True
    assert result.raw_set_cookie_stored is False
    assert result.cookie_replayed is False
    assert result.credential_header_sent is False
    assert result.payload_generated is False

    observation = result.cookie_observations[0]
    assert len(observation.cookie_name_sha256) == 64
    assert observation.secure is True
    assert observation.http_only is True
    assert observation.same_site == "strict"
    assert observation.path_is_root is True
    assert observation.host_prefix is True
    assert observation.issues == ()
    assert secret_value not in repr(result)
    assert "__Host-session" not in repr(result)


def test_missing_attributes_request_manual_review() -> None:
    result = analyze_session_cookie_attributes(
        ("session=secret; Path=/",)
    )

    assert (
        result.classification
        is SessionCookieClassification.REVIEW_RECOMMENDED
    )
    assert result.cookie_count == 1
    assert result.cookies_with_issues == 1
    issues = result.cookie_observations[0].issues
    assert "missing_secure" in issues
    assert "missing_http_only" in issues
    assert "missing_or_invalid_same_site" in issues


def test_prefix_and_same_site_constraints_are_checked() -> None:
    result = analyze_session_cookie_attributes(
        (
            "__Host-id=value; HttpOnly; SameSite=None; "
            "Path=/app; Domain=example.com",
            "__Secure-id=value; HttpOnly; SameSite=Lax",
        )
    )

    issue_counts = dict(result.issue_counts)
    assert issue_counts["invalid_host_prefix_attributes"] == 1
    assert issue_counts["invalid_secure_prefix_attributes"] == 1
    assert issue_counts["same_site_none_without_secure"] == 1
    assert issue_counts["missing_secure"] == 2


def test_no_cookie_headers_is_not_observed() -> None:
    result = analyze_session_cookie_attributes(())

    assert (
        result.classification
        is SessionCookieClassification.NO_COOKIES_OBSERVED
    )
    assert result.cookie_count == 0


def test_malformed_and_oversized_inputs_are_inconclusive() -> None:
    malformed = analyze_session_cookie_attributes(
        ("not-a-cookie",)
    )
    assert (
        malformed.classification
        is SessionCookieClassification.INCONCLUSIVE
    )
    assert malformed.malformed_header_count == 1

    oversized = analyze_session_cookie_attributes(
        (
            "name=" + "x" * MAX_COOKIE_HEADER_CHARACTERS,
        )
    )
    assert oversized.analysis_truncated is True
    assert (
        oversized.classification
        is SessionCookieClassification.INCONCLUSIVE
    )

    too_many = analyze_session_cookie_attributes(
        tuple(
            f"cookie{index}=value; Secure; HttpOnly; SameSite=Lax"
            for index in range(MAX_COOKIE_HEADERS + 1)
        )
    )
    assert too_many.analysis_truncated is True
    assert too_many.cookie_count == MAX_COOKIE_HEADERS
