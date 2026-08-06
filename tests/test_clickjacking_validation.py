"""Tests for the header-only Phase 6C.2 clickjacking validator."""

from __future__ import annotations

import pytest

from saarthi_ai.controlled_validation.clickjacking import (
    ClickjackingClassification,
    analyze_clickjacking_protection,
)


@pytest.mark.parametrize(
    ("headers", "expected_source"),
    [
        (
            {
                "content-security-policy": (
                    "default-src 'self'; frame-ancestors 'none'"
                )
            },
            "csp_frame_ancestors",
        ),
        (
            {"x-frame-options": "DENY"},
            "x_frame_options",
        ),
        (
            {"x-frame-options": "sameorigin"},
            "x_frame_options",
        ),
    ],
)
def test_recognized_framing_restrictions_are_protected(
    headers: dict[str, str],
    expected_source: str,
) -> None:
    result = analyze_clickjacking_protection(
        status_code=200,
        content_type="text/html; charset=utf-8",
        headers=headers,
    )

    assert (
        result.classification
        is ClickjackingClassification.PROTECTED
    )
    assert expected_source in result.protection_sources
    assert result.header_only is True
    assert result.exploit_page_generated is False
    assert result.browser_launched is False
    assert result.payload_generated is False


def test_missing_framing_controls_are_potentially_exposed() -> None:
    result = analyze_clickjacking_protection(
        status_code=200,
        content_type="text/html",
        headers={"content-type": "text/html"},
    )

    assert (
        result.classification
        is ClickjackingClassification.POTENTIALLY_EXPOSED
    )
    assert result.protection_sources == ()
    assert "No frame-ancestors" in result.reason


def test_wildcard_frame_ancestors_is_potentially_exposed() -> None:
    result = analyze_clickjacking_protection(
        status_code=200,
        content_type="text/html",
        headers={
            "Content-Security-Policy": "frame-ancestors *",
            "X-Frame-Options": "invalid",
        },
    )

    assert (
        result.classification
        is ClickjackingClassification.POTENTIALLY_EXPOSED
    )
    assert result.csp_frame_ancestors == ("*",)


@pytest.mark.parametrize(
    ("status_code", "content_type", "headers"),
    [
        (404, "text/html", {}),
        (302, "text/html", {}),
        (200, None, {}),
        (200, "application/json", {}),
        (200, "text/html", {"x-frame-options": "ALLOW-FROM x"}),
    ],
)
def test_non_page_or_ambiguous_responses_are_inconclusive(
    status_code: int,
    content_type: str | None,
    headers: dict[str, str],
) -> None:
    result = analyze_clickjacking_protection(
        status_code=status_code,
        content_type=content_type,
        headers=headers,
    )

    assert (
        result.classification
        is ClickjackingClassification.INCONCLUSIVE
    )


def test_csp_takes_precedence_over_conflicting_x_frame_options() -> None:
    result = analyze_clickjacking_protection(
        status_code=200,
        content_type="text/html",
        headers={
            "content-security-policy": (
                "script-src 'self'; frame-ancestors 'self' "
                "https://trusted.example"
            ),
            "x-frame-options": "invalid",
        },
    )

    assert (
        result.classification
        is ClickjackingClassification.PROTECTED
    )
    assert result.csp_frame_ancestors == (
        "'self'",
        "https://trusted.example",
    )
    assert result.protection_sources == ("csp_frame_ancestors",)
