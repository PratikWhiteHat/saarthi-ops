"""Tests for non-submitting Phase 6C.2 CSRF surface analysis."""

from __future__ import annotations

from saarthi_ai.controlled_validation.csrf_surface import (
    MAX_FORMS,
    CsrfSurfaceClassification,
    analyze_csrf_surface,
)


def analyze(
    body: str,
    *,
    content_type: str | None = "text/html",
    body_truncated: bool = False,
    cookies: tuple[str, ...] = (),
):
    return analyze_csrf_surface(
        target_url="https://example.com/account",
        status_code=200,
        content_type=content_type,
        body=body.encode(),
        body_truncated=body_truncated,
        set_cookie_headers=cookies,
    )


def test_post_form_token_signal_discards_token_value() -> None:
    secret = "csrf-secret-never-store"
    result = analyze(
        "<form method='POST' action='/save'>"
        "<input type='hidden' name='csrf_token' "
        f"value='{secret}'>"
        "<input name='display_name'>"
        "</form>",
        cookies=(
            "session=private; Secure; HttpOnly; SameSite=Lax",
        ),
    )

    assert (
        result.classification
        is CsrfSurfaceClassification.PROTECTION_SIGNALS_OBSERVED
    )
    assert result.form_count == 1
    assert result.post_form_count == 1
    assert result.forms_with_token_signal == 1
    assert result.forms_without_token_signal == 0
    assert result.same_site_protected_cookie_count == 1
    assert result.protection_sources == (
        "anti_csrf_field_name",
        "same_site_cookie",
    )
    assert result.token_values_discarded is True
    assert result.form_submitted is False
    assert result.browser_launched is False
    assert result.request_body_sent is False
    assert result.payload_generated is False
    assert secret not in repr(result)


def test_missing_token_signal_requests_review() -> None:
    result = analyze(
        "<form method='post' action='/save'>"
        "<input name='display_name'>"
        "</form>"
    )

    assert (
        result.classification
        is CsrfSurfaceClassification.REVIEW_RECOMMENDED
    )
    assert result.forms_without_token_signal == 1


def test_cross_origin_form_action_requests_review() -> None:
    result = analyze(
        "<form method='post' action='https://outside.example/save'>"
        "<input type='hidden' name='_token' value='discard'>"
        "</form>"
    )

    assert result.cross_origin_action_count == 1
    assert (
        result.classification
        is CsrfSurfaceClassification.REVIEW_RECOMMENDED
    )


def test_page_without_post_forms_is_not_applicable() -> None:
    result = analyze(
        "<form method='get'><input name='q'></form>"
    )

    assert (
        result.classification
        is CsrfSurfaceClassification.NOT_APPLICABLE
    )
    assert result.form_count == 1
    assert result.post_form_count == 0


def test_non_html_or_truncated_response_is_inconclusive() -> None:
    non_html = analyze("{}", content_type="application/json")
    truncated = analyze(
        "<form method='post'>",
        body_truncated=True,
    )

    assert (
        non_html.classification
        is CsrfSurfaceClassification.INCONCLUSIVE
    )
    assert (
        truncated.classification
        is CsrfSurfaceClassification.INCONCLUSIVE
    )


def test_form_analysis_limit_is_fail_closed() -> None:
    body = "".join(
        "<form method='post'></form>"
        for _ in range(MAX_FORMS + 1)
    )
    result = analyze(body)

    assert result.form_count == MAX_FORMS
    assert result.analysis_truncated is True
    assert (
        result.classification
        is CsrfSurfaceClassification.INCONCLUSIVE
    )
