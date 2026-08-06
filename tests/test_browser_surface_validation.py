"""Tests for non-executing Phase 6C.2 browser-surface analysis."""

from __future__ import annotations

from saarthi_ai.controlled_validation.browser_surface import (
    BROWSER_SURFACE_TYPES,
    BrowserSurfaceClassification,
    analyze_browser_surface,
)


def test_remaining_official_browser_attack_family_is_complete() -> None:
    assert BROWSER_SURFACE_TYPES == (
        "Reflected XSS",
        "Stored XSS",
        "DOM-Based XSS",
        "HTML Injection",
        "CSS Injection",
        "DOM Clobbering",
        "Prototype Pollution",
        "Open Redirect",
        "postMessage Origin Validation",
        "WebSocket Authentication Validation",
        "CORS Exploitation",
    )


def test_browser_surfaces_are_aggregated_without_source_retention() -> None:
    secret = "private-source-value-must-not-be-retained"
    body = f"""
        <form id="profile"><input name="display_name" value="{secret}"></form>
        <style>.profile {{ color: inherit; }}</style>
        <script>
          element.innerHTML = renderedContent;
          Object.assign(target, options);
          window.addEventListener("message", handler);
          if (event.origin === expectedOrigin) acceptMessage(event);
          const socket = new WebSocket(socketUrl);
          const authorization = sessionReference;
          location.assign(destination);
        </script>
    """.encode()

    result = analyze_browser_surface(
        target_url=(
            "https://example.com/profile?"
            "redirect=%2Fhome&search=term"
        ),
        status_code=200,
        content_type="text/html",
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
        body=body,
        body_truncated=False,
    )

    observed = {
        item.attack_type
        for item in result.observed_surfaces
    }
    assert (
        result.classification
        is BrowserSurfaceClassification.REVIEW_RECOMMENDED
    )
    assert observed >= {
        "Reflected XSS",
        "Stored XSS",
        "DOM-Based XSS",
        "HTML Injection",
        "CSS Injection",
        "DOM Clobbering",
        "Prototype Pollution",
        "Open Redirect",
        "postMessage Origin Validation",
        "WebSocket Authentication Validation",
        "CORS Exploitation",
    }
    assert result.postmessage_handler_observed is True
    assert result.postmessage_origin_check_observed is True
    assert result.websocket_usage_observed is True
    assert result.websocket_auth_signal_observed is True
    assert result.cors_wildcard_origin is True
    assert result.cors_credentials_allowed is True
    assert secret not in repr(result)
    assert result.source_text_discarded is True
    assert result.attribute_values_discarded is True
    assert result.browser_launched is False
    assert result.script_executed is False
    assert result.payload_generated is False
    assert result.exploit_executed is False


def test_cors_headers_are_inventory_signals_not_confirmation() -> None:
    result = analyze_browser_surface(
        target_url="https://example.com/api",
        status_code=200,
        content_type="application/json",
        headers={
            "Access-Control-Allow-Origin": (
                "https://trusted.example"
            ),
        },
        body=b"{}",
        body_truncated=False,
    )

    assert result.cors_allow_origin_present is True
    assert result.cors_wildcard_origin is False
    assert {
        item.attack_type
        for item in result.observed_surfaces
    } == {"CORS Exploitation"}
    assert "not a vulnerability" not in result.reason.lower()
    assert result.exploit_executed is False


def test_clean_complete_html_has_no_browser_surface() -> None:
    result = analyze_browser_surface(
        target_url="https://example.com/about",
        status_code=200,
        content_type="text/html",
        headers={},
        body=b"<html><h1>About</h1></html>",
        body_truncated=False,
    )

    assert (
        result.classification
        is BrowserSurfaceClassification.NO_SURFACE_OBSERVED
    )
    assert result.observed_surfaces == ()


def test_truncated_response_without_signals_is_inconclusive() -> None:
    result = analyze_browser_surface(
        target_url="https://example.com/",
        status_code=200,
        content_type="text/html",
        headers={},
        body=b"<html>",
        body_truncated=True,
    )

    assert (
        result.classification
        is BrowserSurfaceClassification.INCONCLUSIVE
    )
