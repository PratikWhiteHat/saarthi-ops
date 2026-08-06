"""Tests for non-mutating Phase 6C.1 injection-surface analysis."""

from __future__ import annotations

from saarthi_ai.controlled_validation.injection_surface import (
    INJECTION_TYPES,
    InjectionSurfaceClassification,
    analyze_injection_surface,
)


def test_official_roadmap_injection_family_is_complete() -> None:
    assert INJECTION_TYPES == (
        "SQL Injection",
        "NoSQL Injection",
        "OS Command Injection",
        "LDAP Injection",
        "XXE Injection",
        "XPath/XQuery Injection",
        "Server-Side Template Injection",
        "Expression Language Injection",
        "CRLF/Header Injection",
        "Host Header Injection",
        "Email Header Injection",
        "Log Injection",
        "ORM/Query Language Injection",
    )


def test_query_and_form_names_produce_aggregate_surface_signals() -> None:
    secret = "private-value-must-not-be-retained"
    body = (
        b"<form><input name='template'><input name='subject'>"
        b"<textarea name='message'>"
        + secret.encode()
        + b"</textarea></form>"
    )

    result = analyze_injection_surface(
        target_url=(
            "https://example.com/search?id="
            f"{secret}&filter=active&host=internal"
        ),
        status_code=200,
        content_type="text/html",
        body=body,
        body_truncated=False,
    )

    observed = {
        item.injection_type: item
        for item in result.observed_surfaces
    }
    assert (
        result.classification
        is InjectionSurfaceClassification.SURFACE_OBSERVED
    )
    assert "SQL Injection" in observed
    assert "NoSQL Injection" in observed
    assert "Host Header Injection" in observed
    assert "Server-Side Template Injection" in observed
    assert "Email Header Injection" in observed
    assert "Log Injection" in observed
    assert secret not in repr(result)
    assert result.parameter_names_discarded is True
    assert result.parameter_values_discarded is True
    assert result.response_body_discarded is True
    assert result.parameters_mutated is False
    assert result.payload_generated is False
    assert result.exploit_executed is False


def test_json_and_xml_types_are_classified_without_body_parsing() -> None:
    json_result = analyze_injection_surface(
        target_url="https://example.com/api",
        status_code=200,
        content_type="application/json",
        body=b'{"secret": "not retained"}',
        body_truncated=False,
    )
    xml_result = analyze_injection_surface(
        target_url="https://example.com/xml",
        status_code=200,
        content_type="application/xml",
        body=b"<private>not retained</private>",
        body_truncated=False,
    )

    assert json_result.json_input_observed is True
    assert {
        item.injection_type
        for item in json_result.observed_surfaces
    } >= {
        "NoSQL Injection",
        "Expression Language Injection",
        "ORM/Query Language Injection",
    }
    assert xml_result.xml_input_observed is True
    assert {
        item.injection_type
        for item in xml_result.observed_surfaces
    } >= {
        "XXE Injection",
        "XPath/XQuery Injection",
        "LDAP Injection",
    }


def test_clean_complete_html_has_no_observed_surface() -> None:
    result = analyze_injection_surface(
        target_url="https://example.com/about",
        status_code=200,
        content_type="text/html",
        body=b"<html><h1>About</h1></html>",
        body_truncated=False,
    )

    assert (
        result.classification
        is InjectionSurfaceClassification.NO_SURFACE_OBSERVED
    )
    assert result.observed_surfaces == ()


def test_truncated_response_is_inconclusive_without_signals() -> None:
    result = analyze_injection_surface(
        target_url="https://example.com/",
        status_code=200,
        content_type="text/html",
        body=b"<html>",
        body_truncated=True,
    )

    assert (
        result.classification
        is InjectionSurfaceClassification.INCONCLUSIVE
    )
