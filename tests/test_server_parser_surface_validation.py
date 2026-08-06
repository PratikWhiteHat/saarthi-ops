"""Tests for non-mutating Phase 6C.3 server/parser analysis."""

from __future__ import annotations

from saarthi_ai.controlled_validation.server_parser_surface import (
    SERVER_PARSER_SURFACE_TYPES,
    ServerParserSurfaceClassification,
    analyze_server_parser_surface,
)


def test_official_server_parser_family_excludes_existing_hpp() -> None:
    assert SERVER_PARSER_SURFACE_TYPES == (
        "Remote Code Execution",
        "Blind SSRF",
        "XXE",
        "XML Entity Expansion",
        "Path Traversal",
        "Local File Inclusion",
        "Remote File Inclusion",
        "Unsafe URL Fetch",
        "Archive Extraction Traversal",
        "Unsafe Deserialization",
    )


def test_all_server_parser_surfaces_are_aggregated_without_values() -> None:
    secret = "private-parser-value-must-not-be-retained"
    target_url = (
        "https://example.com/process?"
        "cmd=review&url=https%3A%2F%2Fremote.example%2Fresource"
        "&include=https%3A%2F%2Fremote.example%2Ftemplate"
        "&file=document&archive=bundle&state=opaque"
    )
    body = (
        b"<form><input name='xml' value='"
        + secret.encode()
        + b"'><input name='template'></form>"
    )

    result = analyze_server_parser_surface(
        target_url=target_url,
        status_code=200,
        content_type="text/html",
        body=body,
        body_truncated=False,
    )

    assert (
        result.classification
        is ServerParserSurfaceClassification.REVIEW_RECOMMENDED
    )
    assert {
        item.attack_type
        for item in result.observed_surfaces
    } == set(SERVER_PARSER_SURFACE_TYPES)
    assert result.absolute_url_value_count == 2
    assert secret not in repr(result)
    assert result.parameter_values_discarded is True
    assert result.form_values_discarded is True
    assert result.response_body_discarded is True
    assert result.parameters_mutated is False
    assert result.parser_payload_sent is False
    assert result.callback_generated is False
    assert result.subprocess_started is False
    assert result.payload_generated is False
    assert result.exploit_executed is False


def test_parser_content_types_create_aggregate_signals() -> None:
    xml_result = analyze_server_parser_surface(
        target_url="https://example.com/xml",
        status_code=200,
        content_type="application/xml",
        body=b"<document />",
        body_truncated=False,
    )
    serialized_result = analyze_server_parser_surface(
        target_url="https://example.com/object",
        status_code=200,
        content_type="application/octet-stream",
        body=b"opaque",
        body_truncated=False,
    )
    archive_result = analyze_server_parser_surface(
        target_url="https://example.com/archive",
        status_code=200,
        content_type="application/zip",
        body=b"opaque",
        body_truncated=False,
    )

    assert xml_result.xml_content_type_observed is True
    assert {
        item.attack_type
        for item in xml_result.observed_surfaces
    } == {"XXE", "XML Entity Expansion"}
    assert serialized_result.serialized_content_type_observed is True
    assert {
        item.attack_type
        for item in serialized_result.observed_surfaces
    } == {"Unsafe Deserialization"}
    assert archive_result.archive_content_type_observed is True
    assert {
        item.attack_type
        for item in archive_result.observed_surfaces
    } == {"Archive Extraction Traversal"}


def test_clean_html_has_no_server_parser_surface() -> None:
    result = analyze_server_parser_surface(
        target_url="https://example.com/about",
        status_code=200,
        content_type="text/html",
        body=b"<html><h1>About</h1></html>",
        body_truncated=False,
    )

    assert (
        result.classification
        is ServerParserSurfaceClassification.NO_SURFACE_OBSERVED
    )
    assert result.observed_surfaces == ()


def test_truncated_response_without_signals_is_inconclusive() -> None:
    result = analyze_server_parser_surface(
        target_url="https://example.com/",
        status_code=200,
        content_type="text/html",
        body=b"<html>",
        body_truncated=True,
    )

    assert (
        result.classification
        is ServerParserSurfaceClassification.INCONCLUSIVE
    )
