"""Tests for non-mutating Phase 6C.3 parameter-surface analysis."""

from __future__ import annotations

from saarthi_ai.controlled_validation.parameter_surface import (
    MAX_PARAMETER_COUNT,
    MAX_QUERY_CHARACTERS,
    ParameterSurfaceClassification,
    analyze_parameter_surface,
)


def test_no_query_is_not_applicable() -> None:
    result = analyze_parameter_surface("https://example.com/account")

    assert (
        result.classification
        is ParameterSurfaceClassification.NOT_APPLICABLE
    )
    assert result.parameter_count == 0
    assert result.target_unchanged is True
    assert result.parameters_mutated is False
    assert result.parser_attack_sent is False
    assert result.payload_generated is False


def test_unique_parameters_have_no_observed_ambiguity() -> None:
    result = analyze_parameter_surface(
        "https://example.com/search?q=saarthi&page=1&filter="
    )

    assert (
        result.classification
        is ParameterSurfaceClassification.NO_AMBIGUITY_OBSERVED
    )
    assert result.parameter_count == 3
    assert result.unique_parameter_count == 3
    assert result.duplicate_parameter_names == ()
    assert result.blank_value_parameter_names == ("filter",)


def test_duplicate_names_are_detected_after_decoding() -> None:
    result = analyze_parameter_surface(
        "https://example.com/search?id=1&%69d=2"
    )

    assert (
        result.classification
        is (
            ParameterSurfaceClassification
            .AMBIGUOUS_SURFACE_OBSERVED
        )
    )
    assert result.duplicate_parameter_names == ("id",)
    assert result.parameter_count == 2
    assert result.target_unchanged is True
    assert result.parameters_mutated is False


def test_bracketed_and_plain_name_variants_are_detected() -> None:
    result = analyze_parameter_surface(
        "https://example.com/?item=one&item%5B%5D=two"
    )

    assert result.variant_parameter_groups == ("item",)
    assert (
        result.classification
        is (
            ParameterSurfaceClassification
            .AMBIGUOUS_SURFACE_OBSERVED
        )
    )


def test_malformed_or_separator_syntax_requests_review() -> None:
    result = analyze_parameter_surface(
        "https://example.com/?=blank&value=%ZZ;other=2"
    )

    assert result.blank_parameter_name_count == 1
    assert result.malformed_percent_encoding is True
    assert result.semicolon_delimiter_observed is True
    assert (
        result.classification
        is (
            ParameterSurfaceClassification
            .AMBIGUOUS_SURFACE_OBSERVED
        )
    )


def test_analysis_limits_fail_closed_as_inconclusive() -> None:
    long_value = "a" * (MAX_QUERY_CHARACTERS + 1)
    result = analyze_parameter_surface(
        f"https://example.com/?value={long_value}"
    )

    assert result.analysis_truncated is True
    assert (
        result.classification
        is ParameterSurfaceClassification.INCONCLUSIVE
    )

    many_parameters = "&".join(
        f"p{index}=1"
        for index in range(MAX_PARAMETER_COUNT + 5)
    )
    count_result = analyze_parameter_surface(
        f"https://example.com/?{many_parameters}"
    )

    assert count_result.analysis_truncated is True
    assert count_result.parameter_count == MAX_PARAMETER_COUNT
    assert (
        count_result.classification
        is ParameterSurfaceClassification.INCONCLUSIVE
    )
