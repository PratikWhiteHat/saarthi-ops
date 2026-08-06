"""Non-mutating Phase 6C.3 HTTP parameter-surface analysis."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import unquote_plus, urlsplit


class ParameterSurfaceClassification(StrEnum):
    """Conservative URL-shape classification, not a vulnerability finding."""

    NO_AMBIGUITY_OBSERVED = "no_ambiguity_observed"
    AMBIGUOUS_SURFACE_OBSERVED = "ambiguous_surface_observed"
    NOT_APPLICABLE = "not_applicable"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class ParameterSurfaceValidationResult:
    """Analysis of the approved URL exactly as supplied by the operator."""

    validator_id: str
    classification: ParameterSurfaceClassification
    reason: str
    parameter_count: int
    unique_parameter_count: int
    duplicate_parameter_names: tuple[str, ...]
    variant_parameter_groups: tuple[str, ...]
    blank_parameter_name_count: int
    blank_value_parameter_names: tuple[str, ...]
    malformed_percent_encoding: bool
    semicolon_delimiter_observed: bool
    analysis_truncated: bool
    target_unchanged: bool = True
    parameters_mutated: bool = False
    parser_attack_sent: bool = False
    payload_generated: bool = False


_MALFORMED_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
_BRACKETED_NAME = re.compile(r"^([^\[\]]+)\[.*\]$")
MAX_QUERY_CHARACTERS = 8_192
MAX_PARAMETER_COUNT = 100
MAX_PARAMETER_NAME_CHARACTERS = 128


def _decode(value: str) -> str:
    return unquote_plus(value, errors="replace")


def analyze_parameter_surface(
    target_url: str,
) -> ParameterSurfaceValidationResult:
    """Inspect query structure without modifying or submitting parameters."""

    raw_query = urlsplit(target_url).query
    if not raw_query:
        return ParameterSurfaceValidationResult(
            validator_id="6C.3-http-parameter-surface-validation",
            classification=(
                ParameterSurfaceClassification.NOT_APPLICABLE
            ),
            reason="The approved target URL contains no query parameters.",
            parameter_count=0,
            unique_parameter_count=0,
            duplicate_parameter_names=(),
            variant_parameter_groups=(),
            blank_parameter_name_count=0,
            blank_value_parameter_names=(),
            malformed_percent_encoding=False,
            semicolon_delimiter_observed=False,
            analysis_truncated=False,
        )

    query_slice = raw_query[:MAX_QUERY_CHARACTERS]
    raw_fields = query_slice.split("&")
    analysis_truncated = (
        len(raw_query) > MAX_QUERY_CHARACTERS
        or len(raw_fields) > MAX_PARAMETER_COUNT
    )
    pairs: list[tuple[str, str]] = []
    blank_name_count = 0
    blank_value_names: set[str] = set()

    for field in raw_fields[:MAX_PARAMETER_COUNT]:
        raw_name, separator, raw_value = field.partition("=")
        name = _decode(raw_name)[:MAX_PARAMETER_NAME_CHARACTERS]
        value = _decode(raw_value) if separator else ""
        pairs.append((name, value))

        if not name:
            blank_name_count += 1
        if not value and name:
            blank_value_names.add(name)

    name_counts = Counter(name for name, _ in pairs if name)
    duplicate_names = tuple(
        sorted(
            name
            for name, count in name_counts.items()
            if count > 1
        )
    )

    variants: dict[str, set[str]] = defaultdict(set)
    for name in name_counts:
        match = _BRACKETED_NAME.match(name)
        base_name = match.group(1) if match else name
        variants[base_name].add(name)

    variant_groups = tuple(
        sorted(
            base_name
            for base_name, names in variants.items()
            if len(names) > 1
        )
    )
    malformed_percent = (
        _MALFORMED_PERCENT.search(query_slice) is not None
    )
    semicolon_delimiter = ";" in query_slice
    ambiguous = bool(
        duplicate_names
        or variant_groups
        or blank_name_count
        or malformed_percent
        or semicolon_delimiter
    )

    if ambiguous:
        classification = (
            ParameterSurfaceClassification
            .AMBIGUOUS_SURFACE_OBSERVED
        )
        reason = (
            "The approved URL contains duplicate or structurally "
            "ambiguous parameter syntax that warrants manual parser "
            "review; no parameter was changed."
        )
    elif analysis_truncated:
        classification = ParameterSurfaceClassification.INCONCLUSIVE
        reason = (
            "The query exceeded bounded analysis limits, so the "
            "parameter surface is inconclusive; no parameter was changed."
        )
    else:
        classification = (
            ParameterSurfaceClassification.NO_AMBIGUITY_OBSERVED
        )
        reason = (
            "No duplicate or structurally ambiguous query-parameter "
            "syntax was observed in the approved URL."
        )

    return ParameterSurfaceValidationResult(
        validator_id="6C.3-http-parameter-surface-validation",
        classification=classification,
        reason=reason,
        parameter_count=len(pairs),
        unique_parameter_count=len(name_counts),
        duplicate_parameter_names=duplicate_names,
        variant_parameter_groups=variant_groups,
        blank_parameter_name_count=blank_name_count,
        blank_value_parameter_names=tuple(
            sorted(blank_value_names)
        ),
        malformed_percent_encoding=malformed_percent,
        semicolon_delimiter_observed=semicolon_delimiter,
        analysis_truncated=analysis_truncated,
    )
