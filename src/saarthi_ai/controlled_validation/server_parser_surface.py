"""Non-mutating Phase 6C.3 server request and parser-surface analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlsplit

MAX_FIELDS = 1_000
MAX_BODY_CHARACTERS = 131_072

SERVER_PARSER_SURFACE_TYPES: tuple[str, ...] = (
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

_NAME_PATTERNS: dict[str, re.Pattern[str]] = {
    "Remote Code Execution": re.compile(
        r"(?:^|[_-])(?:cmd|command|exec|shell|code|evaluate)(?:$|[_-])"
    ),
    "Blind SSRF": re.compile(
        r"(?:^|[_-])(?:url|uri|callback|webhook|endpoint|feed|proxy)(?:$|[_-])"
    ),
    "XXE": re.compile(
        r"(?:^|[_-])(?:xml|doctype|entity|document)(?:$|[_-])"
    ),
    "XML Entity Expansion": re.compile(
        r"(?:^|[_-])(?:xml|doctype|entity|document)(?:$|[_-])"
    ),
    "Path Traversal": re.compile(
        r"(?:^|[_-])(?:path|file|folder|directory|download)(?:$|[_-])"
    ),
    "Local File Inclusion": re.compile(
        r"(?:^|[_-])(?:file|page|template|include|view)(?:$|[_-])"
    ),
    "Remote File Inclusion": re.compile(
        r"(?:^|[_-])(?:file|template|include|resource)(?:$|[_-])"
    ),
    "Unsafe URL Fetch": re.compile(
        r"(?:^|[_-])(?:url|uri|remote|resource|image|fetch)(?:$|[_-])"
    ),
    "Archive Extraction Traversal": re.compile(
        r"(?:^|[_-])(?:archive|zip|tar|extract|bundle|upload)(?:$|[_-])"
    ),
    "Unsafe Deserialization": re.compile(
        r"(?:^|[_-])(?:object|state|blob|serialized|marshal|data)(?:$|[_-])"
    ),
}


class ServerParserSurfaceClassification(StrEnum):
    """Conservative request/parser-surface classification."""

    REVIEW_RECOMMENDED = "review_recommended"
    NO_SURFACE_OBSERVED = "no_server_parser_surface_observed"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class ServerParserSurfaceSignal:
    """Aggregate signal for one official server/parser category."""

    attack_type: str
    signal_count: int
    sources: tuple[str, ...]


@dataclass(frozen=True)
class ServerParserSurfaceValidationResult:
    """Aggregate metadata with names, values, and response body discarded."""

    validator_id: str
    classification: ServerParserSurfaceClassification
    reason: str
    attack_types_covered: tuple[str, ...]
    observed_surfaces: tuple[ServerParserSurfaceSignal, ...]
    query_parameter_count: int
    form_control_count: int
    absolute_url_value_count: int
    duplicate_parameter_count: int
    xml_content_type_observed: bool
    serialized_content_type_observed: bool
    archive_content_type_observed: bool
    body_truncated: bool
    analysis_truncated: bool
    parameter_names_discarded: bool = True
    parameter_values_discarded: bool = True
    form_values_discarded: bool = True
    response_body_discarded: bool = True
    target_unchanged: bool = True
    parameters_mutated: bool = False
    request_body_sent: bool = False
    parser_payload_sent: bool = False
    callback_generated: bool = False
    subprocess_started: bool = False
    payload_generated: bool = False
    exploit_executed: bool = False


class _FormNameParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.names: list[str] = []
        self.analysis_truncated = False

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag.lower() not in {"input", "select", "textarea"}:
            return
        if len(self.names) >= MAX_FIELDS:
            self.analysis_truncated = True
            return
        attributes = {
            name.lower(): value
            for name, value in attrs
            if name
        }
        field_name = attributes.get("name")
        if field_name:
            self.names.append(field_name[:256].lower())


def _add_name_signals(
    name: str,
    source: str,
    counts: dict[str, int],
    sources: dict[str, set[str]],
) -> None:
    for attack_type, pattern in _NAME_PATTERNS.items():
        if pattern.search(name):
            counts[attack_type] += 1
            sources[attack_type].add(source)


def analyze_server_parser_surface(
    *,
    target_url: str,
    status_code: int,
    content_type: str | None,
    body: bytes,
    body_truncated: bool,
) -> ServerParserSurfaceValidationResult:
    """Inventory existing request/parser surfaces without changing input."""

    counts = {name: 0 for name in SERVER_PARSER_SURFACE_TYPES}
    sources: dict[str, set[str]] = {
        name: set() for name in SERVER_PARSER_SURFACE_TYPES
    }
    raw_fields = urlsplit(target_url).query.split("&")
    query_truncated = len(raw_fields) > MAX_FIELDS
    pairs = tuple(
        parse_qsl(
            "&".join(raw_fields[:MAX_FIELDS]),
            keep_blank_values=True,
            max_num_fields=MAX_FIELDS,
        )
    )
    normalized_names = tuple(name[:256].lower() for name, _ in pairs)
    for name in normalized_names:
        _add_name_signals(
            name,
            "query_parameter",
            counts,
            sources,
        )

    absolute_url_value_count = 0
    for name, value in pairs:
        parsed_value = urlsplit(value)
        if (
            parsed_value.scheme.lower() in {"http", "https"}
            and parsed_value.hostname
        ):
            absolute_url_value_count += 1
            normalized_name = name[:256].lower()
            for attack_type in (
                "Blind SSRF",
                "Unsafe URL Fetch",
                "Remote File Inclusion",
            ):
                if _NAME_PATTERNS[attack_type].search(normalized_name):
                    counts[attack_type] += 1
                    sources[attack_type].add("absolute_url_value")

    duplicate_parameter_count = (
        len(normalized_names) - len(set(normalized_names))
    )

    normalized_content_type = (content_type or "").lower()
    xml_content_type_observed = (
        "xml" in normalized_content_type
        or "soap" in normalized_content_type
    )
    serialized_content_type_observed = any(
        marker in normalized_content_type
        for marker in (
            "application/octet-stream",
            "application/x-java-serialized-object",
            "application/x-protobuf",
            "application/msgpack",
        )
    )
    archive_content_type_observed = any(
        marker in normalized_content_type
        for marker in (
            "application/zip",
            "application/x-tar",
            "application/gzip",
            "application/x-7z-compressed",
        )
    )
    if xml_content_type_observed:
        for attack_type in ("XXE", "XML Entity Expansion"):
            counts[attack_type] += 1
            sources[attack_type].add("xml_content_type")
    if serialized_content_type_observed:
        counts["Unsafe Deserialization"] += 1
        sources["Unsafe Deserialization"].add(
            "serialized_content_type"
        )
    if archive_content_type_observed:
        counts["Archive Extraction Traversal"] += 1
        sources["Archive Extraction Traversal"].add(
            "archive_content_type"
        )

    parser = _FormNameParser()
    parse_failed = False
    if "html" in normalized_content_type:
        try:
            parser.feed(
                body[:MAX_BODY_CHARACTERS].decode(
                    "utf-8",
                    errors="replace",
                )
            )
            parser.close()
        except (TypeError, ValueError):
            parse_failed = True
    for name in parser.names:
        _add_name_signals(
            name,
            "html_form_control",
            counts,
            sources,
        )

    observed = tuple(
        ServerParserSurfaceSignal(
            attack_type=name,
            signal_count=counts[name],
            sources=tuple(sorted(sources[name])),
        )
        for name in SERVER_PARSER_SURFACE_TYPES
        if counts[name]
    )
    analysis_truncated = (
        query_truncated
        or parser.analysis_truncated
        or len(body) > MAX_BODY_CHARACTERS
    )
    if observed:
        classification = (
            ServerParserSurfaceClassification.REVIEW_RECOMMENDED
        )
        reason = (
            "Server-side fetch, parser, file, archive, serialization, or "
            "manual execution-review surfaces were observed; no input "
            "was changed and no payload or callback was generated."
        )
    elif (
        body_truncated
        or analysis_truncated
        or parse_failed
        or not 200 <= status_code < 400
    ):
        classification = ServerParserSurfaceClassification.INCONCLUSIVE
        reason = (
            "The bounded response was incomplete or unsuitable for a "
            "conclusive server/parser-surface inventory."
        )
    else:
        classification = (
            ServerParserSurfaceClassification.NO_SURFACE_OBSERVED
        )
        reason = (
            "No server-side request or parser surface was identified in "
            "the approved URL, content type, or bounded HTML."
        )

    return ServerParserSurfaceValidationResult(
        validator_id="6C.3-server-parser-surface-analysis",
        classification=classification,
        reason=reason,
        attack_types_covered=SERVER_PARSER_SURFACE_TYPES,
        observed_surfaces=observed,
        query_parameter_count=len(pairs),
        form_control_count=len(parser.names),
        absolute_url_value_count=absolute_url_value_count,
        duplicate_parameter_count=duplicate_parameter_count,
        xml_content_type_observed=xml_content_type_observed,
        serialized_content_type_observed=(
            serialized_content_type_observed
        ),
        archive_content_type_observed=archive_content_type_observed,
        body_truncated=body_truncated,
        analysis_truncated=analysis_truncated,
    )
