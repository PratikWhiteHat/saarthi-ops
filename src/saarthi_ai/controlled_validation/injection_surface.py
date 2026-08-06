"""Non-mutating Phase 6C.1 injection-surface analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlsplit

MAX_INPUTS = 1_000
MAX_BODY_CHARACTERS = 131_072

INJECTION_TYPES: tuple[str, ...] = (
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

_NAME_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "SQL Injection": (
        re.compile(r"(?:^|[_-])(id|query|search|sort|order|filter)(?:$|[_-])"),
    ),
    "NoSQL Injection": (
        re.compile(r"(?:^|[_-])(filter|selector|where|document|json)(?:$|[_-])"),
    ),
    "OS Command Injection": (
        re.compile(r"(?:^|[_-])(cmd|command|exec|shell|ping|host)(?:$|[_-])"),
    ),
    "LDAP Injection": (
        re.compile(r"(?:^|[_-])(ldap|directory|distinguished|username|user)(?:$|[_-])"),
    ),
    "XXE Injection": (
        re.compile(r"(?:^|[_-])(xml|document|doctype|entity)(?:$|[_-])"),
    ),
    "XPath/XQuery Injection": (
        re.compile(r"(?:^|[_-])(xpath|xquery|xml|node)(?:$|[_-])"),
    ),
    "Server-Side Template Injection": (
        re.compile(r"(?:^|[_-])(template|view|layout|render)(?:$|[_-])"),
    ),
    "Expression Language Injection": (
        re.compile(r"(?:^|[_-])(expression|expr|formula|evaluate)(?:$|[_-])"),
    ),
    "CRLF/Header Injection": (
        re.compile(r"(?:^|[_-])(header|redirect|return|next|url)(?:$|[_-])"),
    ),
    "Host Header Injection": (
        re.compile(r"(?:^|[_-])(host|hostname|domain|origin|callback)(?:$|[_-])"),
    ),
    "Email Header Injection": (
        re.compile(r"(?:^|[_-])(email|mail|recipient|subject|reply|cc|bcc)(?:$|[_-])"),
    ),
    "Log Injection": (
        re.compile(r"(?:^|[_-])(log|message|event|agent|referer)(?:$|[_-])"),
    ),
    "ORM/Query Language Injection": (
        re.compile(r"(?:^|[_-])(filter|sort|order|include|fields|where)(?:$|[_-])"),
    ),
}


class InjectionSurfaceClassification(StrEnum):
    """Conservative classification of passive injection surfaces."""

    SURFACE_OBSERVED = "injection_surface_observed"
    NO_SURFACE_OBSERVED = "no_injection_surface_observed"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class InjectionSurfaceSignal:
    """Aggregate signal for one official injection category."""

    injection_type: str
    signal_count: int
    sources: tuple[str, ...]


@dataclass(frozen=True)
class InjectionSurfaceValidationResult:
    """Aggregate analysis with raw names, values, and bodies discarded."""

    validator_id: str
    classification: InjectionSurfaceClassification
    reason: str
    injection_types_covered: tuple[str, ...]
    observed_surfaces: tuple[InjectionSurfaceSignal, ...]
    query_parameter_count: int
    form_input_count: int
    json_input_observed: bool
    xml_input_observed: bool
    body_truncated: bool
    analysis_truncated: bool
    parameter_names_discarded: bool = True
    parameter_values_discarded: bool = True
    response_body_discarded: bool = True
    target_unchanged: bool = True
    parameters_mutated: bool = False
    request_body_sent: bool = False
    payload_generated: bool = False
    exploit_executed: bool = False


class _InputNameParser(HTMLParser):
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
        if len(self.names) >= MAX_INPUTS:
            self.analysis_truncated = True
            return
        attributes = {
            name.lower(): value
            for name, value in attrs
            if name
        }
        name = attributes.get("name")
        if name:
            self.names.append(name[:256].lower())


def _matched_types(name: str) -> tuple[str, ...]:
    normalized = name.lower()
    return tuple(
        injection_type
        for injection_type, patterns in _NAME_PATTERNS.items()
        if any(pattern.search(normalized) for pattern in patterns)
    )


def analyze_injection_surface(
    *,
    target_url: str,
    status_code: int,
    content_type: str | None,
    body: bytes,
    body_truncated: bool,
) -> InjectionSurfaceValidationResult:
    """Inspect existing input surfaces without generating or sending payloads."""

    counts = {name: 0 for name in INJECTION_TYPES}
    sources: dict[str, set[str]] = {
        name: set() for name in INJECTION_TYPES
    }

    raw_query_fields = urlsplit(target_url).query.split("&")
    query_truncated = len(raw_query_fields) > MAX_INPUTS
    bounded_query = "&".join(raw_query_fields[:MAX_INPUTS])
    query_names = [
        name[:256].lower()
        for name, _value in parse_qsl(
            bounded_query,
            keep_blank_values=True,
            max_num_fields=MAX_INPUTS,
        )
    ]
    for name in query_names:
        for injection_type in _matched_types(name):
            counts[injection_type] += 1
            sources[injection_type].add("query_parameter")

    normalized_content_type = (content_type or "").lower()
    json_input_observed = "json" in normalized_content_type
    xml_input_observed = (
        "xml" in normalized_content_type
        or "soap" in normalized_content_type
    )
    if json_input_observed:
        for injection_type in (
            "NoSQL Injection",
            "Expression Language Injection",
            "ORM/Query Language Injection",
        ):
            counts[injection_type] += 1
            sources[injection_type].add("json_content_type")
    if xml_input_observed:
        for injection_type in (
            "XXE Injection",
            "XPath/XQuery Injection",
            "LDAP Injection",
        ):
            counts[injection_type] += 1
            sources[injection_type].add("xml_content_type")

    parser = _InputNameParser()
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
        for injection_type in _matched_types(name):
            counts[injection_type] += 1
            sources[injection_type].add("html_form_control")

    analysis_truncated = (
        parser.analysis_truncated
        or len(body) > MAX_BODY_CHARACTERS
        or query_truncated
    )
    observed = tuple(
        InjectionSurfaceSignal(
            injection_type=name,
            signal_count=counts[name],
            sources=tuple(sorted(sources[name])),
        )
        for name in INJECTION_TYPES
        if counts[name]
    )

    if observed:
        classification = (
            InjectionSurfaceClassification.SURFACE_OBSERVED
        )
        reason = (
            "Potential injection-relevant input surfaces were observed "
            "from existing request or response metadata; this is not a "
            "vulnerability confirmation."
        )
    elif (
        body_truncated
        or analysis_truncated
        or parse_failed
        or not 200 <= status_code < 400
    ):
        classification = InjectionSurfaceClassification.INCONCLUSIVE
        reason = (
            "The bounded response was incomplete or unsuitable for a "
            "conclusive input-surface inventory."
        )
    else:
        classification = (
            InjectionSurfaceClassification.NO_SURFACE_OBSERVED
        )
        reason = (
            "No injection-relevant input surface was identified in the "
            "approved URL or bounded response."
        )

    return InjectionSurfaceValidationResult(
        validator_id="6C.1-injection-surface-analysis",
        classification=classification,
        reason=reason,
        injection_types_covered=INJECTION_TYPES,
        observed_surfaces=observed,
        query_parameter_count=len(query_names),
        form_input_count=len(parser.names),
        json_input_observed=json_input_observed,
        xml_input_observed=xml_input_observed,
        body_truncated=body_truncated,
        analysis_truncated=analysis_truncated,
    )
