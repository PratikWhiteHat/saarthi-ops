"""Non-executing Phase 6C.2 browser-side attack-surface analysis."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlsplit

MAX_BODY_CHARACTERS = 131_072
MAX_ELEMENTS = 5_000

BROWSER_SURFACE_TYPES: tuple[str, ...] = (
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

_REDIRECT_PARAMETER = re.compile(
    r"(?:^|[_-])(?:next|url|redirect|return|continue|callback)(?:$|[_-])",
)
_SCRIPT_MARKERS: dict[str, tuple[str, ...]] = {
    "dom_html_sink": (
        ".innerhtml",
        ".outerhtml",
        "document.write",
        "insertadjacenthtml",
    ),
    "dynamic_code_sink": (
        "eval(",
        "new function(",
        "settimeout(",
        "setinterval(",
    ),
    "css_sink": (
        ".csstext",
        "insertrule(",
        "style.setproperty(",
    ),
    "dom_clobbering_lookup": (
        "document.forms",
        "nameditem(",
        "window[",
        "document.all",
    ),
    "prototype_mutation": (
        "__proto__",
        ".prototype",
        "object.assign(",
        ".extend(",
    ),
    "redirect_sink": (
        "location.assign(",
        "location.replace(",
        "window.location",
        "document.location",
    ),
    "postmessage": (
        "postmessage(",
        '"message"',
        "'message'",
    ),
    "origin_check": (
        ".origin",
        "origin ==",
        "origin===",
        "origin !=",
        "origin!==",
    ),
    "websocket": (
        "new websocket(",
        "ws://",
        "wss://",
    ),
    "authentication_marker": (
        "authorization",
        "access_token",
        "bearer",
        "session",
    ),
}


class BrowserSurfaceClassification(StrEnum):
    """Conservative browser-surface classification."""

    REVIEW_RECOMMENDED = "review_recommended"
    NO_SURFACE_OBSERVED = "no_browser_surface_observed"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class BrowserSurfaceSignal:
    """Aggregate signal for one official browser-side category."""

    attack_type: str
    signal_count: int
    sources: tuple[str, ...]


@dataclass(frozen=True)
class BrowserSurfaceValidationResult:
    """Aggregate browser metadata with source text and values discarded."""

    validator_id: str
    classification: BrowserSurfaceClassification
    reason: str
    attack_types_covered: tuple[str, ...]
    observed_surfaces: tuple[BrowserSurfaceSignal, ...]
    form_count: int
    form_control_count: int
    script_block_count: int
    inline_handler_count: int
    named_element_count: int
    style_surface_count: int
    redirect_parameter_count: int
    cors_allow_origin_present: bool
    cors_wildcard_origin: bool
    cors_credentials_allowed: bool
    postmessage_handler_observed: bool
    postmessage_origin_check_observed: bool
    websocket_usage_observed: bool
    websocket_auth_signal_observed: bool
    body_truncated: bool
    analysis_truncated: bool
    source_text_discarded: bool = True
    attribute_values_discarded: bool = True
    parameter_names_discarded: bool = True
    parameter_values_discarded: bool = True
    browser_launched: bool = False
    script_executed: bool = False
    parameters_mutated: bool = False
    request_body_sent: bool = False
    payload_generated: bool = False
    exploit_executed: bool = False


class _BrowserSurfaceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.element_count = 0
        self.form_count = 0
        self.form_control_count = 0
        self.script_block_count = 0
        self.inline_handler_count = 0
        self.named_element_count = 0
        self.style_surface_count = 0
        self.meta_refresh_count = 0
        self.marker_counts = {
            marker: 0 for marker in _SCRIPT_MARKERS
        }
        self.analysis_truncated = False
        self._inside_script = False

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if self.element_count >= MAX_ELEMENTS:
            self.analysis_truncated = True
            return
        self.element_count += 1

        normalized_tag = tag.lower()
        attributes = {
            name.lower(): value
            for name, value in attrs
            if name
        }
        if normalized_tag == "form":
            self.form_count += 1
        if normalized_tag in {"input", "select", "textarea"}:
            self.form_control_count += 1
        if normalized_tag == "script":
            self.script_block_count += 1
            self._inside_script = True
        if normalized_tag == "style" or "style" in attributes:
            self.style_surface_count += 1
        if any(name.startswith("on") for name in attributes):
            self.inline_handler_count += 1
        if (
            normalized_tag in {"form", "input", "object", "img", "iframe"}
            and ("id" in attributes or "name" in attributes)
        ):
            self.named_element_count += 1
        if (
            normalized_tag == "meta"
            and (attributes.get("http-equiv") or "").lower() == "refresh"
        ):
            self.meta_refresh_count += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            self._inside_script = False

    def handle_data(self, data: str) -> None:
        if not self._inside_script:
            return
        normalized = data[:MAX_BODY_CHARACTERS].lower()
        for marker, tokens in _SCRIPT_MARKERS.items():
            self.marker_counts[marker] += sum(
                normalized.count(token)
                for token in tokens
            )


def _add_signal(
    counts: dict[str, int],
    sources: dict[str, set[str]],
    attack_type: str,
    count: int,
    source: str,
) -> None:
    if count <= 0:
        return
    counts[attack_type] += count
    sources[attack_type].add(source)


def analyze_browser_surface(
    *,
    target_url: str,
    status_code: int,
    content_type: str | None,
    headers: Mapping[str, str] | None,
    body: bytes,
    body_truncated: bool,
) -> BrowserSurfaceValidationResult:
    """Inventory browser-side surfaces without rendering or executing code."""

    counts = {name: 0 for name in BROWSER_SURFACE_TYPES}
    sources: dict[str, set[str]] = {
        name: set() for name in BROWSER_SURFACE_TYPES
    }
    normalized_headers = {
        str(name).lower(): str(value).strip()
        for name, value in (headers or {}).items()
    }
    allow_origin = normalized_headers.get(
        "access-control-allow-origin"
    )
    cors_allow_origin_present = allow_origin is not None
    cors_wildcard_origin = allow_origin == "*"
    cors_credentials_allowed = (
        normalized_headers.get(
            "access-control-allow-credentials",
            "",
        ).lower()
        == "true"
    )
    if cors_allow_origin_present:
        _add_signal(
            counts,
            sources,
            "CORS Exploitation",
            1,
            "cors_response_header",
        )
    if cors_wildcard_origin:
        _add_signal(
            counts,
            sources,
            "CORS Exploitation",
            1,
            "wildcard_allow_origin",
        )
    if cors_credentials_allowed:
        _add_signal(
            counts,
            sources,
            "CORS Exploitation",
            1,
            "credentials_allowed",
        )

    raw_fields = urlsplit(target_url).query.split("&")
    query_truncated = len(raw_fields) > MAX_ELEMENTS
    bounded_query = "&".join(raw_fields[:MAX_ELEMENTS])
    query_names = tuple(
        name.lower()
        for name, _value in parse_qsl(
            bounded_query,
            keep_blank_values=True,
            max_num_fields=MAX_ELEMENTS,
        )
    )
    redirect_parameter_count = sum(
        _REDIRECT_PARAMETER.search(name) is not None
        for name in query_names
    )
    _add_signal(
        counts,
        sources,
        "Open Redirect",
        redirect_parameter_count,
        "redirect_parameter",
    )

    parser = _BrowserSurfaceParser()
    normalized_content_type = (content_type or "").lower()
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

    html_sink_count = parser.marker_counts["dom_html_sink"]
    dynamic_code_count = parser.marker_counts["dynamic_code_sink"]
    _add_signal(
        counts,
        sources,
        "Reflected XSS",
        min(len(query_names), 1) + html_sink_count,
        "input_and_html_sink",
    )
    _add_signal(
        counts,
        sources,
        "Stored XSS",
        min(parser.form_control_count, 1) + html_sink_count,
        "form_and_html_sink",
    )
    _add_signal(
        counts,
        sources,
        "DOM-Based XSS",
        html_sink_count + dynamic_code_count,
        "client_script_sink",
    )
    _add_signal(
        counts,
        sources,
        "HTML Injection",
        html_sink_count + parser.inline_handler_count,
        "html_mutation_surface",
    )
    _add_signal(
        counts,
        sources,
        "CSS Injection",
        parser.style_surface_count
        + parser.marker_counts["css_sink"],
        "style_surface",
    )
    _add_signal(
        counts,
        sources,
        "DOM Clobbering",
        parser.named_element_count
        + parser.marker_counts["dom_clobbering_lookup"],
        "named_dom_surface",
    )
    _add_signal(
        counts,
        sources,
        "Prototype Pollution",
        parser.marker_counts["prototype_mutation"],
        "prototype_mutation_marker",
    )
    _add_signal(
        counts,
        sources,
        "Open Redirect",
        parser.meta_refresh_count
        + parser.marker_counts["redirect_sink"],
        "client_redirect_surface",
    )

    postmessage_count = parser.marker_counts["postmessage"]
    origin_check_count = parser.marker_counts["origin_check"]
    _add_signal(
        counts,
        sources,
        "postMessage Origin Validation",
        postmessage_count,
        "postmessage_handler",
    )
    websocket_count = parser.marker_counts["websocket"]
    websocket_auth_count = min(
        websocket_count,
        parser.marker_counts["authentication_marker"],
    )
    _add_signal(
        counts,
        sources,
        "WebSocket Authentication Validation",
        websocket_count,
        "websocket_client",
    )
    if websocket_auth_count:
        sources[
            "WebSocket Authentication Validation"
        ].add("authentication_marker")

    observed = tuple(
        BrowserSurfaceSignal(
            attack_type=name,
            signal_count=counts[name],
            sources=tuple(sorted(sources[name])),
        )
        for name in BROWSER_SURFACE_TYPES
        if counts[name]
    )
    analysis_truncated = (
        query_truncated
        or parser.analysis_truncated
        or len(body) > MAX_BODY_CHARACTERS
    )

    if observed:
        classification = BrowserSurfaceClassification.REVIEW_RECOMMENDED
        reason = (
            "Browser-side input, script, redirect, messaging, WebSocket, "
            "or CORS surfaces were observed; no browser code was run and "
            "no vulnerability was confirmed."
        )
    elif (
        body_truncated
        or analysis_truncated
        or parse_failed
        or not 200 <= status_code < 400
    ):
        classification = BrowserSurfaceClassification.INCONCLUSIVE
        reason = (
            "The bounded response was incomplete or unsuitable for a "
            "conclusive browser-surface inventory."
        )
    else:
        classification = (
            BrowserSurfaceClassification.NO_SURFACE_OBSERVED
        )
        reason = (
            "No browser-side attack surface was identified in the "
            "approved URL, response headers, or bounded HTML."
        )

    return BrowserSurfaceValidationResult(
        validator_id="6C.2-browser-attack-surface-analysis",
        classification=classification,
        reason=reason,
        attack_types_covered=BROWSER_SURFACE_TYPES,
        observed_surfaces=observed,
        form_count=parser.form_count,
        form_control_count=parser.form_control_count,
        script_block_count=parser.script_block_count,
        inline_handler_count=parser.inline_handler_count,
        named_element_count=parser.named_element_count,
        style_surface_count=parser.style_surface_count,
        redirect_parameter_count=redirect_parameter_count,
        cors_allow_origin_present=cors_allow_origin_present,
        cors_wildcard_origin=cors_wildcard_origin,
        cors_credentials_allowed=cors_credentials_allowed,
        postmessage_handler_observed=bool(postmessage_count),
        postmessage_origin_check_observed=bool(origin_check_count),
        websocket_usage_observed=bool(websocket_count),
        websocket_auth_signal_observed=bool(websocket_auth_count),
        body_truncated=body_truncated,
        analysis_truncated=analysis_truncated,
    )
