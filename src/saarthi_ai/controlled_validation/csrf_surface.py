"""Non-submitting Phase 6C.2 CSRF protection-surface analysis."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from saarthi_ai.controlled_validation.session_cookie import (
    analyze_session_cookie_attributes,
)

MAX_FORMS = 100
MAX_INPUTS = 1_000
_TOKEN_NAME_MARKERS = (
    "csrf",
    "xsrf",
    "authenticity_token",
    "requestverificationtoken",
    "__requestverificationtoken",
)


class CsrfSurfaceClassification(StrEnum):
    """Conservative CSRF-surface classification."""

    PROTECTION_SIGNALS_OBSERVED = "protection_signals_observed"
    REVIEW_RECOMMENDED = "review_recommended"
    NOT_APPLICABLE = "not_applicable"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class CsrfSurfaceValidationResult:
    """Safe aggregate with no form or token values retained."""

    validator_id: str
    classification: CsrfSurfaceClassification
    reason: str
    form_count: int
    post_form_count: int
    forms_with_token_signal: int
    forms_without_token_signal: int
    cross_origin_action_count: int
    cookie_count: int
    same_site_protected_cookie_count: int
    protection_sources: tuple[str, ...]
    body_truncated: bool
    analysis_truncated: bool
    token_values_discarded: bool = True
    form_submitted: bool = False
    browser_launched: bool = False
    request_body_sent: bool = False
    payload_generated: bool = False


def _origin(url: str) -> tuple[str, str | None, int | None]:
    parsed = urlsplit(url)
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80
    return parsed.scheme.lower(), parsed.hostname, port


class _FormSurfaceParser(HTMLParser):
    def __init__(self, target_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.target_url = target_url
        self.form_count = 0
        self.post_form_count = 0
        self.forms_with_token_signal = 0
        self.forms_without_token_signal = 0
        self.cross_origin_action_count = 0
        self.input_count = 0
        self.analysis_truncated = False
        self._current_post_form: dict[str, bool] | None = None

    def _finish_form(self) -> None:
        if self._current_post_form is None:
            return
        if self._current_post_form["token"]:
            self.forms_with_token_signal += 1
        else:
            self.forms_without_token_signal += 1
        self._current_post_form = None

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        normalized_tag = tag.lower()
        attributes = {
            name.lower(): value
            for name, value in attrs
            if name
        }

        if normalized_tag == "form":
            self._finish_form()
            if self.form_count >= MAX_FORMS:
                self.analysis_truncated = True
                return
            self.form_count += 1
            method = (attributes.get("method") or "get").lower()
            if method != "post":
                self._current_post_form = None
                return

            self.post_form_count += 1
            action = attributes.get("action")
            if action:
                resolved = urljoin(self.target_url, action)
                try:
                    if _origin(resolved) != _origin(self.target_url):
                        self.cross_origin_action_count += 1
                except ValueError:
                    self.cross_origin_action_count += 1
            self._current_post_form = {"token": False}
            return

        if (
            normalized_tag != "input"
            or self._current_post_form is None
        ):
            return

        if self.input_count >= MAX_INPUTS:
            self.analysis_truncated = True
            return
        self.input_count += 1

        input_type = (attributes.get("type") or "text").lower()
        input_name = (attributes.get("name") or "").lower()
        if (
            input_type == "hidden"
            and (
                input_name in {"_token", "token"}
                or any(
                    marker in input_name
                    for marker in _TOKEN_NAME_MARKERS
                )
            )
        ):
            self._current_post_form["token"] = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._finish_form()

    def close(self) -> None:
        super().close()
        self._finish_form()


def analyze_csrf_surface(
    *,
    target_url: str,
    status_code: int,
    content_type: str | None,
    body: bytes,
    body_truncated: bool,
    set_cookie_headers: tuple[str, ...],
) -> CsrfSurfaceValidationResult:
    """Inspect a retrieved page without submitting or altering a form."""

    parser = _FormSurfaceParser(target_url)
    parse_failed = False
    try:
        parser.feed(body.decode("utf-8", errors="replace"))
        parser.close()
    except (TypeError, ValueError):
        parse_failed = True

    cookie_analysis = analyze_session_cookie_attributes(
        set_cookie_headers
    )
    same_site_protected = sum(
        item.same_site in {"strict", "lax"}
        for item in cookie_analysis.cookie_observations
    )
    protection_sources: list[str] = []
    if parser.forms_with_token_signal:
        protection_sources.append("anti_csrf_field_name")
    if same_site_protected:
        protection_sources.append("same_site_cookie")

    analysis_truncated = (
        parser.analysis_truncated
        or cookie_analysis.analysis_truncated
    )
    if (
        not 200 <= status_code < 300
        or content_type is None
        or "html" not in content_type.lower()
        or body_truncated
        or analysis_truncated
        or parse_failed
    ):
        classification = CsrfSurfaceClassification.INCONCLUSIVE
        reason = (
            "The response was not a complete bounded HTML page or "
            "analysis limits were reached."
        )
    elif parser.post_form_count == 0:
        classification = CsrfSurfaceClassification.NOT_APPLICABLE
        reason = (
            "No POST form was observed in the retrieved HTML response."
        )
    elif (
        parser.forms_without_token_signal == 0
        and parser.cross_origin_action_count == 0
    ):
        classification = (
            CsrfSurfaceClassification.PROTECTION_SIGNALS_OBSERVED
        )
        reason = (
            "Every observed POST form includes an anti-CSRF field-name "
            "signal and no cross-origin form action was observed."
        )
    else:
        classification = CsrfSurfaceClassification.REVIEW_RECOMMENDED
        reason = (
            "One or more POST forms lack an anti-CSRF field-name signal "
            "or use a cross-origin action; manual verification is needed."
        )

    return CsrfSurfaceValidationResult(
        validator_id="6C.2-csrf-protection-surface-validation",
        classification=classification,
        reason=reason,
        form_count=parser.form_count,
        post_form_count=parser.post_form_count,
        forms_with_token_signal=parser.forms_with_token_signal,
        forms_without_token_signal=parser.forms_without_token_signal,
        cross_origin_action_count=parser.cross_origin_action_count,
        cookie_count=cookie_analysis.cookie_count,
        same_site_protected_cookie_count=same_site_protected,
        protection_sources=tuple(protection_sources),
        body_truncated=body_truncated,
        analysis_truncated=analysis_truncated,
    )
