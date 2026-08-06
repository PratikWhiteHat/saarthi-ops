"""Non-submitting Phase 6C.6 file-upload surface analysis."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

MAX_FORMS = 100
MAX_INPUTS = 1_000


class UploadSurfaceClassification(StrEnum):
    """Conservative upload-surface classification."""

    UPLOAD_SURFACE_OBSERVED = "upload_surface_observed"
    NO_UPLOAD_SURFACE_OBSERVED = "no_upload_surface_observed"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class UploadSurfaceValidationResult:
    """Aggregate upload metadata with field values and actions discarded."""

    validator_id: str
    classification: UploadSurfaceClassification
    reason: str
    form_count: int
    upload_form_count: int
    file_input_count: int
    post_upload_form_count: int
    multipart_upload_form_count: int
    cross_origin_upload_form_count: int
    orphan_file_input_count: int
    restricted_accept_input_count: int
    unrestricted_accept_input_count: int
    multiple_file_input_count: int
    body_truncated: bool
    analysis_truncated: bool
    field_names_discarded: bool = True
    field_values_discarded: bool = True
    form_actions_discarded: bool = True
    file_uploaded: bool = False
    form_submitted: bool = False
    request_body_sent: bool = False
    payload_generated: bool = False


def _origin(url: str) -> tuple[str, str | None, int | None]:
    parsed = urlsplit(url)
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80
    return parsed.scheme.lower(), parsed.hostname, port


class _UploadSurfaceParser(HTMLParser):
    def __init__(self, target_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.target_url = target_url
        self.form_count = 0
        self.upload_form_count = 0
        self.file_input_count = 0
        self.post_upload_form_count = 0
        self.multipart_upload_form_count = 0
        self.cross_origin_upload_form_count = 0
        self.orphan_file_input_count = 0
        self.restricted_accept_input_count = 0
        self.unrestricted_accept_input_count = 0
        self.multiple_file_input_count = 0
        self.input_count = 0
        self.analysis_truncated = False
        self._current_form: dict[str, bool] | None = None

    def _finish_form(self) -> None:
        form = self._current_form
        if form is None:
            return
        if form["has_file"]:
            self.upload_form_count += 1
            if form["post"]:
                self.post_upload_form_count += 1
            if form["multipart"]:
                self.multipart_upload_form_count += 1
            if form["cross_origin"]:
                self.cross_origin_upload_form_count += 1
        self._current_form = None

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
            enctype = (attributes.get("enctype") or "").lower()
            cross_origin = False
            action = attributes.get("action")
            if action:
                try:
                    cross_origin = _origin(
                        urljoin(self.target_url, action)
                    ) != _origin(self.target_url)
                except ValueError:
                    cross_origin = True

            self._current_form = {
                "has_file": False,
                "post": method == "post",
                "multipart": enctype == "multipart/form-data",
                "cross_origin": cross_origin,
            }
            return

        if normalized_tag != "input":
            return
        if self.input_count >= MAX_INPUTS:
            self.analysis_truncated = True
            return
        self.input_count += 1

        if (attributes.get("type") or "text").lower() != "file":
            return

        self.file_input_count += 1
        if self._current_form is None:
            self.orphan_file_input_count += 1
        else:
            self._current_form["has_file"] = True

        accept = attributes.get("accept")
        if accept is not None and accept.strip():
            self.restricted_accept_input_count += 1
        else:
            self.unrestricted_accept_input_count += 1
        if "multiple" in attributes:
            self.multiple_file_input_count += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._finish_form()

    def close(self) -> None:
        super().close()
        self._finish_form()


def analyze_upload_surface(
    *,
    target_url: str,
    status_code: int,
    content_type: str | None,
    body: bytes,
    body_truncated: bool,
) -> UploadSurfaceValidationResult:
    """Inspect HTML upload metadata without submitting a form or file."""

    parser = _UploadSurfaceParser(target_url)
    parse_failed = False
    try:
        parser.feed(body.decode("utf-8", errors="replace"))
        parser.close()
    except (TypeError, ValueError):
        parse_failed = True

    if (
        not 200 <= status_code < 300
        or content_type is None
        or "html" not in content_type.lower()
        or body_truncated
        or parser.analysis_truncated
        or parse_failed
    ):
        classification = UploadSurfaceClassification.INCONCLUSIVE
        reason = (
            "The response was not a complete bounded HTML page or "
            "analysis limits were reached."
        )
    elif parser.file_input_count:
        classification = (
            UploadSurfaceClassification.UPLOAD_SURFACE_OBSERVED
        )
        reason = (
            "One or more file-input surfaces were observed; no file was "
            "selected, uploaded, or submitted."
        )
    else:
        classification = (
            UploadSurfaceClassification.NO_UPLOAD_SURFACE_OBSERVED
        )
        reason = (
            "No file-input surface was observed in the retrieved HTML."
        )

    return UploadSurfaceValidationResult(
        validator_id="6C.6-file-upload-surface-validation",
        classification=classification,
        reason=reason,
        form_count=parser.form_count,
        upload_form_count=parser.upload_form_count,
        file_input_count=parser.file_input_count,
        post_upload_form_count=parser.post_upload_form_count,
        multipart_upload_form_count=(
            parser.multipart_upload_form_count
        ),
        cross_origin_upload_form_count=(
            parser.cross_origin_upload_form_count
        ),
        orphan_file_input_count=parser.orphan_file_input_count,
        restricted_accept_input_count=(
            parser.restricted_accept_input_count
        ),
        unrestricted_accept_input_count=(
            parser.unrestricted_accept_input_count
        ),
        multiple_file_input_count=(
            parser.multiple_file_input_count
        ),
        body_truncated=body_truncated,
        analysis_truncated=parser.analysis_truncated,
    )
