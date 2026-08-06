"""Tests for non-submitting Phase 6C.6 upload-surface analysis."""

from __future__ import annotations

from saarthi_ai.controlled_validation.upload_surface import (
    MAX_FORMS,
    UploadSurfaceClassification,
    analyze_upload_surface,
)


def analyze(
    body: str,
    *,
    content_type: str | None = "text/html",
    body_truncated: bool = False,
):
    return analyze_upload_surface(
        target_url="https://example.com/account",
        status_code=200,
        content_type=content_type,
        body=body.encode(),
        body_truncated=body_truncated,
    )


def test_upload_form_metadata_is_aggregated_without_retention() -> None:
    secret_name = "private_document"
    secret_value = "/local/private/file.pdf"
    secret_action = "/internal/private-upload"
    result = analyze(
        f"<form method='post' enctype='multipart/form-data' "
        f"action='{secret_action}'>"
        f"<input type='file' name='{secret_name}' "
        f"value='{secret_value}' accept='.pdf' multiple>"
        "</form>"
    )

    assert (
        result.classification
        is UploadSurfaceClassification.UPLOAD_SURFACE_OBSERVED
    )
    assert result.form_count == 1
    assert result.upload_form_count == 1
    assert result.file_input_count == 1
    assert result.post_upload_form_count == 1
    assert result.multipart_upload_form_count == 1
    assert result.restricted_accept_input_count == 1
    assert result.unrestricted_accept_input_count == 0
    assert result.multiple_file_input_count == 1
    assert result.field_names_discarded is True
    assert result.field_values_discarded is True
    assert result.form_actions_discarded is True
    assert result.file_uploaded is False
    assert result.form_submitted is False
    assert result.request_body_sent is False
    assert result.payload_generated is False
    rendered = repr(result)
    assert secret_name not in rendered
    assert secret_value not in rendered
    assert secret_action not in rendered
    assert ".pdf" not in rendered


def test_cross_origin_and_orphan_file_inputs_are_counted() -> None:
    result = analyze(
        "<input type='file'>"
        "<form action='https://outside.example/upload'>"
        "<input type='file'>"
        "</form>"
    )

    assert result.file_input_count == 2
    assert result.upload_form_count == 1
    assert result.cross_origin_upload_form_count == 1
    assert result.orphan_file_input_count == 1
    assert result.unrestricted_accept_input_count == 2


def test_page_without_file_input_has_no_upload_surface() -> None:
    result = analyze(
        "<form method='post'><input name='display_name'></form>"
    )

    assert (
        result.classification
        is UploadSurfaceClassification.NO_UPLOAD_SURFACE_OBSERVED
    )
    assert result.file_input_count == 0


def test_non_html_or_truncated_response_is_inconclusive() -> None:
    non_html = analyze("{}", content_type="application/json")
    truncated = analyze(
        "<input type='file'>",
        body_truncated=True,
    )

    assert (
        non_html.classification
        is UploadSurfaceClassification.INCONCLUSIVE
    )
    assert (
        truncated.classification
        is UploadSurfaceClassification.INCONCLUSIVE
    )


def test_form_limit_fails_closed() -> None:
    body = "".join(
        "<form><input type='file'></form>"
        for _ in range(MAX_FORMS + 1)
    )
    result = analyze(body)

    assert result.form_count == MAX_FORMS
    assert result.analysis_truncated is True
    assert (
        result.classification
        is UploadSurfaceClassification.INCONCLUSIVE
    )
