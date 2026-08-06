"""Tests for the non-executing Phase 6C.1 SQLmap preview."""

from __future__ import annotations

import pytest

from saarthi_ai.execution.sqlmap_adapter import (
    PROHIBITED_SQLMAP_CAPABILITIES,
    SqlmapMethod,
    SqlmapPostContentType,
    SqlmapPreviewError,
    SqlmapPreviewRequest,
    build_sqlmap_invocation_preview,
)


def approved_request(
    **overrides: object,
) -> SqlmapPreviewRequest:
    values: dict[str, object] = {
        "target_url": "https://example.test/search?id=private-value",
        "parameter_name": "id",
        "method": SqlmapMethod.GET,
        "authorized": True,
        "active_testing": True,
        "intrusive_testing": True,
        "approval_granted": True,
    }
    values.update(overrides)
    return SqlmapPreviewRequest(**values)  # type: ignore[arg-type]


def test_get_preview_redacts_values_and_never_executes() -> None:
    preview = build_sqlmap_invocation_preview(
        approved_request()
    )

    assert preview.tool_name == "sqlmap"
    assert preview.method is SqlmapMethod.GET
    assert "private-value" not in repr(preview)
    assert "%3Credacted%3E" in preview.target_display_url
    assert preview.parameter_name == "id"
    assert preview.level == 1
    assert preview.risk == 1
    assert preview.threads == 1
    assert preview.retries == 0
    assert preview.techniques == "BE"
    assert preview.request_values_stored is False
    assert preview.executable_arguments_built is False
    assert preview.executed is False
    assert preview.network_activity is False
    assert preview.subprocess_started is False


@pytest.mark.parametrize(
    "content_type",
    [
        SqlmapPostContentType.FORM,
        SqlmapPostContentType.JSON,
    ],
)
def test_post_preview_supports_redacted_body_shapes(
    content_type: SqlmapPostContentType,
) -> None:
    preview = build_sqlmap_invocation_preview(
        approved_request(
            target_url="https://example.test/login",
            parameter_name="username",
            method=SqlmapMethod.POST,
            post_parameter_names=("username", "password"),
            post_content_type=content_type,
        )
    )

    arguments = " ".join(preview.redacted_arguments)
    assert "--method=POST" in arguments
    assert "--data=" in arguments
    assert "username" in arguments
    assert "password" in arguments
    assert "redacted" in arguments
    assert "--level=1" in arguments
    assert "--risk=1" in arguments
    assert "--threads=1" in arguments
    assert "--retries=0" in arguments
    assert "--technique=BE" in arguments
    assert preview.post_content_type is content_type


@pytest.mark.parametrize(
    "capability",
    PROHIBITED_SQLMAP_CAPABILITIES,
)
def test_preview_prohibits_high_impact_capabilities(
    capability: str,
) -> None:
    preview = build_sqlmap_invocation_preview(
        approved_request()
    )
    arguments = " ".join(preview.redacted_arguments)

    assert capability in preview.prohibited_capabilities
    assert "--dump" not in arguments
    assert "--os-shell" not in arguments
    assert "--sql-shell" not in arguments
    assert "--file-read" not in arguments
    assert "--file-write" not in arguments
    assert "--tamper" not in arguments
    assert "--crawl" not in arguments
    assert "--forms" not in arguments


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authorized", False),
        ("active_testing", False),
        ("intrusive_testing", False),
        ("approval_granted", False),
        ("dry_run", False),
    ],
)
def test_preview_fails_closed_without_required_gate(
    field: str,
    value: bool,
) -> None:
    with pytest.raises(SqlmapPreviewError):
        build_sqlmap_invocation_preview(
            approved_request(**{field: value})
        )


def test_get_parameter_must_exist_in_target() -> None:
    with pytest.raises(
        SqlmapPreviewError,
        match="absent from the target URL",
    ):
        build_sqlmap_invocation_preview(
            approved_request(parameter_name="missing")
        )


def test_post_parameter_and_content_type_are_required() -> None:
    with pytest.raises(
        SqlmapPreviewError,
        match="content type",
    ):
        build_sqlmap_invocation_preview(
            approved_request(
                target_url="https://example.test/login",
                method=SqlmapMethod.POST,
            )
        )

    with pytest.raises(
        SqlmapPreviewError,
        match="absent from POST",
    ):
        build_sqlmap_invocation_preview(
            approved_request(
                target_url="https://example.test/login",
                method=SqlmapMethod.POST,
                post_parameter_names=("username",),
                post_content_type=SqlmapPostContentType.FORM,
            )
        )


@pytest.mark.parametrize(
    "target_url",
    [
        "example.test",
        "ftp://example.test/",
        "https://operator:secret@example.test/",
        "https://example.test/\nsecond",
    ],
)
def test_rejects_invalid_or_credentialed_target(
    target_url: str,
) -> None:
    with pytest.raises(SqlmapPreviewError):
        build_sqlmap_invocation_preview(
            approved_request(target_url=target_url)
        )
