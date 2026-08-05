from __future__ import annotations

import pytest

from saarthi_ai.execution.nuclei_adapter import (
    NucleiAdapterError,
    NucleiDryRunRequest,
    build_nuclei_invocation_preview,
)


def approved_request(**overrides) -> NucleiDryRunRequest:
    values = {
        "target_url": "https://example.test/",
        "authorized": True,
        "active_testing": True,
        "approval_granted": True,
    }
    values.update(overrides)
    return NucleiDryRunRequest(**values)


def test_builds_fixed_non_executed_nuclei_preview() -> None:
    preview = build_nuclei_invocation_preview(
        approved_request()
    )

    assert preview.tool_name == "nuclei"
    assert preview.target_url == "https://example.test/"
    assert preview.executed is False
    assert preview.subprocess_started is False

    assert preview.arguments == (
        "-u",
        "https://example.test/",
        "-jsonl",
        "-silent",
        "-no-color",
        "-disable-update-check",
        "-rate-limit",
        "2",
        "-concurrency",
        "2",
        "-timeout",
        "10",
        "-retries",
        "0",
        "-tags",
        "exposure,misconfig,tech",
        "-exclude-tags",
        "bruteforce,dos,fuzz,headless,intrusive,token-spray",
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("authorized", False, "authorization"),
        ("active_testing", False, "active testing"),
        ("approval_granted", False, "Explicit operator approval"),
        ("dry_run", False, "dry-run"),
    ],
)
def test_fails_closed_without_required_gate(
    field: str,
    value: bool,
    message: str,
) -> None:
    with pytest.raises(NucleiAdapterError, match=message):
        build_nuclei_invocation_preview(
            approved_request(**{field: value})
        )


@pytest.mark.parametrize(
    "target_url",
    [
        "ftp://example.test/",
        "example.test",
        "https://operator:secret@example.test/",
        "https://example.test/\nsecond-target",
    ],
)
def test_rejects_invalid_or_credential_bearing_target(
    target_url: str,
) -> None:
    with pytest.raises(NucleiAdapterError):
        build_nuclei_invocation_preview(
            approved_request(target_url=target_url)
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("rate_limit_per_second", 0, "rate limit"),
        ("rate_limit_per_second", 3, "rate limit"),
        ("concurrency", 0, "concurrency"),
        ("concurrency", 3, "concurrency"),
        ("timeout_seconds", 0, "timeout"),
        ("timeout_seconds", 11, "timeout"),
    ],
)
def test_rejects_limits_outside_adapter_boundary(
    field: str,
    value: int,
    message: str,
) -> None:
    with pytest.raises(NucleiAdapterError, match=message):
        build_nuclei_invocation_preview(
            approved_request(**{field: value})
        )


def test_preview_timeout_matches_default_request_timeout() -> None:
    request = approved_request()

    preview = build_nuclei_invocation_preview(request)

    assert request.timeout_seconds == 10
    assert preview.timeout_seconds == request.timeout_seconds

    timeout_index = preview.arguments.index("-timeout")

    assert preview.arguments[timeout_index + 1] == str(
        request.timeout_seconds
    )


def test_preview_timeout_matches_custom_request_timeout() -> None:
    request = approved_request(timeout_seconds=7)

    preview = build_nuclei_invocation_preview(request)

    assert preview.timeout_seconds == 7

    timeout_index = preview.arguments.index("-timeout")

    assert preview.arguments[timeout_index + 1] == "7"


def approved_execution_request(**overrides):
    from saarthi_ai.execution.nuclei_adapter import (
        NucleiExecutionRequest,
    )

    preview = build_nuclei_invocation_preview(
        approved_request(
            rate_limit_per_second=1,
            concurrency=1,
            timeout_seconds=7,
        )
    )

    values = {
        "preview": preview,
        "authorization_confirmed": True,
        "active_testing_allowed": True,
        "explicitly_approved": True,
    }
    values.update(overrides)

    return NucleiExecutionRequest(**values)


def test_builds_bounded_non_executed_nuclei_execution_plan() -> None:
    from saarthi_ai.execution.nuclei_adapter import (
        MAX_NUCLEI_OUTPUT_BYTES,
        MAX_NUCLEI_PROCESS_TIMEOUT_SECONDS,
        build_nuclei_execution_plan,
    )

    plan = build_nuclei_execution_plan(
        approved_execution_request()
    )

    assert plan.tool_name == "nuclei"
    assert plan.target_url == "https://example.test/"
    assert plan.rate_limit_per_second == 1
    assert plan.concurrency == 1
    assert plan.request_timeout_seconds == 7
    assert (
        plan.process_timeout_seconds
        == MAX_NUCLEI_PROCESS_TIMEOUT_SECONDS
    )
    assert plan.max_output_bytes == MAX_NUCLEI_OUTPUT_BYTES
    assert plan.executed is False
    assert plan.network_activity is False
    assert plan.subprocess_started is False

    assert plan.arguments == (
        "-u",
        "https://example.test/",
        "-jsonl",
        "-silent",
        "-no-color",
        "-disable-update-check",
        "-rate-limit",
        "1",
        "-concurrency",
        "1",
        "-timeout",
        "7",
        "-retries",
        "0",
        "-tags",
        "exposure,misconfig,tech",
        "-exclude-tags",
        "bruteforce,dos,fuzz,headless,intrusive,token-spray",
    )


@pytest.mark.parametrize(
    ("field", "message"),
    [
        (
            "authorization_confirmed",
            "authorization",
        ),
        (
            "active_testing_allowed",
            "active-testing permission",
        ),
        (
            "explicitly_approved",
            "Explicit operator approval",
        ),
    ],
)
def test_nuclei_execution_plan_fails_closed_without_gate(
    field: str,
    message: str,
) -> None:
    from saarthi_ai.execution.nuclei_adapter import (
        build_nuclei_execution_plan,
    )

    with pytest.raises(NucleiAdapterError, match=message):
        build_nuclei_execution_plan(
            approved_execution_request(**{field: False})
        )


def test_nuclei_execution_plan_rejects_modified_arguments() -> None:
    from dataclasses import replace

    from saarthi_ai.execution.nuclei_adapter import (
        build_nuclei_execution_plan,
    )

    request = approved_execution_request()
    modified_preview = replace(
        request.preview,
        arguments=(
            *request.preview.arguments,
            "-headless",
        ),
    )

    with pytest.raises(
        NucleiAdapterError,
        match="fixed approved invocation",
    ):
        build_nuclei_execution_plan(
            replace(
                request,
                preview=modified_preview,
            )
        )


def test_nuclei_execution_plan_rejects_modified_allowed_tags() -> None:
    from dataclasses import replace

    from saarthi_ai.execution.nuclei_adapter import (
        build_nuclei_execution_plan,
    )

    request = approved_execution_request()
    modified_preview = replace(
        request.preview,
        allowed_tags=(
            *request.preview.allowed_tags,
            "cve",
        ),
    )

    with pytest.raises(
        NucleiAdapterError,
        match="allowed tags",
    ):
        build_nuclei_execution_plan(
            replace(
                request,
                preview=modified_preview,
            )
        )


def test_nuclei_execution_plan_rejects_modified_exclusions() -> None:
    from dataclasses import replace

    from saarthi_ai.execution.nuclei_adapter import (
        build_nuclei_execution_plan,
    )

    request = approved_execution_request()
    modified_preview = replace(
        request.preview,
        excluded_tags=tuple(
            tag
            for tag in request.preview.excluded_tags
            if tag != "intrusive"
        ),
    )

    with pytest.raises(
        NucleiAdapterError,
        match="excluded tags",
    ):
        build_nuclei_execution_plan(
            replace(
                request,
                preview=modified_preview,
            )
        )


def test_nuclei_execution_plan_rejects_wrong_tool_identity() -> None:
    from dataclasses import replace

    from saarthi_ai.execution.nuclei_adapter import (
        build_nuclei_execution_plan,
    )

    request = approved_execution_request()
    modified_preview = replace(
        request.preview,
        tool_name="other-tool",
    )

    with pytest.raises(
        NucleiAdapterError,
        match="tool identity",
    ):
        build_nuclei_execution_plan(
            replace(
                request,
                preview=modified_preview,
            )
        )


def test_nuclei_execution_plan_rejects_already_started_preview() -> None:
    from dataclasses import replace

    from saarthi_ai.execution.nuclei_adapter import (
        build_nuclei_execution_plan,
    )

    request = approved_execution_request()
    modified_preview = replace(
        request.preview,
        subprocess_started=True,
    )

    with pytest.raises(
        NucleiAdapterError,
        match="subprocess already started",
    ):
        build_nuclei_execution_plan(
            replace(
                request,
                preview=modified_preview,
            )
        )
