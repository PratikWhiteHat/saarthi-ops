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
