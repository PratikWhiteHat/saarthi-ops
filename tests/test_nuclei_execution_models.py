from datetime import UTC, datetime, timedelta

import pytest

from saarthi_ai.execution.nuclei_execution_models import (
    NucleiExecutionResult,
    NucleiExecutionResultError,
)


def build_result(**overrides) -> NucleiExecutionResult:
    started_at = datetime(2026, 8, 5, 10, 0, tzinfo=UTC)

    values = {
        "tool_name": "nuclei",
        "target_url": "https://example.com/",
        "preparation_evidence_id": (
            "evidence-nuclei-preparation"
        ),
        "executable": "/opt/homebrew/bin/nuclei",
        "arguments": (
            "-u",
            "https://example.com/",
            "-jsonl",
            "-silent",
        ),
        "exit_code": 0,
        "timed_out": False,
        "stdout": '{"template-id":"example"}\n',
        "stderr": "",
        "stdout_sha256": "a" * 64,
        "stderr_sha256": "b" * 64,
        "stdout_bytes": len(
            b'{"template-id":"example"}\n'
        ),
        "stderr_bytes": 0,
        "stdout_truncated": False,
        "stderr_truncated": False,
        "started_at": started_at,
        "completed_at": started_at + timedelta(seconds=2),
        "automatic_retry": False,
    }
    values.update(overrides)

    return NucleiExecutionResult(**values)


def test_accepts_bounded_nuclei_execution_result() -> None:
    result = build_result()

    assert result.tool_name == "nuclei"
    assert result.exit_code == 0
    assert result.timed_out is False
    assert result.automatic_retry is False


def test_accepts_timeout_result_with_exit_code_minus_one() -> None:
    result = build_result(
        exit_code=-1,
        timed_out=True,
    )

    assert result.timed_out is True
    assert result.exit_code == -1


def test_rejects_non_nuclei_tool_identity() -> None:
    with pytest.raises(
        NucleiExecutionResultError,
        match="must identify Nuclei",
    ):
        build_result(tool_name="other-tool")


def test_rejects_missing_preparation_evidence() -> None:
    with pytest.raises(
        NucleiExecutionResultError,
        match="requires preparation evidence",
    ):
        build_result(preparation_evidence_id="")


def test_rejects_invalid_output_hash() -> None:
    with pytest.raises(
        NucleiExecutionResultError,
        match="64 hexadecimal",
    ):
        build_result(stdout_sha256="invalid")


def test_rejects_non_hexadecimal_output_hash() -> None:
    with pytest.raises(
        NucleiExecutionResultError,
        match="must be hexadecimal",
    ):
        build_result(stdout_sha256="z" * 64)


def test_rejects_incorrect_stdout_byte_count() -> None:
    with pytest.raises(
        NucleiExecutionResultError,
        match="stdout byte count",
    ):
        build_result(stdout_bytes=1)


def test_rejects_completion_before_start() -> None:
    started_at = datetime(2026, 8, 5, 10, 0, tzinfo=UTC)

    with pytest.raises(
        NucleiExecutionResultError,
        match="cannot precede",
    ):
        build_result(
            started_at=started_at,
            completed_at=started_at - timedelta(seconds=1),
        )


def test_rejects_timeout_with_normal_exit_code() -> None:
    with pytest.raises(
        NucleiExecutionResultError,
        match="must use exit code -1",
    ):
        build_result(
            timed_out=True,
            exit_code=0,
        )


def test_rejects_automatic_retry() -> None:
    with pytest.raises(
        NucleiExecutionResultError,
        match="Automatic retry is prohibited",
    ):
        build_result(automatic_retry=True)
