from __future__ import annotations

from pathlib import Path

from saarthi_ai.execution.tool_runner import (
    ToolProfile,
    resolve_executable,
    run_tool,
)


def create_executable(
    path: Path,
    content: str,
) -> Path:
    """Create a small executable used for controlled runner tests."""

    path.write_text(content)
    path.chmod(0o755)
    return path


def test_resolve_executable_uses_approved_absolute_path(
    tmp_path: Path,
) -> None:
    """The runner should resolve an executable from its allowlisted path."""

    executable = create_executable(
        tmp_path / "test-tool",
        "#!/bin/sh\nexit 0\n",
    )

    profile = ToolProfile(
        name="test-tool",
        executable_candidates=(str(executable),),
        timeout_seconds=5,
    )

    assert resolve_executable(profile) == str(executable)


def test_resolve_executable_returns_none_when_missing(
    tmp_path: Path,
) -> None:
    """Missing approved executables should not resolve."""

    profile = ToolProfile(
        name="missing-tool",
        executable_candidates=(
            str(tmp_path / "does-not-exist"),
        ),
        timeout_seconds=5,
    )

    assert resolve_executable(profile) is None


def test_run_tool_captures_output_and_hashes(
    tmp_path: Path,
) -> None:
    """Controlled execution should capture stdout, stderr and exit status."""

    executable = create_executable(
        tmp_path / "output-tool",
        """#!/bin/sh
printf 'api.example.com\\n'
printf 'diagnostic message\\n' >&2
exit 0
""",
    )

    profile = ToolProfile(
        name="output-tool",
        executable_candidates=(str(executable),),
        timeout_seconds=5,
    )

    result = run_tool(
        profile,
        ["--approved-test"],
    )

    assert result.tool_name == "output-tool"
    assert result.executable == str(executable)
    assert result.arguments == ("--approved-test",)
    assert result.exit_code == 0
    assert result.stdout == "api.example.com\n"
    assert result.stderr == "diagnostic message\n"
    assert len(result.stdout_sha256) == 64
    assert len(result.stderr_sha256) == 64
    assert result.timed_out is False


def test_run_tool_does_not_invoke_shell(
    tmp_path: Path,
) -> None:
    """Shell metacharacters must remain ordinary arguments."""

    executable = create_executable(
        tmp_path / "argument-tool",
        """#!/bin/sh
printf '%s\\n' "$1"
""",
    )

    marker = tmp_path / "must-not-exist"

    profile = ToolProfile(
        name="argument-tool",
        executable_candidates=(str(executable),),
        timeout_seconds=5,
    )

    result = run_tool(
        profile,
        [
            f"; touch {marker}",
        ],
    )

    assert result.exit_code == 0
    assert result.stdout.strip() == f"; touch {marker}"
    assert marker.exists() is False


def test_run_tool_reports_timeout(
    tmp_path: Path,
) -> None:
    """Timed-out tools should return controlled timeout metadata."""

    executable = create_executable(
        tmp_path / "slow-tool",
        """#!/bin/sh
printf 'started\\n'
sleep 2
""",
    )

    profile = ToolProfile(
        name="slow-tool",
        executable_candidates=(str(executable),),
        timeout_seconds=1,
    )

    result = run_tool(
        profile,
        [],
    )

    assert result.exit_code == -1
    assert result.timed_out is True
    assert len(result.stdout_sha256) == 64
    assert len(result.stderr_sha256) == 64


def test_run_tool_streams_stdout_and_stderr(
    tmp_path: Path,
) -> None:
    """Approved tool output should be emitted through the callback."""

    from saarthi_ai.execution.tool_runner import ToolOutputEvent

    executable = create_executable(
        tmp_path / "stream-tool",
        """#!/bin/sh
printf 'first.example.com\\n'
printf 'warning message\\n' >&2
printf 'second.example.com\\n'
""",
    )

    profile = ToolProfile(
        name="stream-tool",
        executable_candidates=(str(executable),),
        timeout_seconds=5,
    )

    events: list[ToolOutputEvent] = []

    result = run_tool(
        profile,
        [],
        on_output=events.append,
    )

    assert result.exit_code == 0
    assert result.stdout == (
        "first.example.com\n"
        "second.example.com\n"
    )
    assert result.stderr == "warning message\n"

    assert {
        (event.stream, event.line)
        for event in events
    } == {
        ("stdout", "first.example.com"),
        ("stdout", "second.example.com"),
        ("stderr", "warning message"),
    }


def test_run_tool_callback_failure_does_not_stop_tool(
    tmp_path: Path,
) -> None:
    """A broken display callback must not terminate tool execution."""

    executable = create_executable(
        tmp_path / "callback-tool",
        """#!/bin/sh
printf 'api.example.com\\n'
""",
    )

    profile = ToolProfile(
        name="callback-tool",
        executable_candidates=(str(executable),),
        timeout_seconds=5,
    )

    def broken_callback(event) -> None:
        raise RuntimeError("display unavailable")

    result = run_tool(
        profile,
        [],
        on_output=broken_callback,
    )

    assert result.exit_code == 0
    assert result.stdout == "api.example.com\n"


def test_run_tool_streams_output_before_timeout(
    tmp_path: Path,
) -> None:
    """Output emitted before a timeout should remain available."""

    executable = create_executable(
        tmp_path / "stream-timeout-tool",
        """#!/bin/sh
printf 'started\\n'
sleep 2
""",
    )

    profile = ToolProfile(
        name="stream-timeout-tool",
        executable_candidates=(str(executable),),
        timeout_seconds=1,
    )

    lines: list[str] = []

    result = run_tool(
        profile,
        [],
        on_output=lambda event: lines.append(event.line),
    )

    assert result.timed_out is True
    assert result.exit_code == -1
    assert result.stdout == "started\n"
    assert lines == ["started"]
