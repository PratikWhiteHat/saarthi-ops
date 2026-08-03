from __future__ import annotations

import hashlib
import os
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from shutil import which


class ToolRunnerError(RuntimeError):
    """Raised when an approved external tool cannot be executed safely."""


@dataclass(frozen=True)
class ToolProfile:
    """Approved external-tool definition."""

    name: str
    executable_candidates: tuple[str, ...]
    timeout_seconds: int
    max_output_bytes: int = 5_000_000


@dataclass(frozen=True)
class ToolOutputEvent:
    """One bounded output line emitted by an approved tool."""

    tool_name: str
    stream: str
    line: str


@dataclass(frozen=True)
class ToolRunResult:
    """Captured result from one controlled external-tool execution."""

    tool_name: str
    executable: str
    arguments: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    stdout_sha256: str
    stderr_sha256: str
    timed_out: bool


SUBFINDER_PROFILE = ToolProfile(
    name="subfinder",
    executable_candidates=(
        "/opt/homebrew/bin/subfinder",
        "/usr/local/bin/subfinder",
        str(Path.home() / "go/bin/subfinder"),
        "subfinder",
    ),
    timeout_seconds=180,
)

AMASS_PROFILE = ToolProfile(
    name="amass",
    executable_candidates=(
        "/opt/homebrew/bin/amass",
        "/usr/local/bin/amass",
        str(Path.home() / "go/bin/amass"),
        "amass",
    ),
    timeout_seconds=240,
)

ASSETFINDER_PROFILE = ToolProfile(
    name="assetfinder",
    executable_candidates=(
        str(Path.home() / "go/bin/assetfinder"),
        "/opt/homebrew/bin/assetfinder",
        "/usr/local/bin/assetfinder",
        "assetfinder",
    ),
    timeout_seconds=120,
)

PD_HTTPX_PROFILE = ToolProfile(
    name="projectdiscovery-httpx",
    executable_candidates=(
        str(Path.home() / "go/bin/httpx"),
        "/opt/homebrew/bin/httpx",
        "/usr/local/bin/httpx",
    ),
    timeout_seconds=240,
)


KATANA_PROFILE = ToolProfile(
    name="projectdiscovery-katana",
    executable_candidates=(
        "/opt/homebrew/bin/katana",
        "/usr/local/bin/katana",
        str(Path.home() / "go/bin/katana"),
    ),
    timeout_seconds=240,
    max_output_bytes=10_000_000,
)

NUCLEI_PROFILE = ToolProfile(
    name="nuclei",
    executable_candidates=(
        "/opt/homebrew/bin/nuclei",
        "/usr/local/bin/nuclei",
        str(Path.home() / "go/bin/nuclei"),
        "nuclei",
    ),
    timeout_seconds=600,
)


def resolve_executable(profile: ToolProfile) -> str | None:
    """Resolve the first executable matching an approved profile."""

    for candidate in profile.executable_candidates:
        if "/" in candidate:
            path = Path(candidate).expanduser()

            if path.is_file() and os.access(path, os.X_OK):
                return str(path)

            continue

        resolved = which(candidate)

        if resolved:
            return resolved

    return None


def run_tool(
    profile: ToolProfile,
    arguments: list[str],
    *,
    on_output: Callable[[ToolOutputEvent], None] | None = None,
) -> ToolRunResult:
    """Run an approved tool and optionally stream bounded output lines."""

    executable = resolve_executable(profile)

    if executable is None:
        raise ToolRunnerError(
            f"Approved tool '{profile.name}' is not installed or executable."
        )

    command = [executable, *arguments]

    try:
        process = subprocess.Popen(
            command,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            env={
                **os.environ,
                "NO_COLOR": "1",
            },
            start_new_session=True,
        )
    except OSError as exc:
        raise ToolRunnerError(
            f"Unable to start approved tool '{profile.name}': {exc}"
        ) from exc

    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    buffer_lock = threading.Lock()

    max_stream_events = 500
    max_event_line_chars = 1_000
    emitted_events = 0
    emitted_lock = threading.Lock()

    def emit(stream: str, raw_line: bytes) -> None:
        nonlocal emitted_events

        if on_output is None:
            return

        line = raw_line.decode(
            "utf-8",
            errors="replace",
        ).strip()

        if not line:
            return

        with emitted_lock:
            if emitted_events >= max_stream_events:
                return
            emitted_events += 1

        event = ToolOutputEvent(
            tool_name=profile.name,
            stream=stream,
            line=line[:max_event_line_chars],
        )

        try:
            on_output(event)
        except Exception:
            # A display or persistence callback must not break tool execution.
            return

    def read_stream(
        stream_name: str,
        pipe,
        destination: bytearray,
    ) -> None:
        if pipe is None:
            return

        try:
            while True:
                raw_line = pipe.readline()

                if not raw_line:
                    break

                with buffer_lock:
                    remaining = (
                        profile.max_output_bytes
                        - len(destination)
                    )

                    if remaining > 0:
                        destination.extend(
                            raw_line[:remaining]
                        )

                emit(stream_name, raw_line)
        finally:
            pipe.close()

    stdout_thread = threading.Thread(
        target=read_stream,
        args=(
            "stdout",
            process.stdout,
            stdout_buffer,
        ),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=read_stream,
        args=(
            "stderr",
            process.stderr,
            stderr_buffer,
        ),
        daemon=True,
    )

    stdout_thread.start()
    stderr_thread.start()

    deadline = time.monotonic() + profile.timeout_seconds
    timed_out = False

    while process.poll() is None:
        if time.monotonic() >= deadline:
            timed_out = True
            process.terminate()

            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

            break

        time.sleep(0.05)

    if not timed_out:
        process.wait()

    stdout_thread.join(timeout=2)
    stderr_thread.join(timeout=2)

    raw_stdout = bytes(stdout_buffer)
    raw_stderr = bytes(stderr_buffer)

    return ToolRunResult(
        tool_name=profile.name,
        executable=executable,
        arguments=tuple(arguments),
        exit_code=(-1 if timed_out else process.returncode),
        stdout=raw_stdout.decode(
            "utf-8",
            errors="replace",
        ),
        stderr=raw_stderr.decode(
            "utf-8",
            errors="replace",
        ),
        stdout_sha256=hashlib.sha256(
            raw_stdout
        ).hexdigest(),
        stderr_sha256=hashlib.sha256(
            raw_stderr
        ).hexdigest(),
        timed_out=timed_out,
    )
