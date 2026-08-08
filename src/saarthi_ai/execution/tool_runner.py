from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from shutil import which

# Registry of live approved-tool subprocesses. Tools are launched in their own
# session (start_new_session=True), so if the operator quits the UI mid-run
# they would otherwise be orphaned and keep scanning the target. The UI calls
# terminate_active_tools() on quit to stop them.
_active_processes: set[subprocess.Popen[bytes]] = set()
_active_processes_lock = threading.Lock()


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    """Terminate a tool process and its session group, then reap it."""

    if process.poll() is not None:
        return

    def _signal_group(sig: int) -> bool:
        try:
            os.killpg(os.getpgid(process.pid), sig)
            return True
        except (ProcessLookupError, PermissionError, OSError):
            return False

    if not _signal_group(signal.SIGTERM):
        try:
            process.terminate()
        except OSError:
            return

    try:
        process.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        pass

    if not _signal_group(signal.SIGKILL):
        try:
            process.kill()
        except OSError:
            return

    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        return


def terminate_active_tools() -> int:
    """Terminate every running approved-tool subprocess.

    Called when the operator quits the UI so nuclei/sqlmap (and any other
    approved tool) do not keep executing against the target after exit.
    Returns the number of processes that were signalled.
    """

    with _active_processes_lock:
        processes = list(_active_processes)

    for process in processes:
        _terminate_process(process)

    with _active_processes_lock:
        for process in processes:
            _active_processes.discard(process)

    return len(processes)


class ToolRunnerError(RuntimeError):
    """Raised when an approved external tool cannot be executed safely."""


@dataclass(frozen=True)
class ToolProfile:
    """Approved external-tool definition."""

    name: str
    executable_candidates: tuple[str, ...]
    timeout_seconds: int
    max_output_bytes: int = 5_000_000
    max_arguments: int = 128
    max_argument_length: int = 8_192


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
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    aborted: bool = False


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

SQLMAP_PROFILE = ToolProfile(
    name="sqlmap",
    executable_candidates=(
        "/opt/homebrew/bin/sqlmap",
        "/usr/local/bin/sqlmap",
        "sqlmap",
    ),
    timeout_seconds=300,
    max_output_bytes=1_000_000,
    max_arguments=64,
    max_argument_length=4_096,
)

# wabarc/wayback — archives a page to PUBLIC web archives (IA, archive.today,
# IPFS, Telegraph, Ghostarchive). Outward-facing / effectively irreversible, so
# it is opt-in and operator-authorized per run (see execution/wayback_adapter).
WAYBACK_PROFILE = ToolProfile(
    name="wayback",
    executable_candidates=(
        "/opt/homebrew/bin/wayback",
        "/usr/local/bin/wayback",
        str(Path.home() / "go/bin/wayback"),
        "wayback",
    ),
    timeout_seconds=300,
)

# ghauri — advanced blind-SQLi detection/exploitation (sqlmap alternative).
# Intrusive active testing, so it is operator-authorized like sqlmap; the
# adapter keeps it non-destructive (blind techniques + identity proof only).
GHAURI_PROFILE = ToolProfile(
    name="ghauri",
    executable_candidates=(
        str(Path.home() / ".local/bin/ghauri"),
        "/opt/homebrew/bin/ghauri",
        "/usr/local/bin/ghauri",
        "ghauri",
    ),
    timeout_seconds=600,
    max_output_bytes=1_000_000,
    max_arguments=64,
    max_argument_length=4_096,
)


def validate_tool_arguments(
    profile: ToolProfile,
    arguments: list[str],
) -> None:
    """Reject arguments that exceed the generic runner safety boundary."""

    if profile.max_arguments < 0:
        raise ToolRunnerError(
            f"Approved tool '{profile.name}' has an invalid argument limit."
        )

    if profile.max_argument_length < 1:
        raise ToolRunnerError(
            f"Approved tool '{profile.name}' has an invalid argument-length limit."
        )

    if len(arguments) > profile.max_arguments:
        raise ToolRunnerError(
            f"Approved tool '{profile.name}' received too many arguments: "
            f"{len(arguments)} exceeds {profile.max_arguments}."
        )

    for index, argument in enumerate(arguments):
        if not isinstance(argument, str):
            raise ToolRunnerError(
                f"Approved tool '{profile.name}' argument {index} is not text."
            )

        if len(argument) > profile.max_argument_length:
            raise ToolRunnerError(
                f"Approved tool '{profile.name}' argument {index} exceeds "
                f"{profile.max_argument_length} characters."
            )

        if any(ord(character) < 32 or ord(character) == 127 for character in argument):
            raise ToolRunnerError(
                f"Approved tool '{profile.name}' argument {index} contains "
                "a prohibited control character."
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
    abort_check: Callable[[], bool] | None = None,
) -> ToolRunResult:
    """Run an approved tool and optionally stream bounded output lines.

    ``abort_check`` is polled while the tool runs; when it returns True the
    process (and its session group) is terminated early and the result is
    marked ``aborted``. The adaptive controller uses this to stop a run the
    moment it detects a condition (WAF, reconnect, rate-limit) worth adapting.
    """

    validate_tool_arguments(profile, arguments)

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

    with _active_processes_lock:
        _active_processes.add(process)

    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    buffer_lock = threading.Lock()
    truncated_streams = {
        "stdout": False,
        "stderr": False,
    }

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

                    if len(raw_line) > remaining:
                        truncated_streams[stream_name] = True

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
    aborted = False

    def _stop() -> None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    while process.poll() is None:
        if time.monotonic() >= deadline:
            timed_out = True
            _stop()
            break

        if abort_check is not None and abort_check():
            aborted = True
            _stop()
            break

        time.sleep(0.05)

    if not (timed_out or aborted):
        process.wait()

    stdout_thread.join(timeout=2)
    stderr_thread.join(timeout=2)

    with _active_processes_lock:
        _active_processes.discard(process)

    raw_stdout = bytes(stdout_buffer)
    raw_stderr = bytes(stderr_buffer)

    return ToolRunResult(
        tool_name=profile.name,
        executable=executable,
        arguments=tuple(arguments),
        exit_code=(-1 if timed_out or aborted else process.returncode),
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
        stdout_truncated=truncated_streams["stdout"],
        stderr_truncated=truncated_streams["stderr"],
        aborted=aborted,
    )
