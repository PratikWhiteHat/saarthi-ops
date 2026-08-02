from __future__ import annotations

import hashlib
import os
import subprocess
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
) -> ToolRunResult:
    """Run a fixed approved tool without invoking a shell."""

    executable = resolve_executable(profile)

    if executable is None:
        raise ToolRunnerError(f"Approved tool '{profile.name}' is not installed or executable.")

    command = [executable, *arguments]

    try:
        completed = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            text=False,
            timeout=profile.timeout_seconds,
            check=False,
            env={
                **os.environ,
                "NO_COLOR": "1",
            },
        )

        raw_stdout = completed.stdout[: profile.max_output_bytes]
        raw_stderr = completed.stderr[: profile.max_output_bytes]

        stdout = raw_stdout.decode("utf-8", errors="replace")
        stderr = raw_stderr.decode("utf-8", errors="replace")

        return ToolRunResult(
            tool_name=profile.name,
            executable=executable,
            arguments=tuple(arguments),
            exit_code=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            stdout_sha256=hashlib.sha256(raw_stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(raw_stderr).hexdigest(),
            timed_out=False,
        )

    except subprocess.TimeoutExpired as exc:
        raw_stdout = exc.stdout if isinstance(exc.stdout, bytes) else (exc.stdout or "").encode()
        raw_stderr = exc.stderr if isinstance(exc.stderr, bytes) else (exc.stderr or "").encode()

        return ToolRunResult(
            tool_name=profile.name,
            executable=executable,
            arguments=tuple(arguments),
            exit_code=-1,
            stdout=raw_stdout.decode("utf-8", errors="replace"),
            stderr=raw_stderr.decode("utf-8", errors="replace"),
            stdout_sha256=hashlib.sha256(raw_stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(raw_stderr).hexdigest(),
            timed_out=True,
        )
