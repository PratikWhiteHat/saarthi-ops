"""Bounded result models for controlled Nuclei execution."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


class NucleiExecutionResultError(ValueError):
    """Raised when a Nuclei execution result violates its contract."""


@dataclass(frozen=True)
class NucleiExecutionResult:
    """Validated bounded outcome from one controlled Nuclei invocation."""

    tool_name: str
    target_url: str
    preparation_evidence_id: str
    executable: str
    arguments: tuple[str, ...]
    exit_code: int
    timed_out: bool
    stdout: str
    stderr: str
    stdout_sha256: str
    stderr_sha256: str
    stdout_bytes: int
    stderr_bytes: int
    stdout_truncated: bool
    stderr_truncated: bool
    started_at: datetime
    completed_at: datetime
    automatic_retry: bool = False

    def __post_init__(self) -> None:
        """Fail closed when execution-result metadata is inconsistent."""

        if self.tool_name != "nuclei":
            raise NucleiExecutionResultError(
                "Controlled execution result must identify Nuclei."
            )

        if not self.target_url:
            raise NucleiExecutionResultError(
                "Controlled Nuclei result requires a target URL."
            )

        if not self.preparation_evidence_id:
            raise NucleiExecutionResultError(
                "Controlled Nuclei result requires preparation evidence."
            )

        if not self.executable:
            raise NucleiExecutionResultError(
                "Controlled Nuclei result requires a resolved executable."
            )

        if not self.arguments:
            raise NucleiExecutionResultError(
                "Controlled Nuclei result requires exact arguments."
            )

        if len(self.stdout_sha256) != 64:
            raise NucleiExecutionResultError(
                "Nuclei stdout SHA-256 must contain 64 hexadecimal characters."
            )

        if len(self.stderr_sha256) != 64:
            raise NucleiExecutionResultError(
                "Nuclei stderr SHA-256 must contain 64 hexadecimal characters."
            )

        try:
            int(self.stdout_sha256, 16)
            int(self.stderr_sha256, 16)
        except ValueError as exc:
            raise NucleiExecutionResultError(
                "Nuclei output hashes must be hexadecimal."
            ) from exc

        if self.stdout_bytes < 0 or self.stderr_bytes < 0:
            raise NucleiExecutionResultError(
                "Nuclei output byte counts cannot be negative."
            )

        if self.stdout_bytes != len(self.stdout.encode("utf-8")):
            raise NucleiExecutionResultError(
                "Nuclei stdout byte count does not match captured output."
            )

        if self.stderr_bytes != len(self.stderr.encode("utf-8")):
            raise NucleiExecutionResultError(
                "Nuclei stderr byte count does not match captured output."
            )

        if self.completed_at < self.started_at:
            raise NucleiExecutionResultError(
                "Nuclei completion time cannot precede its start time."
            )

        if self.timed_out and self.exit_code != -1:
            raise NucleiExecutionResultError(
                "A timed-out Nuclei result must use exit code -1."
            )

        if self.automatic_retry is not False:
            raise NucleiExecutionResultError(
                "Automatic retry is prohibited for controlled Nuclei execution."
            )
