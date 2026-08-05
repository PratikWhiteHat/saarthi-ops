"""Non-executing Nuclei adapter contract for controlled validation."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from saarthi_ai.execution.tool_runner import NUCLEI_PROFILE

MAX_NUCLEI_RATE_LIMIT = 2
MAX_NUCLEI_CONCURRENCY = 2
MAX_NUCLEI_TIMEOUT_SECONDS = 10

ALLOWED_NUCLEI_TAGS = (
    "exposure",
    "misconfig",
    "tech",
)

EXCLUDED_NUCLEI_TAGS = (
    "bruteforce",
    "dos",
    "fuzz",
    "headless",
    "intrusive",
    "token-spray",
)


class NucleiAdapterError(ValueError):
    """Raised when a Nuclei dry-run proposal fails closed."""


@dataclass(frozen=True)
class NucleiDryRunRequest:
    """One approved, non-executed Nuclei invocation proposal."""

    target_url: str
    authorized: bool
    active_testing: bool
    approval_granted: bool
    rate_limit_per_second: int = MAX_NUCLEI_RATE_LIMIT
    concurrency: int = MAX_NUCLEI_CONCURRENCY
    timeout_seconds: int = MAX_NUCLEI_TIMEOUT_SECONDS
    dry_run: bool = True


@dataclass(frozen=True)
class NucleiInvocationPreview:
    """Fixed Nuclei command arguments that have not been executed."""

    tool_name: str
    target_url: str
    arguments: tuple[str, ...]
    timeout_seconds: int
    rate_limit_per_second: int
    concurrency: int
    allowed_tags: tuple[str, ...]
    excluded_tags: tuple[str, ...]
    executed: bool = False
    subprocess_started: bool = False


def _normalize_target_url(value: str) -> str:
    """Validate one credential-free absolute HTTP(S) target URL."""

    candidate = value.strip()
    parsed = urlsplit(candidate)

    if (
        parsed.scheme.lower() not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise NucleiAdapterError(
            "Nuclei requires a credential-free absolute HTTP or HTTPS target."
        )

    if any(ord(character) < 32 or ord(character) == 127 for character in candidate):
        raise NucleiAdapterError(
            "Nuclei target contains a prohibited control character."
        )

    return candidate


def build_nuclei_invocation_preview(
    request: NucleiDryRunRequest,
) -> NucleiInvocationPreview:
    """Build fixed conservative Nuclei arguments without starting a process."""

    if request.dry_run is not True:
        raise NucleiAdapterError(
            "Nuclei execution is not enabled. A dry-run request is required."
        )

    if request.authorized is not True:
        raise NucleiAdapterError(
            "Nuclei target authorization must be explicitly confirmed."
        )

    if request.active_testing is not True:
        raise NucleiAdapterError(
            "Nuclei requires active testing to be permitted."
        )

    if request.approval_granted is not True:
        raise NucleiAdapterError(
            "Explicit operator approval is required for Nuclei."
        )

    if not 1 <= request.rate_limit_per_second <= MAX_NUCLEI_RATE_LIMIT:
        raise NucleiAdapterError(
            f"Nuclei rate limit must be between 1 and "
            f"{MAX_NUCLEI_RATE_LIMIT} requests per second."
        )

    if not 1 <= request.concurrency <= MAX_NUCLEI_CONCURRENCY:
        raise NucleiAdapterError(
            f"Nuclei concurrency must be between 1 and "
            f"{MAX_NUCLEI_CONCURRENCY}."
        )

    if not 1 <= request.timeout_seconds <= MAX_NUCLEI_TIMEOUT_SECONDS:
        raise NucleiAdapterError(
            f"Nuclei timeout must be between 1 and "
            f"{MAX_NUCLEI_TIMEOUT_SECONDS} seconds."
        )

    target_url = _normalize_target_url(request.target_url)

    arguments = (
        "-u",
        target_url,
        "-jsonl",
        "-silent",
        "-no-color",
        "-disable-update-check",
        "-rate-limit",
        str(request.rate_limit_per_second),
        "-concurrency",
        str(request.concurrency),
        "-timeout",
        str(request.timeout_seconds),
        "-retries",
        "0",
        "-tags",
        ",".join(ALLOWED_NUCLEI_TAGS),
        "-exclude-tags",
        ",".join(EXCLUDED_NUCLEI_TAGS),
    )

    return NucleiInvocationPreview(
        tool_name=NUCLEI_PROFILE.name,
        target_url=target_url,
        arguments=arguments,
        timeout_seconds=request.timeout_seconds,
        rate_limit_per_second=request.rate_limit_per_second,
        concurrency=request.concurrency,
        allowed_tags=ALLOWED_NUCLEI_TAGS,
        excluded_tags=EXCLUDED_NUCLEI_TAGS,
    )


@dataclass(frozen=True)
class NucleiExecutionRequest:
    """Approved request to validate one fixed Nuclei invocation."""

    preview: NucleiInvocationPreview
    authorization_confirmed: bool
    active_testing_allowed: bool
    explicitly_approved: bool


@dataclass(frozen=True)
class NucleiExecutionPlan:
    """Validated fixed Nuclei invocation ready for a later runner phase."""

    tool_name: str
    target_url: str
    arguments: tuple[str, ...]
    request_timeout_seconds: int
    rate_limit_per_second: int
    concurrency: int
    process_timeout_seconds: int
    max_output_bytes: int
    executed: bool = False
    network_activity: bool = False
    subprocess_started: bool = False


MAX_NUCLEI_PROCESS_TIMEOUT_SECONDS = 120
MAX_NUCLEI_OUTPUT_BYTES = 1_000_000


def build_nuclei_execution_plan(
    request: NucleiExecutionRequest,
) -> NucleiExecutionPlan:
    """Validate an exact conservative Nuclei invocation without execution."""

    if request.authorization_confirmed is not True:
        raise NucleiAdapterError(
            "Stored Nuclei target authorization must be confirmed."
        )

    if request.active_testing_allowed is not True:
        raise NucleiAdapterError(
            "Stored active-testing permission is required for Nuclei."
        )

    if request.explicitly_approved is not True:
        raise NucleiAdapterError(
            "Explicit operator approval is required for Nuclei execution."
        )

    preview = request.preview

    if preview.executed is not False:
        raise NucleiAdapterError(
            "Nuclei execution requires a non-executed preview."
        )

    if preview.subprocess_started is not False:
        raise NucleiAdapterError(
            "Nuclei preview indicates that a subprocess already started."
        )

    rebuilt = build_nuclei_invocation_preview(
        NucleiDryRunRequest(
            target_url=preview.target_url,
            authorized=True,
            active_testing=True,
            approval_granted=True,
            rate_limit_per_second=preview.rate_limit_per_second,
            concurrency=preview.concurrency,
            timeout_seconds=preview.timeout_seconds,
            dry_run=True,
        )
    )

    if preview.tool_name != NUCLEI_PROFILE.name:
        raise NucleiAdapterError(
            "Nuclei preview tool identity does not match the approved profile."
        )

    if preview.arguments != rebuilt.arguments:
        raise NucleiAdapterError(
            "Nuclei arguments do not match the fixed approved invocation."
        )

    if preview.allowed_tags != ALLOWED_NUCLEI_TAGS:
        raise NucleiAdapterError(
            "Nuclei allowed tags do not match the approved safe set."
        )

    if preview.excluded_tags != EXCLUDED_NUCLEI_TAGS:
        raise NucleiAdapterError(
            "Nuclei excluded tags do not match the approved safe set."
        )

    return NucleiExecutionPlan(
        tool_name=preview.tool_name,
        target_url=preview.target_url,
        arguments=preview.arguments,
        request_timeout_seconds=preview.timeout_seconds,
        rate_limit_per_second=preview.rate_limit_per_second,
        concurrency=preview.concurrency,
        process_timeout_seconds=MAX_NUCLEI_PROCESS_TIMEOUT_SECONDS,
        max_output_bytes=MAX_NUCLEI_OUTPUT_BYTES,
    )
