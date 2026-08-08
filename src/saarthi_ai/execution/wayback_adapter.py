"""Adapter for the wabarc/wayback archiver.

WARNING: this tool PUBLISHES the target's pages to PUBLIC web archives
(Internet Archive, archive.today, IPFS, Telegraph, Ghostarchive). That is
outward-facing and effectively irreversible — archived copies get cached and
indexed by third parties. It therefore breaks Saarthi's local-only default and
is treated like the other intrusive tools: OFF by default, and every run must
be explicitly authorized by the operator.

Deliberately NOT exposed here: daemon mode (`-d`), Tor (`--tor`), and any
credential/token flags. Only the read-only-style archive backends are allowed.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from saarthi_ai.execution.tool_runner import (
    WAYBACK_PROFILE,
    ToolOutputEvent,
    ToolRunResult,
    run_tool,
)

# Allowed archive backends -> wayback flag. All publish to a public archive.
ARCHIVE_BACKENDS: dict[str, str] = {
    "ia": "--ia",  # Internet Archive
    "is": "--is",  # archive.today
    "ph": "--ph",  # Telegraph
    "ga": "--ga",  # Ghostarchive
    "ip": "--ip",  # IPFS (via configured daemon)
}
DEFAULT_BACKENDS: tuple[str, ...] = ("ia", "is")

_URL_RE = re.compile(r"https?://[^\s'\"<>]+")


class WaybackError(RuntimeError):
    """Raised when a wayback request is invalid or not authorized."""


@dataclass(frozen=True)
class WaybackArchiveResult:
    """Structured result of one authorized wayback archive run."""

    target_url: str
    backends: tuple[str, ...]
    archived_urls: tuple[str, ...]
    tool_result: ToolRunResult


def _validate_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise WaybackError(
            f"wayback target must be an absolute http(s) URL: {url!r}"
        )
    return url


def build_wayback_arguments(
    url: str,
    backends: tuple[str, ...],
) -> list[str]:
    """Build a validated, non-destructive wayback argument list.

    Only archive backends are permitted; daemon/Tor/token flags are never
    emitted. The target URL is validated as absolute http(s).
    """

    _validate_url(url)
    if not backends:
        raise WaybackError("At least one archive backend is required.")

    args: list[str] = []
    for name in backends:
        flag = ARCHIVE_BACKENDS.get(name)
        if flag is None:
            raise WaybackError(
                f"Unsupported or disallowed wayback backend: {name!r}. "
                f"Allowed: {', '.join(sorted(ARCHIVE_BACKENDS))}."
            )
        if flag not in args:
            args.append(flag)
    args.append(url)
    return args


def parse_archived_urls(stdout: str) -> tuple[str, ...]:
    """Extract the archived-copy URLs wayback prints, de-duplicated."""

    seen: list[str] = []
    for match in _URL_RE.findall(stdout or ""):
        if match not in seen:
            seen.append(match)
    return tuple(seen)


def run_wayback_archive(
    url: str,
    *,
    backends: tuple[str, ...] = DEFAULT_BACKENDS,
    authorized: bool = False,
    on_output: Callable[[ToolOutputEvent], None] | None = None,
) -> WaybackArchiveResult:
    """Archive ``url`` to public web archives. Requires explicit authorization.

    ``authorized`` must be True — this publishes the target externally, so the
    caller has to affirm operator authorization for that outward action.
    """

    if not authorized:
        raise WaybackError(
            "wayback publishes the target to public archives; pass "
            "authorized=True only when the operator has approved that."
        )

    target = _validate_url(url)
    args = build_wayback_arguments(target, tuple(backends))
    result = run_tool(WAYBACK_PROFILE, args, on_output=on_output)
    return WaybackArchiveResult(
        target_url=target,
        backends=tuple(backends),
        archived_urls=parse_archived_urls(result.stdout),
        tool_result=result,
    )


__all__ = [
    "ARCHIVE_BACKENDS",
    "DEFAULT_BACKENDS",
    "ToolOutputEvent",
    "WaybackArchiveResult",
    "WaybackError",
    "build_wayback_arguments",
    "parse_archived_urls",
    "run_wayback_archive",
]
