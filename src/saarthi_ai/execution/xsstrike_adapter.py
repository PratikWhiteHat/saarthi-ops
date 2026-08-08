"""Adapter for XSStrike — reflected/DOM XSS detection.

XSStrike actively injects XSS payloads, so — like sqlmap/ghauri — it is
operator-authorized per run. The adapter keeps runs targeted and
non-destructive by construction:
- scans only the single provided URL (no --crawl / --seeds site spidering);
- never uses --blind (blind/stored XSS fires in OTHER users'/admins' browsers,
  out of scope for a bounded reflected/DOM check);
- no --proxy and no custom payload files.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from saarthi_ai.execution.tool_runner import (
    XSSTRIKE_PROFILE,
    ToolOutputEvent,
    ToolRunResult,
    run_tool,
)

# A working XSStrike payload reports an efficiency score; treat a high score as
# a confirmed reflected/DOM XSS.
_EFFICIENCY_RE = re.compile(r"efficiency:\s*(\d+)", re.IGNORECASE)
_VULNERABLE_EFFICIENCY = 90


class XSStrikeError(RuntimeError):
    """Raised when an XSStrike request is invalid or not authorized."""


@dataclass(frozen=True)
class XSStrikeScanResult:
    """Structured result of one authorized XSStrike scan."""

    target_url: str
    vulnerable: bool
    max_efficiency: int
    tool_result: ToolRunResult


def _validate_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise XSStrikeError(
            f"XSStrike target must be an absolute http(s) URL: {url!r}"
        )
    return url


def build_xsstrike_arguments(
    url: str,
    *,
    data: str | None = None,
    json_data: bool = False,
    delay: int = 0,
    timeout: int = 30,
    skip_dom: bool = False,
) -> list[str]:
    """Build a validated, targeted, non-destructive XSStrike argument list."""

    _validate_url(url)
    args = [
        "-u",
        url,
        "--skip",  # non-interactive (do not prompt to continue)
        "-t",
        "1",
        "-d",
        str(max(0, delay)),
        "--timeout",
        str(max(1, timeout)),
    ]
    if data:
        args += ["--data", data]
        if json_data:
            args.append("--json")
    if skip_dom:
        args.append("--skip-dom")
    # --blind, --crawl, --seeds, --proxy and -f are deliberately never emitted.
    return args


def parse_xsstrike_verdict(output: str) -> tuple[bool, int]:
    """Return (vulnerable, max_efficiency) parsed from XSStrike output."""

    efficiencies = [int(match) for match in _EFFICIENCY_RE.findall(output or "")]
    max_efficiency = max(efficiencies) if efficiencies else 0
    return (max_efficiency >= _VULNERABLE_EFFICIENCY, max_efficiency)


def run_xsstrike_scan(
    url: str,
    *,
    data: str | None = None,
    json_data: bool = False,
    delay: int = 0,
    timeout: int = 30,
    skip_dom: bool = False,
    authorized: bool = False,
    on_output: Callable[[ToolOutputEvent], None] | None = None,
) -> XSStrikeScanResult:
    """Run XSStrike against a single URL. Requires explicit authorization.

    ``authorized`` must be True — XSStrike injects live XSS payloads into the
    target, so the caller has to affirm operator authorization for that.
    """

    if not authorized:
        raise XSStrikeError(
            "XSStrike performs active XSS testing; pass authorized=True only "
            "when the operator has approved it."
        )

    target = _validate_url(url)
    args = build_xsstrike_arguments(
        target,
        data=data,
        json_data=json_data,
        delay=delay,
        timeout=timeout,
        skip_dom=skip_dom,
    )
    result = run_tool(XSSTRIKE_PROFILE, args, on_output=on_output)
    combined = (result.stdout or "") + "\n" + (result.stderr or "")
    vulnerable, max_efficiency = parse_xsstrike_verdict(combined)
    return XSStrikeScanResult(
        target_url=target,
        vulnerable=vulnerable,
        max_efficiency=max_efficiency,
        tool_result=result,
    )


__all__ = [
    "XSStrikeError",
    "XSStrikeScanResult",
    "build_xsstrike_arguments",
    "parse_xsstrike_verdict",
    "run_xsstrike_scan",
]
