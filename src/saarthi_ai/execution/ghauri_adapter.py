"""Adapter for ghauri — blind-SQLi detection/exploitation cross-check.

ghauri is an intrusive active-testing tool (it sends SQL-injection payloads to
the target), so — exactly like sqlmap — it is operator-authorized per run.

The adapter keeps runs NON-DESTRUCTIVE by construction:
- only blind-focused techniques (B/T/E) are allowed;
- at most identity-proof enumeration (--banner/--current-user/--current-db/
  --hostname) is added;
- data-exfiltration and shell flags (--dump, --tables, --columns, -D/-T/-C,
  --sql-shell) and tamper/evasion are never emitted.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from saarthi_ai.execution.tool_runner import (
    GHAURI_PROFILE,
    ToolOutputEvent,
    ToolRunResult,
    run_tool,
)

# Blind-focused techniques ghauri accepts (subset of its BEST set).
_SAFE_TECHNIQUES = {"B", "T", "E", "BT", "BE", "TE", "BET"}
# Read-only identity proof; NEVER data dump or shells.
_IDENTITY_PROOF_FLAGS = (
    "--banner",
    "--current-user",
    "--current-db",
    "--hostname",
)


class GhauriError(RuntimeError):
    """Raised when a ghauri request is invalid or not authorized."""


@dataclass(frozen=True)
class GhauriCrossCheckResult:
    """Structured result of one authorized ghauri cross-check run."""

    target_url: str
    parameter: str
    technique: str
    injectable: bool
    tool_result: ToolRunResult


def _validate_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise GhauriError(
            f"ghauri target must be an absolute http(s) URL: {url!r}"
        )
    return url


def build_ghauri_arguments(
    url: str,
    parameter: str,
    *,
    technique: str = "BT",
    level: int = 1,
    delay: int = 1,
    timeout: int = 30,
    identity_proof: bool = True,
    match_string: str | None = None,
) -> list[str]:
    """Build a validated, non-destructive ghauri argument list."""

    _validate_url(url)
    if not parameter or not parameter.strip():
        raise GhauriError("A testable parameter (-p) is required.")

    normalized = technique.upper().strip()
    if normalized not in _SAFE_TECHNIQUES:
        raise GhauriError(
            f"Only blind techniques are allowed: {sorted(_SAFE_TECHNIQUES)}; "
            f"got {technique!r}."
        )
    if not 1 <= level <= 3:
        raise GhauriError("ghauri level must be between 1 and 3.")

    args = [
        "-u",
        url,
        "-p",
        parameter.strip(),
        "--technique",
        normalized,
        "--level",
        str(level),
        "--delay",
        str(max(0, delay)),
        "--timeout",
        str(max(1, timeout)),
        "--threads",
        "1",
        "--batch",
        "--flush-session",
        "--confirm",
    ]
    if match_string:
        args += ["--string", match_string]
    if identity_proof:
        args += list(_IDENTITY_PROOF_FLAGS)
    return args


_INJECTABLE_RE = re.compile(
    r"is vulnerable|appears? to be injectable|is injectable|"
    r"injection point\(s\)",
    re.IGNORECASE,
)
_NOT_INJECTABLE_RE = re.compile(
    r"not injectable|does not (?:seem|appear) to be injectable|"
    r"all tested parameters do not appear",
    re.IGNORECASE,
)


def parse_ghauri_verdict(stdout: str) -> bool:
    """True when ghauri reports the parameter injectable, else False."""

    text = stdout or ""
    if _NOT_INJECTABLE_RE.search(text):
        return False
    return bool(_INJECTABLE_RE.search(text))


def run_ghauri_crosscheck(
    url: str,
    parameter: str,
    *,
    technique: str = "BT",
    level: int = 1,
    delay: int = 1,
    timeout: int = 30,
    identity_proof: bool = True,
    match_string: str | None = None,
    authorized: bool = False,
    on_output: Callable[[ToolOutputEvent], None] | None = None,
) -> GhauriCrossCheckResult:
    """Run ghauri as a blind-SQLi cross-check. Requires explicit authorization.

    ``authorized`` must be True — ghauri actively injects payloads into the
    target, so the caller has to affirm operator authorization for that.
    """

    if not authorized:
        raise GhauriError(
            "ghauri performs active SQL-injection testing; pass "
            "authorized=True only when the operator has approved it."
        )

    target = _validate_url(url)
    args = build_ghauri_arguments(
        target,
        parameter,
        technique=technique,
        level=level,
        delay=delay,
        timeout=timeout,
        identity_proof=identity_proof,
        match_string=match_string,
    )
    result = run_tool(GHAURI_PROFILE, args, on_output=on_output)
    return GhauriCrossCheckResult(
        target_url=target,
        parameter=parameter.strip(),
        technique=technique.upper().strip(),
        injectable=parse_ghauri_verdict(result.stdout),
        tool_result=result,
    )


__all__ = [
    "GhauriCrossCheckResult",
    "GhauriError",
    "build_ghauri_arguments",
    "parse_ghauri_verdict",
    "run_ghauri_crosscheck",
]
