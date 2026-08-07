"""Adaptive tool control: detect WAF / reconnect / rate-limit in a tool's

live output and automatically retry it with bounded, allowlisted settings.

Design constraints:
- The model never emits raw flags. Adaptations come from a fixed, per-tool
  allowlist and are re-validated here (defense in depth).
- WAF bypass (sqlmap --tamper / --random-agent) is only ever applied when
  ``allow_waf_bypass`` is set (authorized targets). OS/SQL shells, filesystem
  access and bulk dumping are never added by any adaptation.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from saarthi_ai.execution.tool_runner import (
    ToolOutputEvent,
    ToolProfile,
    ToolRunResult,
    run_tool,
)

# A curated, non-destructive tamper set (generic obfuscation only).
SAFE_TAMPER_SCRIPTS = "space2comment,between,randomcase"

# Flags an adaptation is ever allowed to set/add, per tool. Anything outside
# this set is rejected before it can reach the tool.
ALLOWED_ADAPTIVE_SET_FLAGS: dict[str, frozenset[str]] = {
    "sqlmap": frozenset({"--delay", "--timeout", "--retries", "--tamper"}),
    "nuclei": frozenset({"-rate-limit", "-timeout", "-retries"}),
}
ALLOWED_ADAPTIVE_ADD_FLAGS: dict[str, frozenset[str]] = {
    "sqlmap": frozenset({"--random-agent"}),
    "nuclei": frozenset(),
}
# WAF-bypass flags gated behind allow_waf_bypass.
WAF_BYPASS_FLAGS = frozenset({"--tamper", "--random-agent"})


class AdaptiveCondition(StrEnum):
    """A condition detected in a tool's output that warrants adaptation."""

    WAF = "waf"
    RATE_LIMITED = "rate_limited"
    CONNECTION_RESET = "connection_reset"


_PATTERNS: dict[str, list[tuple[AdaptiveCondition, re.Pattern[str]]]] = {
    "sqlmap": [
        (
            AdaptiveCondition.WAF,
            re.compile(
                r"waf/ips|protected by some kind of waf|"
                r"40[36]\s*\(?(forbidden|not acceptable)?\)?|"
                r"has declined the request|blocked by",
                re.IGNORECASE,
            ),
        ),
        (
            AdaptiveCondition.RATE_LIMITED,
            re.compile(r"429|too many requests", re.IGNORECASE),
        ),
        (
            AdaptiveCondition.CONNECTION_RESET,
            re.compile(
                r"connection (?:reset|timed out|refused|dropped)|"
                r"unable to connect|reconnect|connection to the target",
                re.IGNORECASE,
            ),
        ),
    ],
    "nuclei": [
        (
            AdaptiveCondition.RATE_LIMITED,
            re.compile(r"429|too many requests|rate.?limit", re.IGNORECASE),
        ),
        (
            AdaptiveCondition.CONNECTION_RESET,
            re.compile(
                r"connection reset|connection refused|i/o timeout|"
                r"context deadline exceeded|no route to host|"
                r"could not resolve",
                re.IGNORECASE,
            ),
        ),
    ],
}


@dataclass(frozen=True)
class Adaptation:
    """A bounded change to a tool's arguments in response to a condition."""

    condition: AdaptiveCondition
    set_flags: dict[str, str] = field(default_factory=dict)
    add_flags: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class AdaptationEvent:
    """Emitted when the controller adapts and relaunches a tool."""

    tool_name: str
    attempt: int
    condition: AdaptiveCondition
    arguments: tuple[str, ...]
    note: str


def detect_condition(
    tool_name: str,
    text: str,
) -> AdaptiveCondition | None:
    """Return the first adaptive condition matched in one output line."""

    for condition, pattern in _PATTERNS.get(tool_name, []):
        if pattern.search(text):
            return condition
    return None


def plan_adaptation(
    tool_name: str,
    condition: AdaptiveCondition,
    attempt: int,
    *,
    allow_waf_bypass: bool,
) -> Adaptation | None:
    """Map a detected condition to a bounded, escalating adaptation."""

    delay = str(min(1 + attempt, 5))

    if tool_name == "sqlmap":
        if condition is AdaptiveCondition.WAF:
            set_flags = {"--delay": delay}
            add_flags: tuple[str, ...] = ()
            note = "WAF detected → add delay"
            if allow_waf_bypass:
                add_flags = ("--random-agent",)
                note = "WAF detected → randomize UA + add delay"
                if attempt >= 2:
                    set_flags["--tamper"] = SAFE_TAMPER_SCRIPTS
                    note = "WAF persists → bounded tamper + randomize UA"
            else:
                note = "WAF detected → back off (evasion disabled)"
            return Adaptation(condition, set_flags, add_flags, note)
        if condition is AdaptiveCondition.RATE_LIMITED:
            return Adaptation(
                condition,
                {"--delay": str(min(2 * attempt, 8))},
                (),
                "Rate-limited → back off with delay",
            )
        if condition is AdaptiveCondition.CONNECTION_RESET:
            return Adaptation(
                condition,
                {"--timeout": "20", "--retries": "3", "--delay": delay},
                (),
                "Connection unstable → raise timeout/retries",
            )

    if tool_name == "nuclei":
        if condition in (
            AdaptiveCondition.RATE_LIMITED,
            AdaptiveCondition.WAF,
        ):
            return Adaptation(
                condition,
                {"-rate-limit": "1", "-timeout": "15", "-retries": "2"},
                (),
                "Rate-limited → throttle rate + raise timeout",
            )
        if condition is AdaptiveCondition.CONNECTION_RESET:
            return Adaptation(
                condition,
                {"-timeout": "20", "-retries": "3"},
                (),
                "Connection unstable → raise timeout/retries",
            )

    return None


def _validate_adaptation(
    tool_name: str,
    adaptation: Adaptation,
    *,
    allow_waf_bypass: bool,
) -> None:
    """Fail closed if an adaptation touches a non-allowlisted flag."""

    allowed_set = ALLOWED_ADAPTIVE_SET_FLAGS.get(tool_name, frozenset())
    allowed_add = ALLOWED_ADAPTIVE_ADD_FLAGS.get(tool_name, frozenset())

    for flag in adaptation.set_flags:
        if flag not in allowed_set:
            raise ValueError(f"Adaptation set flag not allowed: {flag}")
    for flag in adaptation.add_flags:
        if flag not in allowed_add:
            raise ValueError(f"Adaptation add flag not allowed: {flag}")

    if not allow_waf_bypass:
        used = set(adaptation.set_flags) | set(adaptation.add_flags)
        if used & WAF_BYPASS_FLAGS:
            raise ValueError(
                "WAF-bypass flag used without allow_waf_bypass."
            )


def _set_flag(arguments: list[str], flag: str, value: str) -> list[str]:
    """Set (replace or append) a flag's value across both arg styles."""

    for index, argument in enumerate(arguments):
        if argument == flag:  # space form: "-flag value"
            if index + 1 < len(arguments):
                return (
                    arguments[: index + 1] + [value] + arguments[index + 2 :]
                )
            return arguments + [value]
        if argument.startswith(flag + "="):  # equals form: "--flag=value"
            return (
                arguments[:index] + [f"{flag}={value}"] + arguments[index + 1 :]
            )

    if flag.startswith("--"):
        return arguments + [f"{flag}={value}"]
    return arguments + [flag, value]


def apply_adaptation(
    arguments: list[str],
    adaptation: Adaptation,
) -> list[str]:
    """Return a new argument list with the adaptation applied."""

    result = list(arguments)
    for flag, value in adaptation.set_flags.items():
        result = _set_flag(result, flag, value)
    for flag in adaptation.add_flags:
        if flag not in result:
            result.append(flag)
    return result


def run_tool_adaptively(
    profile: ToolProfile,
    base_arguments: list[str],
    *,
    allow_waf_bypass: bool = False,
    max_attempts: int = 3,
    on_output: Callable[[ToolOutputEvent], None] | None = None,
    on_adapt: Callable[[AdaptationEvent], None] | None = None,
) -> ToolRunResult:
    """Run a tool, adapting and relaunching it when a condition is detected."""

    arguments = list(base_arguments)
    result: ToolRunResult | None = None

    for attempt in range(1, max_attempts + 1):
        holder: dict[str, AdaptiveCondition | None] = {"condition": None}
        is_last = attempt == max_attempts

        def watch(
            event: ToolOutputEvent,
            _holder: dict[str, AdaptiveCondition | None] = holder,
            _is_last: bool = is_last,
        ) -> None:
            if _holder["condition"] is None and not _is_last:
                detected = detect_condition(profile.name, event.line)
                if detected is not None:
                    _holder["condition"] = detected
            if on_output is not None:
                on_output(event)

        result = run_tool(
            profile,
            arguments,
            on_output=watch,
            abort_check=lambda _holder=holder: _holder["condition"] is not None,
        )

        condition = holder["condition"]
        if condition is None:
            return result

        adaptation = plan_adaptation(
            profile.name,
            condition,
            attempt,
            allow_waf_bypass=allow_waf_bypass,
        )
        if adaptation is None:
            return result

        _validate_adaptation(
            profile.name,
            adaptation,
            allow_waf_bypass=allow_waf_bypass,
        )
        arguments = apply_adaptation(arguments, adaptation)

        if on_adapt is not None:
            on_adapt(
                AdaptationEvent(
                    tool_name=profile.name,
                    attempt=attempt,
                    condition=condition,
                    arguments=tuple(arguments),
                    note=adaptation.note,
                )
            )

    assert result is not None
    return result
