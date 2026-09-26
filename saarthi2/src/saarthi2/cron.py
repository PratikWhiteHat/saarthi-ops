"""Minimal 5-field cron parser for time-based triggers.

Fields: ``minute hour day-of-month month day-of-week`` (``*`` any, ``a,b`` list,
``a-b`` range, ``*/n`` / ``a-b/n`` step). Day-of-week: 0 or 7 = Sunday. Used by
the scheduler to fire workflows on a cron expression instead of a fixed interval.
No external dependency.
"""

from __future__ import annotations

from datetime import datetime, timedelta

_FIELD_BOUNDS = (
    (0, 59),  # minute
    (0, 23),  # hour
    (1, 31),  # day of month
    (1, 12),  # month
    (0, 6),   # day of week (Mon=0..Sun=6 after normalizing 7->0 to Sun=6)
)


def _parse_field(spec: str, low: int, high: int) -> set[int]:
    values: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        step = 1
        if "/" in part:
            base, step_str = part.split("/", 1)
            step = int(step_str)
            if step <= 0:
                raise ValueError(f"invalid step {step_str!r}")
        else:
            base = part
        if base in ("*", ""):
            start, end = low, high
        elif "-" in base:
            start_str, end_str = base.split("-", 1)
            start, end = int(start_str), int(end_str)
        else:
            start = end = int(base)
        for value in range(start, end + 1):
            if value < low or value > high:
                raise ValueError(f"value {value} out of range [{low},{high}]")
            if (value - start) % step == 0:
                values.add(value)
    if not values:
        raise ValueError(f"empty cron field {spec!r}")
    return values


def parse_cron(expr: str) -> list[set[int]]:
    """Parse a 5-field cron expression into per-field allowed-value sets."""

    fields = expr.split()
    if len(fields) != 5:
        raise ValueError(f"cron expression must have 5 fields, got {len(fields)}: {expr!r}")
    parsed: list[set[int]] = []
    for spec, (low, high) in zip(fields, _FIELD_BOUNDS, strict=True):
        if spec == "*/1":
            spec = "*"
        # Day-of-week: accept 0 and 7 as Sunday, normalize to Python Mon=0..Sun=6.
        if (low, high) == (0, 6):
            # cron dow: 0/7=Sun..6=Sat -> Python weekday: Mon=0..Sun=6.
            spec = spec.replace("7", "0")
            values = {(6 if v == 0 else v - 1) for v in _parse_field(spec, 0, 6)}
            parsed.append(values)
        else:
            parsed.append(_parse_field(spec, low, high))
    return parsed


def matches(expr: str, when: datetime) -> bool:
    """Whether ``when`` (minute resolution) satisfies the cron expression."""

    minute, hour, dom, month, dow = parse_cron(expr)
    return (
        when.minute in minute
        and when.hour in hour
        and when.day in dom
        and when.month in month
        and when.weekday() in dow
    )


def next_fire(expr: str, after: datetime) -> datetime:
    """Next datetime strictly after ``after`` (truncated to the minute) that matches."""

    parse_cron(expr)  # validate up front
    candidate = (after + timedelta(minutes=1)).replace(second=0, microsecond=0)
    # A matching minute must occur within ~366 days for any valid expression.
    for _ in range(366 * 24 * 60):
        if matches(expr, candidate):
            return candidate
        candidate += timedelta(minutes=1)
    raise ValueError(f"no cron match within a year for {expr!r}")
