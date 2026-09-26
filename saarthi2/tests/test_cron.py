"""5-field cron parsing + next-fire computation."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from saarthi2.cron import matches, next_fire, parse_cron


def test_parse_wildcards_and_steps() -> None:
    minute, hour, dom, month, dow = parse_cron("*/15 * * * *")
    assert minute == {0, 15, 30, 45}
    assert hour == set(range(24))
    assert dom == set(range(1, 32))
    assert month == set(range(1, 13))
    assert dow == set(range(7))


def test_parse_lists_and_ranges() -> None:
    minute, hour, *_ = parse_cron("0,30 9-17 * * *")
    assert minute == {0, 30}
    assert hour == set(range(9, 18))


def test_dow_sunday_normalization() -> None:
    # cron 0 and 7 both mean Sunday -> Python weekday 6
    _, _, _, _, dow0 = parse_cron("0 0 * * 0")
    _, _, _, _, dow7 = parse_cron("0 0 * * 7")
    assert dow0 == {6} == dow7
    # cron 1 (Monday) -> Python weekday 0
    _, _, _, _, dmon = parse_cron("0 0 * * 1")
    assert dmon == {0}


def test_invalid_expressions() -> None:
    with pytest.raises(ValueError):
        parse_cron("* * * *")  # only 4 fields
    with pytest.raises(ValueError):
        parse_cron("99 * * * *")  # minute out of range


def test_matches() -> None:
    when = datetime(2026, 9, 26, 6, 0, tzinfo=UTC)  # a Saturday, 06:00
    assert matches("0 6 * * *", when) is True
    assert matches("0 7 * * *", when) is False


def test_next_fire_top_of_next_hour() -> None:
    after = datetime(2026, 9, 26, 6, 30, tzinfo=UTC)
    nxt = next_fire("0 * * * *", after)
    assert nxt == datetime(2026, 9, 26, 7, 0, tzinfo=UTC)


def test_next_fire_specific_time() -> None:
    after = datetime(2026, 9, 26, 6, 30, tzinfo=UTC)
    nxt = next_fire("0 9 * * *", after)
    assert nxt == datetime(2026, 9, 26, 9, 0, tzinfo=UTC)


def test_next_fire_skips_to_matching_day() -> None:
    # Every Monday 00:00; after a Saturday should land on the following Monday.
    after = datetime(2026, 9, 26, 6, 30, tzinfo=UTC)  # Saturday
    nxt = next_fire("0 0 * * 1", after)
    assert nxt.weekday() == 0  # Monday
    assert (nxt.hour, nxt.minute) == (0, 0)
