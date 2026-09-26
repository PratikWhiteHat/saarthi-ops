"""Interval + cron scheduling loops (offline, bounded via injection seams)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from saarthi2.config import Settings
from saarthi2.distributed import Job
from saarthi2.scheduler import run_cron_schedule, run_schedule


def _settings(tmp_path) -> Settings:
    return Settings(work_dir=tmp_path / "work", workflows_dir=tmp_path / "wf")


def test_run_schedule_fires_n_times(tmp_path) -> None:
    fired: list[int] = []

    async def run_once() -> object:
        fired.append(1)
        return None

    async def no_sleep(_seconds: float) -> None:
        return None

    count = asyncio.run(
        run_schedule(
            Job(workflow="x"), _settings(tmp_path),
            every=10, times=3, sleep=no_sleep, run_once=run_once,
        )
    )
    assert count == 3
    assert len(fired) == 3


def test_run_cron_schedule_fires_and_waits(tmp_path) -> None:
    waits: list[float] = []
    fired: list[int] = []

    async def run_once() -> object:
        fired.append(1)
        return None

    async def record_sleep(seconds: float) -> None:
        waits.append(seconds)

    # Frozen clock at 06:30; cron fires at the top of every hour -> waits 1800s.
    def now() -> datetime:
        return datetime(2026, 9, 26, 6, 30, tzinfo=UTC)

    count = asyncio.run(
        run_cron_schedule(
            Job(workflow="x"), _settings(tmp_path),
            expr="0 * * * *", times=2,
            sleep=record_sleep, now=now, run_once=run_once,
        )
    )
    assert count == 2
    assert fired == [1, 1]
    assert waits == [1800.0, 1800.0]


def test_run_cron_schedule_rejects_bad_expr(tmp_path) -> None:
    with pytest.raises(ValueError):
        asyncio.run(
            run_cron_schedule(Job(workflow="x"), _settings(tmp_path), expr="nope", times=1)
        )
