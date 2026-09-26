"""File-watch trigger (mtime poll), bounded via injection seams."""

from __future__ import annotations

import asyncio
from pathlib import Path

from saarthi2.config import Settings
from saarthi2.distributed import Job
from saarthi2.triggers import run_watch


def _settings(tmp_path) -> Settings:
    return Settings(work_dir=tmp_path / "work", workflows_dir=tmp_path / "wf")


def test_watch_fires_on_change(tmp_path) -> None:
    fired: list[int] = []
    ticks = iter([100.0, 101.0, 101.0, 102.0])  # baseline, change, no-change, change

    def fake_stat(_path: Path) -> float:
        return next(ticks)

    async def no_sleep(_s: float) -> None:
        return None

    async def run_once() -> object:
        fired.append(1)
        return None

    count = asyncio.run(
        run_watch(
            Job(workflow="x"), _settings(tmp_path),
            path=str(tmp_path), max_checks=3,
            stat=fake_stat, sleep=no_sleep, run_once=run_once,
        )
    )
    # baseline=100; checks see 101 (fire), 101 (no), 102 (fire) -> 2 fires
    assert count == 2
    assert len(fired) == 2


def test_watch_stops_after_max_fires(tmp_path) -> None:
    ticks = iter([0.0] + [float(i) for i in range(1, 20)])

    def fake_stat(_path: Path) -> float:
        return next(ticks)

    async def no_sleep(_s: float) -> None:
        return None

    async def run_once() -> object:
        return None

    count = asyncio.run(
        run_watch(
            Job(workflow="x"), _settings(tmp_path),
            path=str(tmp_path), max_fires=3,
            stat=fake_stat, sleep=no_sleep, run_once=run_once,
        )
    )
    assert count == 3


def test_newest_mtime_helper(tmp_path) -> None:
    from saarthi2.triggers import _newest_mtime

    assert _newest_mtime(tmp_path / "missing") == 0.0
    f = tmp_path / "a.txt"
    f.write_text("x")
    assert _newest_mtime(f) > 0
    assert _newest_mtime(tmp_path) > 0  # directory: newest child
