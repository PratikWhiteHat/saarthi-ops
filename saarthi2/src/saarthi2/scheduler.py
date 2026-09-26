"""Scheduling — run a workflow repeatedly on an interval.

Webhook triggers are handled by the REST API (``POST /api/runs`` and
``/api/hooks/{workflow}``); this module covers time-based (interval) scheduling.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from saarthi2.config import Settings
from saarthi2.cron import next_fire
from saarthi2.distributed import Job, process_job


async def run_schedule(
    job: Job,
    settings: Settings,
    *,
    every: float,
    times: int | None = None,
    on_event: Callable[[str], None] | None = None,
    sleep: Callable[[float], Awaitable[None]] | None = None,
    run_once: Callable[[], Awaitable[object]] | None = None,
) -> int:
    """Run ``job`` now and then every ``every`` seconds.

    Stops after ``times`` runs (``None`` = forever). ``sleep``/``run_once`` are
    injection seams so the loop is bounded and offline in tests.
    """

    import asyncio

    do_sleep = sleep or asyncio.sleep

    async def _default_run() -> object:
        return await process_job(job, settings, on_event=on_event)

    run = run_once or _default_run
    count = 0
    while True:
        if on_event:
            on_event(f"[schedule] fire #{count + 1}: {job.workflow}")
        await run()
        count += 1
        if times is not None and count >= times:
            return count
        await do_sleep(every)


async def run_cron_schedule(
    job: Job,
    settings: Settings,
    *,
    expr: str,
    times: int | None = None,
    on_event: Callable[[str], None] | None = None,
    sleep: Callable[[float], Awaitable[None]] | None = None,
    now: Callable[[], datetime] | None = None,
    run_once: Callable[[], Awaitable[object]] | None = None,
) -> int:
    """Run ``job`` on a cron expression until ``times`` fires (``None`` = forever).

    ``sleep``/``now``/``run_once`` are injection seams so the loop is bounded and
    offline in tests. Validates the cron expression up front.
    """

    import asyncio

    next_fire(expr, datetime.now(UTC))  # fail fast on a bad expression
    do_sleep = sleep or asyncio.sleep
    clock = now or (lambda: datetime.now(UTC))

    async def _default_run() -> object:
        return await process_job(job, settings, on_event=on_event)

    run = run_once or _default_run
    count = 0
    while True:
        current = clock()
        upcoming = next_fire(expr, current)
        wait = max(0.0, (upcoming - current).total_seconds())
        if on_event:
            on_event(f"[cron] next {job.workflow} at {upcoming.isoformat()} (in {int(wait)}s)")
        await do_sleep(wait)
        if on_event:
            on_event(f"[cron] fire #{count + 1}: {job.workflow}")
        await run()
        count += 1
        if times is not None and count >= times:
            return count
