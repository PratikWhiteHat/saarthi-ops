"""File-watch trigger — fire a workflow when a watched path changes.

Poll-based (mtime), so it needs no extra dependency. Fires ``job`` when the
watched file/directory's newest mtime increases. ``stat``/``sleep``/``run_once``/
``max_checks`` are injection seams so the loop is bounded and offline in tests.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path

from saarthi2.config import Settings
from saarthi2.distributed import Job, process_job


def _newest_mtime(path: Path) -> float:
    """Newest mtime under ``path`` (the file itself, or any file in a directory)."""

    if path.is_dir():
        mtimes = [child.stat().st_mtime for child in path.rglob("*") if child.is_file()]
        return max(mtimes) if mtimes else 0.0
    if path.is_file():
        return path.stat().st_mtime
    return 0.0


async def run_watch(
    job: Job,
    settings: Settings,
    *,
    path: str,
    poll_interval: float = 5.0,
    max_fires: int | None = None,
    max_checks: int | None = None,
    on_event: Callable[[str], None] | None = None,
    sleep: Callable[[float], Awaitable[None]] | None = None,
    stat: Callable[[Path], float] | None = None,
    run_once: Callable[[], Awaitable[object]] | None = None,
) -> int:
    """Watch ``path`` and fire ``job`` on each change. Returns the number of fires."""

    import asyncio

    watched = Path(path).expanduser()
    do_sleep = sleep or asyncio.sleep
    read_mtime = stat or _newest_mtime

    async def _default_run() -> object:
        return await process_job(job, settings, on_event=on_event)

    run = run_once or _default_run
    last = read_mtime(watched)
    if on_event:
        on_event(f"[watch] watching {watched} (baseline mtime={last})")

    fires = 0
    checks = 0
    while True:
        await do_sleep(poll_interval)
        checks += 1
        current = read_mtime(watched)
        if current > last:
            last = current
            if on_event:
                on_event(f"[watch] change detected -> fire #{fires + 1}: {job.workflow}")
            await run()
            fires += 1
            if max_fires is not None and fires >= max_fires:
                return fires
        if max_checks is not None and checks >= max_checks:
            return fires
