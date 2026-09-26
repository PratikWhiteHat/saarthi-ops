"""Distributed master/worker execution over a job queue.

``MemoryQueue`` is in-process (single machine / tests). ``RedisQueue`` (optional,
needs a running Redis + the ``redis`` package) gives a real cross-machine
master/worker fleet: a master enqueues jobs, workers on other hosts pop and run
them. ``process_job`` executes one job through the normal engine.
"""

from __future__ import annotations

import json
import uuid
from collections import deque
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from pydantic import BaseModel, Field

from saarthi2.config import Settings


class Job(BaseModel):
    """A unit of work: run a workflow against a target."""

    workflow: str
    target: str | None = None
    vars: dict[str, str] = Field(default_factory=dict)
    no_ai: bool = False
    id: str = Field(default_factory=lambda: f"job-{uuid.uuid4().hex[:12]}")


class JobQueue(Protocol):
    def push(self, job: Job) -> None: ...
    def pop(self) -> Job | None: ...
    def size(self) -> int: ...


class MemoryQueue:
    """In-process FIFO queue."""

    def __init__(self) -> None:
        self._items: deque[Job] = deque()

    def push(self, job: Job) -> None:
        self._items.append(job)

    def pop(self) -> Job | None:
        return self._items.popleft() if self._items else None

    def size(self) -> int:
        return len(self._items)


class RedisQueue:
    """Redis-list-backed queue for a cross-machine fleet (optional)."""

    def __init__(self, url: str, key: str = "saarthi2:jobs") -> None:
        import redis  # lazy: only needed for distributed mode

        self._redis = redis.Redis.from_url(url)
        self._key = key

    def push(self, job: Job) -> None:
        self._redis.rpush(self._key, job.model_dump_json())

    def pop(self) -> Job | None:
        raw = self._redis.lpop(self._key)
        if raw is None:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        return Job.model_validate(json.loads(raw))

    def size(self) -> int:
        return int(self._redis.llen(self._key))


def get_queue(redis_url: str = "") -> JobQueue:
    """Return a Redis queue when a URL is configured, else in-memory."""

    return RedisQueue(redis_url) if redis_url else MemoryQueue()


async def process_job(
    job: Job,
    settings: Settings,
    *,
    on_event: Callable[[str], None] | None = None,
) -> Any:
    """Execute one job through the engine and return the RunResult."""

    from saarthi2.engine import WorkflowRunner, load_workflow, resolve_workflow
    from saarthi2.plugins import load_plugins
    from saarthi2.runtime import build_deps
    from saarthi2.state import open_store

    load_plugins(settings)  # workers pick up the same extension plugins
    workflow = load_workflow(resolve_workflow(job.workflow, settings.workflows_dir))
    store = open_store(settings)
    try:
        deps = build_deps(
            settings, store=store, on_event=on_event, use_ai=not job.no_ai
        )
        return await WorkflowRunner(deps).run(
            workflow, target=job.target, extra_vars=dict(job.vars), run_id=job.id
        )
    finally:
        store.close()


async def run_worker(
    queue: JobQueue,
    settings: Settings,
    *,
    once: bool = False,
    poll_interval: float = 2.0,
    on_event: Callable[[str], None] | None = None,
    sleep: Callable[[float], Awaitable[None]] | None = None,
    max_jobs: int | None = None,
) -> int:
    """Pop and process jobs until the queue drains (once) or forever.

    Returns the number of jobs processed. ``sleep``/``max_jobs`` are injection
    seams for tests so the loop is bounded.
    """

    import asyncio

    do_sleep = sleep or asyncio.sleep
    processed = 0
    while True:
        job = queue.pop()
        if job is None:
            if once:
                break
            await do_sleep(poll_interval)
            if max_jobs is not None and processed >= max_jobs:
                break
            continue
        if on_event:
            on_event(f"[worker] running {job.id}: {job.workflow}")
        await process_job(job, settings, on_event=on_event)
        processed += 1
        if max_jobs is not None and processed >= max_jobs:
            break
        if once and queue.size() == 0:
            break
    return processed
