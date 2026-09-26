"""Distributed queue + worker + scheduler + subagents + cloud."""

from __future__ import annotations

import asyncio

from saarthi2.cloud import CLOUD_PROVIDERS, render_provision_command
from saarthi2.config import Settings
from saarthi2.distributed import Job, MemoryQueue, get_queue, run_worker
from saarthi2.scheduler import run_schedule
from saarthi2.subagents import render_subagent_command

_ECHO = 'name: echo\nsteps:\n  - {id: h, uses: tool, with: {cmd: "echo hi"}}\n'


def _settings(tmp_path) -> Settings:
    wf = tmp_path / "wf"
    wf.mkdir()
    (wf / "echo.yaml").write_text(_ECHO)
    return Settings(work_dir=tmp_path / "work", workflows_dir=wf)


def test_memory_queue_fifo() -> None:
    q = MemoryQueue()
    q.push(Job(workflow="a"))
    q.push(Job(workflow="b"))
    assert q.size() == 2
    assert q.pop().workflow == "a"
    assert q.pop().workflow == "b"
    assert q.pop() is None


def test_get_queue_defaults_to_memory() -> None:
    assert isinstance(get_queue(""), MemoryQueue)


def test_worker_drains_queue(tmp_path) -> None:
    settings = _settings(tmp_path)
    q = MemoryQueue()
    q.push(Job(workflow="echo"))
    q.push(Job(workflow="echo"))
    processed = asyncio.run(run_worker(q, settings, once=True))
    assert processed == 2
    # runs were persisted
    from saarthi2.state import Store

    store = Store(settings.db_path, settings.evidence_dir, settings.audit_path)
    assert len(store.list_runs()) == 2
    store.close()


def test_scheduler_fires_n_times(tmp_path) -> None:
    settings = _settings(tmp_path)
    fired = {"n": 0}

    async def fake_run() -> None:
        fired["n"] += 1

    async def fake_sleep(_seconds: float) -> None:
        return None

    count = asyncio.run(
        run_schedule(
            Job(workflow="echo"), settings, every=0, times=3,
            run_once=fake_run, sleep=fake_sleep,
        )
    )
    assert count == 3
    assert fired["n"] == 3


def test_subagent_command() -> None:
    cmd = render_subagent_command("claude", "find bugs in app.py")
    assert cmd == "claude -p 'find bugs in app.py'"
    import pytest

    with pytest.raises(ValueError, match="unknown sub-agent"):
        render_subagent_command("nope", "x")


def test_cloud_provision_templates() -> None:
    assert set(CLOUD_PROVIDERS) == {"digitalocean", "aws", "gcp", "linode", "azure"}
    cmd = render_provision_command(
        "digitalocean", {"name": "box1", "size": "s-1vcpu", "image": "ubuntu", "region": "nyc1"}
    )
    assert "doctl compute droplet create box1" in cmd
    import pytest

    with pytest.raises(ValueError, match="unknown cloud provider"):
        render_provision_command("nope", {})
