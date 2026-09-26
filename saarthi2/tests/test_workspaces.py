"""Workspace grouping: runner tags runs, store groups + filters them."""

from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

from saarthi2.config import Settings
from saarthi2.server import RunManager, RunRequest, create_app

_ECHO = 'name: echo\nsteps:\n  - {id: h, uses: tool, with: {cmd: "echo hi"}}\n'


def _settings(tmp_path) -> Settings:
    wf_dir = tmp_path / "wf"
    wf_dir.mkdir()
    (wf_dir / "echo.yaml").write_text(_ECHO)
    return Settings(work_dir=tmp_path / "work", workflows_dir=wf_dir)


def _manager_with_runs(tmp_path):
    settings = _settings(tmp_path)
    manager = RunManager(settings)
    asyncio.run(manager.execute_now(RunRequest(workflow="echo", target="a.com", no_ai=True)))
    asyncio.run(manager.execute_now(RunRequest(workflow="echo", target="a.com", no_ai=True)))
    asyncio.run(manager.execute_now(RunRequest(workflow="echo", target="b.com", no_ai=True)))
    return settings, manager


def test_runs_are_tagged_with_workspace(tmp_path) -> None:
    _settings_, manager = _manager_with_runs(tmp_path)
    store = manager.read_store()
    try:
        runs = store.list_runs()
        workspaces = {r["workspace"] for r in runs}
    finally:
        store.close()
    assert workspaces == {"a_com", "b_com"}


def test_list_workspaces_counts(tmp_path) -> None:
    _settings_, manager = _manager_with_runs(tmp_path)
    store = manager.read_store()
    try:
        ws = {w["workspace"]: w["runs"] for w in store.list_workspaces()}
    finally:
        store.close()
    assert ws == {"a_com": 2, "b_com": 1}


def test_list_runs_filtered_by_workspace(tmp_path) -> None:
    _settings_, manager = _manager_with_runs(tmp_path)
    store = manager.read_store()
    try:
        a_runs = store.list_runs(workspace="a_com")
        b_runs = store.list_runs(workspace="b_com")
    finally:
        store.close()
    assert len(a_runs) == 2
    assert len(b_runs) == 1


def test_workspaces_endpoint(tmp_path) -> None:
    settings, manager = _manager_with_runs(tmp_path)
    client = TestClient(create_app(settings, manager))
    ws = {w["workspace"]: w["runs"] for w in client.get("/api/workspaces").json()}
    assert ws["a_com"] == 2
    filtered = client.get("/api/runs", params={"workspace": "b_com"}).json()
    assert len(filtered) == 1
