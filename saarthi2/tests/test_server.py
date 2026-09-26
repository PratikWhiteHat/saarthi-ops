"""REST API: workflows, visualization, and run lifecycle (offline)."""

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


def test_health_and_workflows(tmp_path) -> None:
    client = TestClient(create_app(_settings(tmp_path)))
    assert client.get("/api/health").json()["status"] == "ok"
    names = [w["name"] for w in client.get("/api/workflows").json()]
    assert "echo" in names


def test_tools_and_functions_endpoints(tmp_path) -> None:
    client = TestClient(create_app(_settings(tmp_path)))
    tools = {t["name"] for t in client.get("/api/tools").json()}
    assert {"subfinder", "nuclei", "httpx", "semgrep", "trivy"} <= tools
    funcs = {f["name"] for f in client.get("/api/functions").json()}
    assert {"sort_unique", "grep", "parse_sarif", "classify_cdn_waf"} <= funcs


def test_subagents_and_providers_endpoints(tmp_path) -> None:
    client = TestClient(create_app(_settings(tmp_path)))
    agents = {a["name"] for a in client.get("/api/subagents").json()}
    assert {"claude", "codex", "gemini"} <= agents
    providers = {p["name"] for p in client.get("/api/providers").json()}
    assert {"digitalocean", "aws", "gcp", "linode", "azure"} <= providers


def test_api_key_auth(tmp_path) -> None:
    settings = _settings(tmp_path)
    settings = settings.__class__(
        work_dir=settings.work_dir, workflows_dir=settings.workflows_dir, api_key="secret"
    )
    client = TestClient(create_app(settings))
    # health stays open
    assert client.get("/api/health").status_code == 200
    # data endpoints require the key
    assert client.get("/api/workflows").status_code == 401
    ok = client.get("/api/workflows", headers={"X-API-Key": "secret"})
    assert ok.status_code == 200


def test_webhook_trigger(tmp_path) -> None:
    settings = _settings(tmp_path)
    manager = RunManager(settings)

    async def _stub(request, run_id):
        manager._logs.setdefault(run_id, []).append("stub")

    manager._run = _stub
    with TestClient(create_app(settings, manager)) as client:
        r = client.post("/api/hooks/echo")
        assert r.status_code == 200
        assert r.json()["workflow"] == "echo"
        assert client.post("/api/hooks/missing").status_code == 404


def test_workflow_detail_has_mermaid(tmp_path) -> None:
    client = TestClient(create_app(_settings(tmp_path)))
    detail = client.get("/api/workflows/echo").json()
    assert detail["name"] == "echo"
    assert detail["mermaid"].startswith("flowchart")
    assert detail["steps"][0]["id"] == "h"
    assert client.get("/api/workflows/does-not-exist").status_code == 404


def test_index_served(tmp_path) -> None:
    client = TestClient(create_app(_settings(tmp_path)))
    body = client.get("/").text
    assert "Saarthi" in body and "mermaid" in body


def test_run_lifecycle(tmp_path) -> None:
    settings = _settings(tmp_path)
    manager = RunManager(settings)
    run_id = asyncio.run(manager.execute_now(RunRequest(workflow="echo", no_ai=True)))

    client = TestClient(create_app(settings, manager))
    detail = client.get(f"/api/runs/{run_id}").json()
    assert detail["run"]["status"] == "completed"
    assert detail["steps"][0]["step_id"] == "h"
    assert detail["running"] is False

    runs = client.get("/api/runs").json()
    assert any(r["run_id"] == run_id for r in runs)


def test_post_run_returns_id_and_validates(tmp_path) -> None:
    settings = _settings(tmp_path)
    manager = RunManager(settings)

    # Stub the background execution so the endpoint's validate+schedule path is
    # tested without leaving a real subprocess task running under TestClient.
    async def _stub(request, run_id):
        manager._logs.setdefault(run_id, []).append("stub")

    manager._run = _stub

    with TestClient(create_app(settings, manager)) as client:
        ok = client.post("/api/runs", json={"workflow": "echo", "no_ai": True})
        assert ok.status_code == 200
        assert ok.json()["run_id"].startswith("run-")
        assert client.post("/api/runs", json={"workflow": "missing"}).status_code == 400
