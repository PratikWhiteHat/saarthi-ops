"""New REST endpoints: stats, events, settings, jobs, findings, report."""

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


def _run_and_client(tmp_path):
    settings = _settings(tmp_path)
    manager = RunManager(settings)
    run_id = asyncio.run(manager.execute_now(RunRequest(workflow="echo", no_ai=True)))
    # attach a finding so severity aggregation is exercised
    store = manager.read_store()
    try:
        store.record_findings(run_id, [{"tool": "nuclei", "severity": "high", "message": "x"}])
    finally:
        store.close()
    return TestClient(create_app(settings, manager)), run_id


def test_stats_endpoint(tmp_path) -> None:
    client, _ = _run_and_client(tmp_path)
    stats = client.get("/api/stats").json()
    assert stats["runs"] >= 1
    assert stats["findings"] == 1
    assert stats["findings_by_severity"]["high"] == 1


def test_findings_endpoint(tmp_path) -> None:
    client, run_id = _run_and_client(tmp_path)
    findings = client.get("/api/findings", params={"run_id": run_id}).json()
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_events_endpoint(tmp_path) -> None:
    client, _ = _run_and_client(tmp_path)
    events = client.get("/api/events").json()
    assert any(e.get("event") == "run_created" for e in events)


def test_settings_endpoint_redacts(tmp_path) -> None:
    settings = _settings(tmp_path)
    settings = settings.__class__(
        work_dir=settings.work_dir, workflows_dir=settings.workflows_dir,
        api_key="secret", slack_webhook="https://hooks/x",
    )
    client = TestClient(create_app(settings))
    # /api/settings sits behind auth when a key is set — authenticate to read it.
    view = client.get("/api/settings", headers={"X-API-Key": "secret"}).json()
    assert view["api_key"] == "***set***"
    assert view["slack_webhook"] == "***set***"
    assert view["redis_url"] == ""
    assert "secret" not in str(view)


def test_report_endpoint(tmp_path) -> None:
    client, run_id = _run_and_client(tmp_path)
    md = client.get(f"/api/runs/{run_id}/report").json()
    assert md["format"] == "markdown"
    assert "Saarthi 2.0 Report" in md["content"]
    js = client.get(f"/api/runs/{run_id}/report", params={"format": "json"}).json()
    assert '"severity_counts"' in js["content"]
    assert client.get("/api/runs/nope/report").status_code == 404


def test_jobs_endpoints(tmp_path) -> None:
    client, _ = _run_and_client(tmp_path)
    assert client.get("/api/jobs").json()["distributed"] is False
    ok = client.post("/api/jobs", json={"workflow": "echo", "target": "ex.com"})
    assert ok.status_code == 200
    assert ok.json()["job_id"].startswith("job-")
    assert client.post("/api/jobs", json={"workflow": "missing"}).status_code == 400


def test_run_detail_includes_output_and_findings(tmp_path) -> None:
    client, run_id = _run_and_client(tmp_path)
    detail = client.get(f"/api/runs/{run_id}").json()
    # the echo tool step captured its stdout, now surfaced in the detail
    step = next(s for s in detail["steps"] if s["step_id"] == "h")
    assert "hi" in step["output"]
    assert detail["findings"][0]["severity"] == "high"  # seeded in _run_and_client


def test_step_output_endpoint(tmp_path) -> None:
    client, run_id = _run_and_client(tmp_path)
    out = client.get(f"/api/runs/{run_id}/steps/h/output").json()
    assert "hi" in out["output"]
    assert client.get(f"/api/runs/{run_id}/steps/nope/output").status_code == 404


def test_dashboard_has_all_panels(tmp_path) -> None:
    client, _ = _run_and_client(tmp_path)
    html = client.get("/").text
    for marker in (
        'id="nav"', 'id="view"', 'id="drawer"', 'id="topstats"', 'id="new-scan"',
        'openNewScanDrawer', 'LLM Playground', 'Cloud & Storage', 'cat:plugins',
        'Workspaces', 'Findings',
    ):
        assert marker in html, f"missing UI element: {marker}"


def test_app_factory_builds_app(tmp_path, monkeypatch) -> None:
    from saarthi2.server import app_factory

    monkeypatch.setenv("SAARTHI2_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("SAARTHI2_WORKFLOWS_DIR", str(tmp_path / "wf"))
    (tmp_path / "wf").mkdir()
    app = app_factory()
    client = TestClient(app)
    assert client.get("/api/health").json()["status"] == "ok"


def test_storage_endpoint(tmp_path) -> None:
    client, _ = _run_and_client(tmp_path)
    names = {p["name"] for p in client.get("/api/storage").json()}
    assert {"s3", "gcs", "azure"} <= names


def test_llm_endpoint(tmp_path) -> None:
    settings = _settings(tmp_path)
    manager = RunManager(settings)

    async def fake_chat(prompt, *, tools=None, skills=False):
        return f"echo:{prompt}"

    manager.chat = fake_chat
    client = TestClient(create_app(settings, manager))
    ok = client.post("/api/llm", json={"prompt": "hello"})
    assert ok.status_code == 200
    assert ok.json()["answer"] == "echo:hello"


def test_llm_endpoint_unavailable(tmp_path) -> None:
    settings = _settings(tmp_path)
    manager = RunManager(settings)

    async def broken_chat(prompt, *, tools=None, skills=False):
        raise RuntimeError("ollama down")

    manager.chat = broken_chat
    client = TestClient(create_app(settings, manager))
    assert client.post("/api/llm", json={"prompt": "x"}).status_code == 503
