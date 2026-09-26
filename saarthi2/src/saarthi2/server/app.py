"""FastAPI application: REST API + serves the Web UI."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse

from saarthi2.config import Settings, get_settings
from saarthi2.engine import WorkflowError, list_workflows, load_workflow, to_mermaid
from saarthi2.server.run_manager import ChatRequest, RunManager, RunRequest

_STATIC = Path(__file__).parent / "static"


def _make_auth(settings: Settings):
    async def check(x_api_key: str | None = Header(default=None)) -> None:
        if settings.api_key and x_api_key != settings.api_key:
            raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")

    return check


def create_app(
    settings: Settings | None = None, manager: RunManager | None = None
) -> FastAPI:
    settings = settings or get_settings()
    manager = manager or RunManager(settings)

    from saarthi2.plugins import load_plugins

    load_plugins(settings)

    app = FastAPI(title="Saarthi 2.0", version="0.2.0")
    app.state.settings = settings
    app.state.manager = manager

    # /api/* is protected when SAARTHI2_API_KEY is set (no-op otherwise).
    api = APIRouter(prefix="/api", dependencies=[Depends(_make_auth(settings))])

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return (_STATIC / "index.html").read_text(encoding="utf-8")

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "auth": bool(settings.api_key)}

    @api.get("/workflows")
    def workflows() -> list[dict]:
        items: list[dict] = []
        for path in list_workflows(settings.workflows_dir):
            try:
                workflow = load_workflow(path)
            except WorkflowError:
                continue
            items.append(
                {
                    "name": path.stem,
                    "description": workflow.description,
                    "steps": len(workflow.steps),
                }
            )
        return items

    @api.get("/workflows/{name}")
    def workflow_detail(name: str) -> dict:
        try:
            workflow = load_workflow(manager.resolve_workflow(name))
        except WorkflowError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {
            "name": workflow.name,
            "description": workflow.description,
            "steps": [
                {"id": s.id, "uses": s.uses, "loop": s.loop, "when": s.when, "register": s.register}
                for s in workflow.steps
            ],
            "mermaid": to_mermaid(workflow),
        }

    @api.post("/runs")
    async def start_run(request: RunRequest) -> dict:
        try:
            run_id = manager.start(request)
        except WorkflowError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"run_id": run_id}

    @api.post("/hooks/{name}")
    @api.get("/hooks/{name}")
    async def webhook(name: str, target: str | None = None) -> dict:
        """Webhook trigger: start a run of ``name`` (optional ?target=)."""

        try:
            run_id = manager.start(RunRequest(workflow=name, target=target))
        except WorkflowError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"run_id": run_id, "workflow": name}

    @api.get("/runs")
    def runs(workspace: str | None = None) -> list[dict]:
        store = manager.read_store()
        try:
            return store.list_runs(workspace=workspace)
        finally:
            store.close()

    @api.get("/workspaces")
    def workspaces_list() -> list[dict]:
        store = manager.read_store()
        try:
            return store.list_workspaces()
        finally:
            store.close()

    @api.get("/runs/{run_id}")
    def run_detail(run_id: str) -> dict:
        store = manager.read_store()
        try:
            run = store.get_run(run_id)
            steps = store.list_steps(run_id)
            findings_rows = store.list_findings(run_id=run_id)
        finally:
            store.close()
        return {
            "run": run,
            "steps": steps,
            "findings": findings_rows,
            "log": manager.logs(run_id),
            "running": manager.is_running(run_id),
        }

    @api.get("/runs/{run_id}/steps/{step_id}/output")
    def step_output(run_id: str, step_id: str) -> dict:
        """Full output for one step: the on-disk evidence if present, else the stored preview."""

        store = manager.read_store()
        try:
            steps = {s["step_id"]: s for s in store.list_steps(run_id)}
            step = steps.get(step_id)
            if step is None:
                raise HTTPException(status_code=404, detail=f"step {step_id!r} not found")
            evidence = step.get("evidence_path")
            full = store.read_evidence(evidence) if evidence else ""
            output = full or (step.get("output") or "")
        finally:
            store.close()
        return {"step_id": step_id, "output": output, "evidence_path": step.get("evidence_path")}

    @api.get("/findings")
    def findings(run_id: str | None = None) -> list[dict]:
        store = manager.read_store()
        try:
            return store.list_findings(run_id=run_id)
        finally:
            store.close()

    @api.get("/runs/{run_id}/report")
    def run_report(run_id: str, format: str = "markdown") -> dict:
        from saarthi2.report import render_json, render_markdown

        store = manager.read_store()
        try:
            run = store.get_run(run_id)
            steps = store.list_steps(run_id)
            findings_rows = store.list_findings(run_id=run_id)
        finally:
            store.close()
        if run is None:
            raise HTTPException(status_code=404, detail=f"run {run_id!r} not found")
        renderer = render_json if format == "json" else render_markdown
        return {"run_id": run_id, "format": format, "content": renderer(run, steps, findings_rows)}

    @api.get("/stats")
    def stats() -> dict:
        store = manager.read_store()
        try:
            return store.stats()
        finally:
            store.close()

    @api.get("/events")
    def events(limit: int = 100) -> list[dict]:
        store = manager.read_store()
        try:
            return store.tail_audit(limit=limit)
        finally:
            store.close()

    @api.get("/settings")
    def settings_view() -> dict:
        """Redacted runtime settings (never leak secrets)."""

        def _redact(value: str) -> str:
            return "***set***" if value else ""

        return {
            "ollama_host": settings.ollama_host,
            "ollama_model": settings.ollama_model,
            "work_dir": str(settings.work_dir),
            "workflows_dir": str(settings.workflows_dir),
            "redis_url": _redact(settings.redis_url),
            "api_key": _redact(settings.api_key),
            "slack_webhook": _redact(settings.slack_webhook),
            "discord_webhook": _redact(settings.discord_webhook),
            "telegram": _redact(settings.telegram_token),
        }

    @api.get("/jobs")
    def jobs_size() -> dict:
        from saarthi2.distributed import get_queue

        queue = get_queue(settings.redis_url)
        return {"queue_size": queue.size(), "distributed": bool(settings.redis_url)}

    @api.post("/jobs")
    def jobs_enqueue(request: RunRequest) -> dict:
        from saarthi2.distributed import Job, get_queue

        try:
            manager.resolve_workflow(request.workflow)  # 400 on unknown workflow
        except WorkflowError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        queue = get_queue(settings.redis_url)
        job = Job(
            workflow=request.workflow,
            target=request.target,
            vars=request.vars,
            no_ai=request.no_ai,
        )
        queue.push(job)
        return {"job_id": job.id, "queue_size": queue.size()}

    @api.post("/llm")
    async def llm_chat(request: ChatRequest) -> dict:
        try:
            answer = await manager.chat(request.prompt, tools=request.tools, skills=request.skills)
        except Exception as exc:  # Ollama down / model missing / agent error
            raise HTTPException(status_code=503, detail=f"LLM unavailable: {exc}") from exc
        return {"answer": answer}

    @api.get("/tools")
    def tools() -> list[dict]:
        from saarthi2.adapters import adapter_catalog

        return adapter_catalog()

    @api.get("/functions")
    def functions() -> list[dict]:
        from saarthi2.functions import function_catalog

        return function_catalog()

    @api.get("/subagents")
    def subagents() -> list[dict]:
        from saarthi2.subagents import subagent_catalog

        return subagent_catalog()

    @api.get("/providers")
    def providers() -> list[dict]:
        from saarthi2.cloud import cloud_catalog

        return cloud_catalog()

    @api.get("/storage")
    def storage() -> list[dict]:
        from saarthi2.storage import storage_catalog

        return storage_catalog()

    @api.get("/plugins")
    def plugins() -> list[dict]:
        from saarthi2.plugins import discover

        return discover(plugins_dir=settings.plugins_dir).details

    @api.get("/skills")
    def skills() -> list[dict]:
        from saarthi2.rag import SkillLibrary

        return SkillLibrary.from_dir(settings.skills_dir).catalog()

    @api.get("/skills/search")
    def skills_search(q: str, k: int = 5) -> list[dict]:
        from saarthi2.rag import SkillLibrary

        return SkillLibrary.from_dir(settings.skills_dir).search(q, k=k)

    app.include_router(api)
    return app


def app_factory() -> FastAPI:
    """Import-string entry point for ``uvicorn --reload`` (reads settings from env)."""

    return create_app()
