"""Manages workflow runs launched from the API: background tasks + live logs."""

from __future__ import annotations

import asyncio
from pathlib import Path

from pydantic import BaseModel, Field

from saarthi2.config import Settings
from saarthi2.engine import WorkflowError, WorkflowRunner, load_workflow
from saarthi2.runtime import build_deps
from saarthi2.state import Store, open_store


class RunRequest(BaseModel):
    """API payload to start a run."""

    workflow: str
    target: str | None = None
    vars: dict[str, str] = Field(default_factory=dict)
    no_ai: bool = False


class ChatRequest(BaseModel):
    """API payload for a one-shot LLM chat."""

    prompt: str
    tools: list[str] = Field(default_factory=list)
    skills: bool = False


class RunManager:
    """Resolves workflows, launches runs, and keeps an in-memory live log."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._logs: dict[str, list[str]] = {}
        self._tasks: dict[str, asyncio.Task] = {}

    # --- workflow resolution -------------------------------------------------

    def resolve_workflow(self, name: str) -> Path:
        candidate = Path(name).expanduser()
        if candidate.is_file():
            return candidate
        for suffix in (".yaml", ".yml"):
            path = self.settings.workflows_dir / f"{name}{suffix}"
            if path.is_file():
                return path
        raise WorkflowError(f"Workflow {name!r} not found.")

    # --- reads ---------------------------------------------------------------

    def read_store(self) -> Store:
        return open_store(self.settings)

    def logs(self, run_id: str) -> list[str]:
        return list(self._logs.get(run_id, []))

    def is_running(self, run_id: str) -> bool:
        task = self._tasks.get(run_id)
        return task is not None and not task.done()

    # --- execution -----------------------------------------------------------

    def _make_deps(self, store: Store, run_id: str, *, use_ai: bool):
        log = self._logs.setdefault(run_id, [])

        def on_event(message: str) -> None:
            log.append(message)
            if len(log) > 2000:
                del log[:-2000]

        return build_deps(self.settings, store=store, on_event=on_event, use_ai=use_ai)

    async def _run(self, request: RunRequest, run_id: str) -> None:
        store = self.read_store()
        try:
            workflow = load_workflow(self.resolve_workflow(request.workflow))
            deps = self._make_deps(store, run_id, use_ai=not request.no_ai)
            runner = WorkflowRunner(deps)
            await runner.run(
                workflow,
                target=request.target,
                extra_vars=dict(request.vars),
                run_id=run_id,
            )
        except Exception as exc:  # surface into the live log, never crash the API
            self._logs.setdefault(run_id, []).append(f"[ERR] {exc}")
        finally:
            store.close()

    def start(self, request: RunRequest) -> str:
        """Schedule a run in the background and return its id immediately."""

        # Validate the workflow up front so a bad request fails fast.
        self.resolve_workflow(request.workflow)
        run_id = f"run-{len(self._logs) + 1:04d}-{abs(hash(request.workflow)) % 100000:05d}"
        self._logs[run_id] = []
        self._tasks[run_id] = asyncio.create_task(self._run(request, run_id))
        return run_id

    async def chat(
        self, prompt: str, *, tools: list[str] | None = None, skills: bool = False
    ) -> str:
        """One-shot agent chat (summarize-only by default). Needs Ollama running."""

        deps = build_deps(self.settings, store=None, on_event=None, use_ai=True)
        if deps.agent is None:
            raise RuntimeError("AI agent is not available")
        if skills and deps.skills is not None and not deps.skills.is_empty:
            context = deps.skills.context_for(prompt, k=3)
            if context:
                prompt = f"{context}\n\n---\n\n{prompt}"
        result = await deps.agent.run(prompt, tool_names=tools or [], max_iterations=3)
        return getattr(result, "answer", str(result))

    async def execute_now(self, request: RunRequest) -> str:
        """Run to completion (used by tests / synchronous callers)."""

        seq = len(self._logs) + 1
        salt = abs(hash((request.workflow, request.target))) % 100000
        run_id = f"run-sync-{seq:04d}-{salt:05d}"
        self._logs[run_id] = []
        await self._run(request, run_id)
        return run_id
