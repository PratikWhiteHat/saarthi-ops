"""The workflow runner: sequences steps, expands loops, threads context."""

from __future__ import annotations

import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from saarthi2.engine.context import RunContext, evaluate_when, resolve_items
from saarthi2.engine.models import (
    RunResult,
    Step,
    StepResult,
    StepStatus,
    Workflow,
)


@dataclass
class StepDeps:
    """Collaborators injected into step handlers (real in the CLI, fake in tests).

    ``run_command`` returns ``(exit_code, stdout, stderr)``. ``http_request``
    returns an object with ``status_code`` and ``text``. ``agent`` exposes an
    async ``run(...)``. ``gate`` (optional) audits/authorizes each action.
    """

    run_command: Callable[..., Awaitable[tuple[int, str, str]]]
    http_request: Callable[..., Awaitable[Any]]
    agent: Any = None
    gate: Any = None
    store: Any = None
    on_event: Callable[[str], None] | None = None

    def emit(self, message: str) -> None:
        if self.on_event is not None:
            self.on_event(message)


# Populated by saarthi2.steps at import time: {uses: async handler}.
StepHandler = Callable[[Step, RunContext, StepDeps], Awaitable[StepResult]]


class WorkflowRunner:
    """Runs a validated :class:`Workflow` against a target."""

    def __init__(self, deps: StepDeps) -> None:
        self.deps = deps
        # Imported here so the handler registry is populated before first use.
        from saarthi2.steps import STEP_TYPES

        self._handlers: dict[str, StepHandler] = STEP_TYPES

    async def run(
        self,
        workflow: Workflow,
        *,
        target: str | None = None,
        extra_vars: dict[str, Any] | None = None,
        run_id: str | None = None,
    ) -> RunResult:
        run_id = run_id or f"run-{uuid.uuid4().hex[:12]}"
        merged_vars = {**workflow.vars, **(extra_vars or {})}
        resolved_target = target or merged_vars.get("target")
        ctx = RunContext(run_id=run_id, target=resolved_target, vars=merged_vars)

        result = RunResult(
            run_id=run_id,
            workflow=workflow.name,
            target=resolved_target,
            status=StepStatus.RUNNING,
        )
        if self.deps.store is not None:
            self.deps.store.create_run(result)

        for step in workflow.steps:
            step_result = await self._run_step(step, ctx)
            result.steps.append(step_result)
            ctx.record(step.id, step_result)
            if step.register and step.register != step.id:
                ctx.steps[step.register] = ctx.steps[step.id]
            if self.deps.store is not None:
                self.deps.store.record_step(run_id, step_result)

            if step_result.status is StepStatus.FAILED and not step.continue_on_error:
                result.status = StepStatus.FAILED
                if self.deps.store is not None:
                    self.deps.store.update_run(result)
                return result

        result.status = StepStatus.COMPLETED
        if self.deps.store is not None:
            self.deps.store.update_run(result)
        return result

    async def _run_step(self, step: Step, ctx: RunContext) -> StepResult:
        label = step.name or step.id
        if step.when is not None and not evaluate_when(step.when, ctx.scope()):
            self.deps.emit(f"[skip] {label} (when=false)")
            return StepResult(step_id=step.id, status=StepStatus.SKIPPED)

        if step.loop is not None:
            return await self._run_loop(step, ctx, label)

        self.deps.emit(f"[run ] {label} ({step.uses})")
        return await self._dispatch(step, ctx)

    async def _run_loop(self, step: Step, ctx: RunContext, label: str) -> StepResult:
        items = resolve_items(step.loop or "", ctx.scope())
        self.deps.emit(f"[loop] {label}: {len(items)} item(s)")
        iterations: list[StepResult] = []
        any_failed = False
        for index, item in enumerate(items):
            ctx.item = item
            self.deps.emit(f"[loop] {label} [{index + 1}/{len(items)}]: {item}")
            iteration = await self._dispatch(step, ctx)
            iterations.append(iteration)
            if iteration.status is StepStatus.FAILED:
                any_failed = True
        ctx.item = None

        combined = "\n".join(it.output for it in iterations if it.output)
        status = (
            StepStatus.FAILED
            if any_failed and not step.continue_on_error
            else StepStatus.COMPLETED
        )
        return StepResult(
            step_id=step.id,
            status=status,
            output=combined,
            data={"item_count": len(items)},
            iterations=iterations,
        )

    async def _dispatch(self, step: Step, ctx: RunContext) -> StepResult:
        handler = self._handlers.get(step.uses)
        if handler is None:  # pragma: no cover - loader validates this
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED,
                error=f"Unknown step type: {step.uses}",
            )
        started = time.monotonic()
        try:
            result = await handler(step, ctx, self.deps)
        except Exception as exc:  # a bad step must not crash the whole run
            result = StepResult(
                step_id=step.id,
                status=StepStatus.FAILED,
                error=f"{type(exc).__name__}: {exc}",
            )
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result
