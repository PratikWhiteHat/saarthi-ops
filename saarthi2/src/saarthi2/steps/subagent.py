"""``subagent`` step: delegate a prompt to an external agent CLI."""

from __future__ import annotations

from typing import TYPE_CHECKING

from saarthi2.engine.context import RunContext, render_obj
from saarthi2.engine.models import Step, StepResult, StepStatus
from saarthi2.subagents import render_subagent_command

if TYPE_CHECKING:
    from saarthi2.engine.runner import StepDeps


async def handle_subagent(step: Step, ctx: RunContext, deps: StepDeps) -> StepResult:
    params = render_obj(step.with_, ctx.scope())
    agent = str(params.get("agent", "")).strip()
    prompt = str(params.get("prompt", "")).strip()
    if not prompt:
        return StepResult(
            step_id=step.id, status=StepStatus.FAILED, error="subagent requires a 'prompt'"
        )
    try:
        cmd = render_subagent_command(agent, prompt, params.get("args"))
    except ValueError as exc:
        return StepResult(step_id=step.id, status=StepStatus.FAILED, error=str(exc))

    timeout = int(params.get("timeout", 600))
    if deps.gate is not None:
        deps.gate.check("subagent", {"agent": agent})

    exit_code, stdout, stderr = await deps.run_command(cmd, timeout=timeout, shell=False)
    output = stdout if stdout else stderr
    status = StepStatus.COMPLETED if exit_code == 0 else StepStatus.FAILED
    return StepResult(
        step_id=step.id,
        status=status,
        output=output,
        exit_code=exit_code,
        data={"agent": agent},
        error=(stderr[:500] if (exit_code != 0 and not stdout) else None),
    )
