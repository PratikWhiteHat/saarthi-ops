"""``llm`` step: run the agentic loop against the local model.

This is the "AI runs tools repeatedly" capability as a workflow step. ``with``:
``prompt`` (required), ``tools`` (tool names the agent may call; omit for all,
``[]`` for none), and ``max_iterations``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from saarthi2.engine.context import RunContext, render_obj
from saarthi2.engine.models import Step, StepResult, StepStatus

if TYPE_CHECKING:
    from saarthi2.engine.runner import StepDeps


async def handle_llm(step: Step, ctx: RunContext, deps: StepDeps) -> StepResult:
    params = render_obj(step.with_, ctx.scope())
    prompt = str(params.get("prompt", "")).strip()
    if not prompt:
        return StepResult(
            step_id=step.id,
            status=StepStatus.FAILED,
            error="llm step requires a 'prompt'",
        )
    if deps.agent is None:
        return StepResult(
            step_id=step.id,
            status=StepStatus.FAILED,
            error="no AI agent is configured for this run",
        )

    tool_names = params.get("tools")  # None -> all tools; [] -> none
    max_iterations = int(params.get("max_iterations", 6))

    # Optional RAG: ground the prompt in the relevant bug-hunting playbook(s).
    # ``skills: true`` uses the prompt as the query; ``skills: "<query>"`` overrides it.
    skills = params.get("skills")
    if skills and getattr(deps, "skills", None) is not None and not deps.skills.is_empty:
        query = skills if isinstance(skills, str) else prompt
        context = deps.skills.context_for(query, k=int(params.get("skills_k", 3)))
        if context:
            prompt = f"{context}\n\n---\n\n{prompt}"

    result = await deps.agent.run(
        prompt,
        tool_names=tool_names,
        max_iterations=max_iterations,
        ctx=ctx,
        deps=deps,
    )
    return StepResult(
        step_id=step.id,
        status=StepStatus.COMPLETED,
        output=result.answer,
        data={
            "iterations": result.iterations,
            "tool_calls": result.tool_calls,
            "stopped_reason": result.stopped_reason,
        },
    )
