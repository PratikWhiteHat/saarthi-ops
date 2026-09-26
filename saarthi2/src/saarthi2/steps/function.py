"""``function`` step: run a built-in data/file utility function."""

from __future__ import annotations

from typing import TYPE_CHECKING

from saarthi2.engine.context import RunContext, render_obj
from saarthi2.engine.models import Step, StepResult, StepStatus
from saarthi2.functions import FUNCTION_REGISTRY

if TYPE_CHECKING:
    from saarthi2.engine.runner import StepDeps


async def handle_function(step: Step, ctx: RunContext, deps: StepDeps) -> StepResult:
    params = render_obj(step.with_, ctx.scope())
    name = params.get("func") or params.get("name")
    fn = FUNCTION_REGISTRY.get(str(name))
    if fn is None:
        return StepResult(
            step_id=step.id,
            status=StepStatus.FAILED,
            error=f"unknown function {name!r}; known: {sorted(FUNCTION_REGISTRY)}",
        )

    # args may be nested under 'args' or provided flat alongside 'func'.
    args = params.get("args")
    if not isinstance(args, dict):
        args = {k: v for k, v in params.items() if k not in ("func", "name")}

    if deps.gate is not None:
        deps.gate.check("function", {"func": name})

    result = fn(args, ctx)
    data = dict(result.get("data", {}))

    # Functions that produce findings (parse_sarif/parse_nuclei) get persisted
    # to the findings store so they show up in the dashboard's Findings tab.
    findings = data.get("findings")
    if isinstance(findings, list) and findings and deps.store is not None:
        deps.store.record_findings(ctx.run_id, findings)

    return StepResult(
        step_id=step.id,
        status=StepStatus.COMPLETED,
        output=str(result.get("output", "")),
        data=data,
    )
