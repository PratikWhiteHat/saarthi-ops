"""``tool`` step: run an external CLI/security tool or shell command."""

from __future__ import annotations

from typing import TYPE_CHECKING

from saarthi2.engine.context import RunContext, render_obj
from saarthi2.engine.models import Step, StepResult, StepStatus

if TYPE_CHECKING:
    from saarthi2.engine.runner import StepDeps


async def handle_tool(step: Step, ctx: RunContext, deps: StepDeps) -> StepResult:
    params = render_obj(step.with_, ctx.scope())
    cmd = str(params.get("cmd", "")).strip()
    if not cmd:
        return StepResult(
            step_id=step.id,
            status=StepStatus.FAILED,
            error="tool step requires a 'cmd'",
        )

    timeout = int(params.get("timeout", 300))
    shell = bool(params.get("shell", False))

    if deps.gate is not None:
        deps.gate.check("command", {"cmd": cmd})

    exit_code, stdout, stderr = await deps.run_command(cmd, timeout=timeout, shell=shell)
    output = stdout if stdout else stderr
    status = StepStatus.COMPLETED if exit_code == 0 else StepStatus.FAILED

    result = StepResult(
        step_id=step.id,
        status=status,
        output=output,
        exit_code=exit_code,
        data={"cmd": cmd},
        error=(stderr[:500] if (exit_code != 0 and not stdout) else None),
    )
    if deps.store is not None and output:
        path, _sha = deps.store.save_evidence(
            ctx.run_id, step.id, output.encode("utf-8", "replace")
        )
        result.evidence_path = path
    return result
