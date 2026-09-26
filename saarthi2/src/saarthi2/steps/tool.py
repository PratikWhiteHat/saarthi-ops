"""``tool`` step: run a CLI/security tool via a raw command or a named adapter.

Supports named adapters (``with: {tool: subfinder, target: ...}``) and runners
(``with: {runner: docker, image: ...}`` / ``{runner: ssh, ssh_host: ...}``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from saarthi2.adapters import render_adapter_command
from saarthi2.engine.context import RunContext, render_obj
from saarthi2.engine.models import Step, StepResult, StepStatus
from saarthi2.runners import prepare_runner, wrap_command

if TYPE_CHECKING:
    from saarthi2.engine.runner import StepDeps


async def handle_tool(step: Step, ctx: RunContext, deps: StepDeps) -> StepResult:
    params = render_obj(step.with_, ctx.scope())

    tool_name = params.get("tool")
    if tool_name:
        try:
            cmd = render_adapter_command(str(tool_name), params)
        except ValueError as exc:
            return StepResult(step_id=step.id, status=StepStatus.FAILED, error=str(exc))
    else:
        cmd = str(params.get("cmd", "")).strip()
    if not cmd:
        return StepResult(
            step_id=step.id,
            status=StepStatus.FAILED,
            error="tool step requires a 'cmd' or a 'tool' adapter name",
        )

    try:
        run_cmd, shell = wrap_command(cmd, params)
        prepare_runner(params)
    except ValueError as exc:
        return StepResult(step_id=step.id, status=StepStatus.FAILED, error=str(exc))

    timeout = int(params.get("timeout", 300))
    if deps.gate is not None:
        deps.gate.check(
            "command", {"cmd": run_cmd, "runner": params.get("runner", "local")}
        )

    exit_code, stdout, stderr = await deps.run_command(run_cmd, timeout=timeout, shell=shell)
    output = stdout if stdout else stderr
    status = StepStatus.COMPLETED if exit_code == 0 else StepStatus.FAILED

    result = StepResult(
        step_id=step.id,
        status=status,
        output=output,
        exit_code=exit_code,
        data={"cmd": run_cmd, "runner": params.get("runner", "local"), "tool": tool_name},
        error=(stderr[:500] if (exit_code != 0 and not stdout) else None),
    )
    if deps.store is not None and output:
        path, _sha = deps.store.save_evidence(
            ctx.run_id, step.id, output.encode("utf-8", "replace")
        )
        result.evidence_path = path
    return result
