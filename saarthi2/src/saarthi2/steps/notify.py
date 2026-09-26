"""``notify`` step: send a message to configured chat channels."""

from __future__ import annotations

from typing import TYPE_CHECKING

from saarthi2.engine.context import RunContext, render_obj
from saarthi2.engine.models import Step, StepResult, StepStatus

if TYPE_CHECKING:
    from saarthi2.engine.runner import StepDeps


async def handle_notify(step: Step, ctx: RunContext, deps: StepDeps) -> StepResult:
    params = render_obj(step.with_, ctx.scope())
    message = str(params.get("message", "")).strip()
    if not message:
        return StepResult(
            step_id=step.id, status=StepStatus.FAILED, error="notify requires a 'message'"
        )

    channels = params.get("channels")
    if isinstance(channels, str):
        channels = [c.strip() for c in channels.split(",") if c.strip()]

    if deps.notifier is None:
        return StepResult(
            step_id=step.id,
            status=StepStatus.COMPLETED,
            output="(no notifier configured)",
            data={"sent": {}},
        )

    results = await deps.notifier.send(message, channels=channels)
    return StepResult(
        step_id=step.id,
        status=StepStatus.COMPLETED,
        output="notified: " + ", ".join(f"{k}={v}" for k, v in results.items()),
        data={"sent": results},
    )
