"""``http`` step: make a single HTTP request and capture the response."""

from __future__ import annotations

from typing import TYPE_CHECKING

from saarthi2.engine.context import RunContext, render_obj
from saarthi2.engine.models import Step, StepResult, StepStatus

if TYPE_CHECKING:
    from saarthi2.engine.runner import StepDeps

MAX_BODY = 200_000


async def handle_http(step: Step, ctx: RunContext, deps: StepDeps) -> StepResult:
    params = render_obj(step.with_, ctx.scope())
    url = str(params.get("url", "")).strip()
    if not url:
        return StepResult(
            step_id=step.id,
            status=StepStatus.FAILED,
            error="http step requires a 'url'",
        )

    method = str(params.get("method", "GET")).upper()
    headers = params.get("headers") or {}
    body = params.get("body")
    timeout = int(params.get("timeout", 30))

    if deps.gate is not None:
        deps.gate.check("http", {"url": url, "method": method})

    response = await deps.http_request(
        method, url, headers=headers, body=body, timeout=timeout
    )
    status_code = getattr(response, "status_code", None)
    text = (getattr(response, "text", "") or "")[:MAX_BODY]

    result = StepResult(
        step_id=step.id,
        status=StepStatus.COMPLETED,
        output=text,
        exit_code=status_code,
        data={"status": status_code, "url": url, "method": method},
    )
    if deps.store is not None and text:
        path, _sha = deps.store.save_evidence(
            ctx.run_id, step.id, text.encode("utf-8", "replace")
        )
        result.evidence_path = path
    return result
