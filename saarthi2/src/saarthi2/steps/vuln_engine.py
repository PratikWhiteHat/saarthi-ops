"""``vuln_engine`` step: run the deterministic vulnerability identification engine.

This is the back half of a run as a workflow step: it logs in (optional), crawls
the authenticated surface, COMPREHENDs an App Model, PLANs tasks from the editable
matrix, TESTs with templated payloads, and VERIFIes with the deterministic oracle.
The App Model + plan are persisted to the run context and confirmed/suspected
findings to the findings store. ``with`` keys:

    base_url        where to start (defaults to the run target)
    login           {url, username, password, *_selector} — optional browser login
    cookie          raw Cookie header to reuse an existing session (alt to login)
    use_llm         let the 14B refine the App Model classification (default true)
    xss_browser     use a headless browser to confirm reflected XSS (default true)
    active_probe    send benign canaries to detect reflection (default true)
    probe_post      also actively probe POST surfaces (default false; side-effects)
    max_pages/max_tasks/timeout/oob_domain
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from saarthi2.engine.context import RunContext, render_obj, target_url
from saarthi2.engine.models import Step, StepResult, StepStatus

if TYPE_CHECKING:
    from saarthi2.engine.runner import StepDeps


def _summary_text(result: Any) -> str:
    lines: list[str] = []
    model = result.app_model
    if model is not None:
        lines.append(
            f"App Model: type={model.app_type}, "
            f"{len(model.input_surfaces)} input surface(s), "
            f"tech={', '.join(model.tech_stack) or '-'}, "
            f"signals={', '.join(model.interesting_signals) or '-'}"
        )
    if not result.entered_test:
        lines.append(f"TEST NOT ENTERED — {result.reason}")
        return "\n".join(lines)
    lines.append(f"Plan: {len(result.plan)} task(s) across the surface.")
    confirmed = result.confirmed
    suspected = [f for f in result.findings if f.status.value == "suspected"]
    lines.append(f"Findings: {len(confirmed)} confirmed, {len(suspected)} suspected.")
    for f in confirmed:
        lines.append(f"  [CONFIRMED {f.severity}] {f.vuln_class} — {f.location()}")
    for f in suspected:
        lines.append(f"  [suspected] {f.vuln_class} — {f.location()}")
    return "\n".join(lines)


async def handle_vuln_engine(step: Step, ctx: RunContext, deps: StepDeps) -> StepResult:
    from saarthi2.vulnengine.browser import PlaywrightXss, playwright_available
    from saarthi2.vulnengine.browser import login as browser_login
    from saarthi2.vulnengine.http import HttpSender
    from saarthi2.vulnengine.pipeline import run_pipeline

    params = render_obj(step.with_, ctx.scope())
    base_url = str(params.get("base_url") or "").strip() or target_url(ctx.target or "")
    if not base_url:
        return StepResult(
            step_id=step.id,
            status=StepStatus.FAILED,
            error="vuln_engine requires 'base_url' or a run target",
        )

    if deps.gate is not None:
        deps.gate.check("http", {"url": base_url, "source": "vuln_engine"})

    # --- authenticate (optional) ---------------------------------------------
    cookies: dict[str, str] = {}
    login = params.get("login") if isinstance(params.get("login"), dict) else None
    if login and login.get("url") and login.get("username"):
        cookies = await browser_login(
            str(login["url"]),
            str(login.get("username", "")),
            str(login.get("password", "")),
            username_selector=login.get("username_selector"),
            password_selector=login.get("password_selector"),
            submit_selector=login.get("submit_selector"),
        )
        deps.emit(f"[vuln] login -> {len(cookies)} cookie(s)")

    headers: dict[str, str] = {}
    if params.get("cookie"):
        headers["Cookie"] = str(params["cookie"])
    sender = HttpSender(cookies=cookies, headers=headers, timeout=int(params.get("timeout", 20)))

    chat = deps.llm if params.get("use_llm", True) else None
    browser = None
    if params.get("xss_browser", True) and playwright_available():
        browser = PlaywrightXss(cookies=cookies)

    max_tasks = params.get("max_tasks")
    result = await run_pipeline(
        base_url,
        sender,
        chat=chat,
        browser=browser,
        config_dir=deps.config_dir,
        active_probe=bool(params.get("active_probe", True)),
        probe_post=bool(params.get("probe_post", False)),
        max_pages=int(params.get("max_pages", 40)),
        max_depth=int(params.get("max_depth", 2)),
        max_tasks=int(max_tasks) if max_tasks is not None else None,
        oob_domain=str(params.get("oob_domain", "")),
        on_event=lambda e: deps.emit(f"[vuln] {e.get('type')}: "
                                     f"{json.dumps({k: v for k, v in e.items() if k != 'type'})}"),
    )

    # Persist the App Model + plan to the run context (spec: comprehend/plan
    # outputs live on run-context for downstream steps and the report).
    ctx.vars["app_model"] = result.app_model.model_dump() if result.app_model else {}
    ctx.vars["plan"] = [t.model_dump() for t in result.plan]

    rows = [f.to_row() for f in result.findings]
    if rows and deps.store is not None:
        deps.store.record_findings(ctx.run_id, rows)

    return StepResult(
        step_id=step.id,
        status=StepStatus.COMPLETED,
        output=_summary_text(result),
        data={
            "entered_test": result.entered_test,
            "reason": result.reason,
            "surfaces": len(result.app_model.input_surfaces) if result.app_model else 0,
            "tasks": len(result.plan),
            "confirmed": len(result.confirmed),
            "suspected": len([f for f in result.findings if f.status.value == "suspected"]),
            "findings": [
                {
                    "vuln_class": f.vuln_class,
                    "status": f.status.value,
                    "severity": f.severity,
                    "location": f.location(),
                }
                for f in result.findings
            ],
        },
    )
