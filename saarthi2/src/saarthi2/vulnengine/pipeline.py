"""Orchestrate comprehend -> plan -> test -> verify -> report.

Enforces the HARD REQUIREMENT: the pipeline cannot enter TEST without a populated
App Model AND a non-empty plan. When either is missing it stops with a reason and
zero findings — it never falls back to blind probing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from saarthi2.vulnengine.comprehend import build_app_model
from saarthi2.vulnengine.crawl import crawl_site
from saarthi2.vulnengine.http import HttpSender
from saarthi2.vulnengine.models import AppModel, Finding, TestTask
from saarthi2.vulnengine.planner import plan as build_plan
from saarthi2.vulnengine.tester import run_tests


@dataclass
class PipelineResult:
    app_model: AppModel | None = None
    plan: list[TestTask] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    entered_test: bool = False
    reason: str = ""

    @property
    def confirmed(self) -> list[Finding]:
        return [f for f in self.findings if f.status.value == "confirmed"]


async def run_pipeline(
    base_url: str,
    sender: HttpSender,
    *,
    chat: Any = None,
    browser: Any = None,
    oob_check: Any = None,
    oob_domain: str = "",
    config_dir: Path | None = None,
    active_probe: bool = True,
    probe_post: bool = False,
    max_pages: int = 40,
    max_depth: int = 2,
    max_tasks: int | None = None,
    on_event: Any = None,
) -> PipelineResult:
    """Run the full back half of a run against ``base_url`` as the current session."""

    def emit(event: dict) -> None:
        if on_event is not None:
            try:
                on_event(event)
            except Exception:
                pass

    emit({"type": "phase", "phase": "comprehend"})
    crawl = await crawl_site(base_url, sender, max_pages=max_pages, max_depth=max_depth)
    app_model = await build_app_model(
        crawl, sender, chat=chat, active_probe=active_probe, probe_post=probe_post
    )
    emit(
        {
            "type": "app_model",
            "app_type": app_model.app_type,
            "surfaces": len(app_model.input_surfaces),
            "signals": app_model.interesting_signals,
        }
    )

    # HARD REQUIREMENT #1: no App Model surfaces -> refuse to enter TEST.
    if not app_model.is_populated:
        return PipelineResult(
            app_model=app_model,
            entered_test=False,
            reason="App Model has no input surfaces — refusing to enter TEST.",
        )

    emit({"type": "phase", "phase": "plan"})
    tasks = build_plan(app_model, config_dir=config_dir)
    emit({"type": "plan", "tasks": len(tasks)})

    # HARD REQUIREMENT #2: empty plan -> refuse to enter TEST.
    if not tasks:
        return PipelineResult(
            app_model=app_model,
            plan=[],
            entered_test=False,
            reason="Plan is empty — refusing to enter TEST.",
        )

    emit({"type": "phase", "phase": "test"})
    findings = await run_tests(
        tasks,
        app_model,
        sender,
        config_dir=config_dir,
        browser=browser,
        oob_check=oob_check,
        oob_domain=oob_domain,
        max_tasks=max_tasks,
        on_event=on_event,
    )
    emit(
        {
            "type": "phase",
            "phase": "report",
            "findings": len(findings),
            "confirmed": len([f for f in findings if f.status.value == "confirmed"]),
        }
    )
    return PipelineResult(
        app_model=app_model, plan=tasks, findings=findings, entered_test=True
    )
