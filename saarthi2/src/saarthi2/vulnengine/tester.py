"""TEST — run each planned task through payloads + the oracle, emit findings.

Sequential, one endpoint at a time (the engine is local and non-parallel by
design). For each task we SELECT+MUTATE templated payloads, then hand them to the
oracle. A confirmed verdict yields a ``confirmed``/``oracle`` finding with
evidence; a merely suspicious one yields a ``suspected``/``ai`` finding; nothing
suspicious yields no finding at all (so a clean target stays empty).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from saarthi2.vulnengine import oracle
from saarthi2.vulnengine.http import HttpSender
from saarthi2.vulnengine.models import (
    AppModel,
    Finding,
    FindingSource,
    FindingStatus,
    InputSurface,
    TestTask,
    severity_for,
)
from saarthi2.vulnengine.payloads import select_and_mutate


def _finding_id(task: TestTask) -> str:
    raw = "|".join([task.method, task.endpoint, task.param or "", task.vuln_class])
    return "f-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def build_surface_index(app_model: AppModel) -> dict[tuple[str, str], InputSurface]:
    index: dict[tuple[str, str], InputSurface] = {}
    for surface in app_model.input_surfaces:
        index.setdefault((surface.method.upper(), surface.url), surface)
    return index


def _summary(task: TestTask, verdict: oracle.Verdict, confirmed: bool) -> str:
    where = f"parameter '{task.param}' of {task.endpoint}" if task.param else task.endpoint
    tech = verdict.technique or task.vuln_class
    if confirmed:
        return (
            f"Confirmed {tech} in {where} ({task.method}). The oracle reproduced it "
            f"deterministically: {_evidence_sentence(verdict)}"
        )
    note = f" ({verdict.reason})" if verdict.reason else ""
    return (
        f"Suspected {tech} in {where} ({task.method}) — a positive signal was seen "
        f"but the oracle could not confirm it{note}. Needs manual review."
    )


def _evidence_sentence(verdict: oracle.Verdict) -> str:
    ev = verdict.evidence
    t = verdict.technique
    if t == "sqli_boolean":
        return (
            f"TRUE and FALSE payloads gave a stable, differing response "
            f"(true_len={ev.get('true_len')} vs false_len={ev.get('false_len')}, "
            f"{ev.get('trials')} trials)."
        )
    if t == "sqli_error":
        return "a SQL error appeared with the injected quote and not at baseline."
    if t in ("sqli_time", "command_injection"):
        return (
            f"the injected delay reproduced and scaled (baseline={ev.get('baseline_ms')}ms, "
            f"{ev.get('sleep_s')}s→{ev.get('injected_ms')}ms, "
            f"2x→{ev.get('injected_2x_ms')}ms)."
        )
    if t == "reflected_xss":
        return (
            "the payload reflected and executed in a headless browser "
            f"(marker {ev.get('marker')})."
        )
    if t == "lfi":
        return (
            f"the response leaked file contents matching /{ev.get('signature')}/ "
            f"('{ev.get('match')}')."
        )
    if t == "open_redirect":
        return f"the redirect Location pointed at the attacker host ({ev.get('location')})."
    if t == "idor_bola":
        return (
            f"id {ev.get('neighbor_id')} returned a different object than {ev.get('own_id')} "
            f"under the current session."
        )
    if t == "ssrf":
        return f"an OOB callback carrying the minted token arrived ({ev.get('oob')})."
    return "see evidence."


async def run_tests(
    tasks: list[TestTask],
    app_model: AppModel,
    sender: HttpSender,
    *,
    config_dir: Path | None = None,
    payloads_cfg: dict[str, Any] | None = None,
    browser: Any = None,
    oob_check: Any = None,
    oob_domain: str = "",
    attacker_host: str = "saarthi-oast.example",
    sleep: int = 5,
    max_tasks: int | None = None,
    on_event: Any = None,
) -> list[Finding]:
    """Execute the plan sequentially and return the findings it produced."""

    index = build_surface_index(app_model)
    findings: dict[str, Finding] = {}
    ran = 0

    for task in tasks:
        if max_tasks is not None and ran >= max_tasks:
            break
        surface = index.get((task.method.upper(), task.endpoint))
        if surface is None:
            continue
        prepared = select_and_mutate(
            task.vuln_class,
            config_dir=config_dir,
            payloads_cfg=payloads_cfg,
            sleep=sleep,
            attacker_host=attacker_host,
            oob_domain=oob_domain,
        )
        if not prepared:
            continue
        ran += 1
        if on_event is not None:
            on_event({"type": "test", "vuln_class": task.vuln_class,
                      "endpoint": task.endpoint, "param": task.param})

        try:
            verdict = await oracle.verify(
                task, surface, sender, prepared, browser=browser, oob_check=oob_check
            )
        except Exception as exc:  # a verifier error must not kill the run
            verdict = oracle.Verdict(technique=task.vuln_class, reason=f"verify error: {exc}")

        if not verdict.confirmed and not verdict.suspected:
            continue

        confirmed = verdict.confirmed
        fid = _finding_id(task)
        finding = Finding(
            id=fid,
            vuln_class=verdict.technique or task.vuln_class,
            severity=severity_for(verdict.technique or task.vuln_class),
            url=task.endpoint,
            param=task.param,
            method=task.method,
            status=FindingStatus.CONFIRMED if confirmed else FindingStatus.SUSPECTED,
            source=FindingSource.ORACLE if confirmed else FindingSource.AI,
            confidence=0.99 if confirmed else 0.4,
            summary=_summary(task, verdict, confirmed),
            request={
                "method": task.method,
                "url": task.endpoint,
                "param": task.param,
                "technique": verdict.technique,
                "payload": prepared[0].values,
            },
            evidence=verdict.evidence,
        )
        # A confirmed finding supersedes an earlier suspected one for the same task.
        existing = findings.get(fid)
        if existing is None or (confirmed and existing.status is not FindingStatus.CONFIRMED):
            findings[fid] = finding
        if on_event is not None and confirmed:
            on_event({"type": "confirmed", "vuln_class": finding.vuln_class,
                      "endpoint": task.endpoint, "param": task.param})

    ordered = sorted(
        findings.values(),
        key=lambda f: (f.status is not FindingStatus.CONFIRMED, f.vuln_class, f.url),
    )
    return ordered
