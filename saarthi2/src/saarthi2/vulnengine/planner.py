"""PLAN — deterministic App Model -> ordered test tasks via the editable matrix.

The class<->feature routing is fixed config (the feature->vuln matrix). The model
may reorder/prioritize the resulting list, but it never changes which class maps
to which feature. Two matching modes (see the matrix header):

  * a rule WITH ``requires`` routes on grounded signals, per parameter — so a
    reflecting numeric id yields both idor_bola (numeric_id) and xss/sqli
    (reflects_input), each pinned to the parameter that earned it.
  * a rule WITHOUT ``requires`` routes on the surface's structural ``type``
    (auth_field, file_upload).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from saarthi2.vulnengine import signals as sig
from saarthi2.vulnengine.config import load_matrix
from saarthi2.vulnengine.models import AppModel, InputSurface, SurfaceType, TestTask


def _effective_param_signals(surface: InputSurface, param: str) -> set[str]:
    stored = surface.param_signals.get(param)
    if stored:
        return set(stored)
    return sig.param_signals(param, surface.example_values.get(param, ""))


def _rule_priority(rule: dict[str, Any]) -> int:
    try:
        return int(rule.get("priority", 0))
    except (TypeError, ValueError):
        return 0


def _classes(rule: dict[str, Any]) -> list[str]:
    raw = rule.get("vuln_classes") or []
    return [str(c).strip() for c in raw if str(c).strip()]


def plan(
    app_model: AppModel,
    *,
    config_dir: Path | None = None,
    matrix: dict[str, Any] | None = None,
) -> list[TestTask]:
    """Map an App Model to a deduped, priority-ordered list of test tasks."""

    matrix = matrix if matrix is not None else load_matrix(config_dir)
    surface_rules = matrix.get("surface_rules") or []
    app_rules = matrix.get("app_rules") or []

    # key -> (priority, task) so a higher-priority rule wins on dedup.
    chosen: dict[tuple[str, str, str, str], tuple[int, TestTask]] = {}

    def add(task: TestTask, priority: int) -> None:
        existing = chosen.get(task.key())
        if existing is None or priority > existing[0]:
            task.priority = priority
            chosen[task.key()] = (priority, task)

    for surface in app_model.input_surfaces:
        params = surface.params or [None]  # form-level task when no named params
        for rule in surface_rules:
            if not isinstance(rule, dict):
                continue
            requires = {str(r) for r in (rule.get("requires") or [])}
            priority = _rule_priority(rule)
            classes = _classes(rule)
            if not classes:
                continue

            if requires:
                for param in surface.params:
                    if requires <= _effective_param_signals(surface, param):
                        for vuln_class in classes:
                            add(
                                TestTask(
                                    endpoint=surface.url,
                                    param=param,
                                    method=surface.method,
                                    vuln_class=vuln_class,
                                    surface_type=surface.type,
                                    auth_required=surface.auth_required,
                                    signals=sorted(requires),
                                ),
                                priority,
                            )
            else:
                rule_type = str(rule.get("type") or SurfaceType.GENERIC)
                if rule_type != surface.type.value:
                    continue
                for param in params:
                    for vuln_class in classes:
                        add(
                            TestTask(
                                endpoint=surface.url,
                                param=param,
                                method=surface.method,
                                vuln_class=vuln_class,
                                surface_type=surface.type,
                                auth_required=surface.auth_required,
                                signals=[f"type={surface.type.value}"],
                            ),
                            priority,
                        )

    for rule in app_rules:
        if not isinstance(rule, dict):
            continue
        if str(rule.get("app_type") or "").strip().lower() != app_model.app_type.strip().lower():
            continue
        priority = _rule_priority(rule)
        classes = _classes(rule)
        for surface in app_model.input_surfaces:
            for param in surface.params or [None]:
                for vuln_class in classes:
                    add(
                        TestTask(
                            endpoint=surface.url,
                            param=param,
                            method=surface.method,
                            vuln_class=vuln_class,
                            surface_type=surface.type,
                            auth_required=surface.auth_required,
                            signals=[f"app_type={app_model.app_type}"],
                        ),
                        priority,
                    )

    tasks = [task for _, task in chosen.values()]
    tasks.sort(
        key=lambda t: (-t.priority, t.endpoint, t.param or "", t.vuln_class)
    )
    return tasks
