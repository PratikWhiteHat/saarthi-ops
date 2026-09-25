"""Run context and ``{{ }}`` variable interpolation.

Deliberately small and safe: no ``eval``/Jinja. Templates reference dotted paths
into the run context — ``{{ target }}``, ``{{ item }}``, ``{{ vars.foo }}``,
``{{ steps.<id>.output }}`` — and unknown paths render to an empty string.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from saarthi2.engine.models import StepResult

_TEMPLATE_RE = re.compile(r"\{\{\s*([^}]+?)\s*\}\}")
_SINGLE_RE = re.compile(r"^\s*\{\{\s*([^}]+?)\s*\}\}\s*$")
_FALSY = {"", "false", "0", "none", "no", "null"}


def _lookup(path: str, root: dict[str, Any]) -> Any:
    """Walk a dotted path through nested dicts/objects; None if absent."""

    current: Any = root
    for part in path.strip().split("."):
        part = part.strip()
        if part == "":
            return None
        if isinstance(current, dict):
            if part not in current:
                return None
            current = current[part]
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            current = getattr(current, part, None)
        if current is None:
            return None
    return current


def render(template: Any, root: dict[str, Any]) -> Any:
    """Interpolate a value. Non-strings pass through unchanged."""

    if not isinstance(template, str):
        return template

    def _sub(match: re.Match[str]) -> str:
        value = _lookup(match.group(1), root)
        return "" if value is None else str(value)

    return _TEMPLATE_RE.sub(_sub, template)


def render_obj(obj: Any, root: dict[str, Any]) -> Any:
    """Recursively interpolate all strings inside a dict/list structure."""

    if isinstance(obj, str):
        return render(obj, root)
    if isinstance(obj, dict):
        return {key: render_obj(value, root) for key, value in obj.items()}
    if isinstance(obj, list):
        return [render_obj(item, root) for item in obj]
    return obj


def resolve_items(expr: str, root: dict[str, Any]) -> list[Any]:
    """Resolve a ``loop`` expression into a list of items.

    A bare ``{{ path }}`` resolves to the raw value (a list is used as-is; a
    string is split into non-empty lines). Anything else is rendered to a string
    and split into lines.
    """

    single = _SINGLE_RE.match(expr)
    if single is not None:
        value = _lookup(single.group(1), root)
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            return [line.strip() for line in value.splitlines() if line.strip()]
        return [value]

    rendered = render(expr, root)
    return [line.strip() for line in str(rendered).splitlines() if line.strip()]


def evaluate_when(expr: str, root: dict[str, Any]) -> bool:
    """Return whether a ``when`` expression is truthy after interpolation."""

    return str(render(expr, root)).strip().lower() not in _FALSY


@dataclass
class RunContext:
    """Mutable state threaded through a workflow run."""

    run_id: str
    target: str | None = None
    vars: dict[str, Any] = field(default_factory=dict)
    steps: dict[str, Any] = field(default_factory=dict)
    item: Any = None

    def scope(self) -> dict[str, Any]:
        """The dict templates resolve against."""

        return {
            "target": self.target or "",
            "vars": self.vars,
            "steps": self.steps,
            "item": self.item,
        }

    def record(self, step_id: str, result: StepResult) -> None:
        """Expose a completed step's result under ``steps.<id>``."""

        self.steps[step_id] = {
            "output": result.output,
            "data": result.data,
            "exit_code": result.exit_code,
            "status": result.status.value,
        }
