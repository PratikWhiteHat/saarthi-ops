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


def target_url(target: str) -> str:
    """Ensure the target has a scheme, without ever doubling an existing one.

    ``example.com`` -> ``https://example.com``; a URL is returned unchanged.
    """

    target = (target or "").strip()
    if not target:
        return ""
    return target if "://" in target else f"https://{target}"


def resolve_vars(
    variables: dict[str, Any], base: dict[str, Any], passes: int = 5
) -> dict[str, Any]:
    """Resolve inter-var / target references in workflow vars up front.

    Interpolation is single-pass, so a var like ``workdir: ".../{{ target_slug }}"``
    would leave the inner template literal when another step reads ``{{ vars.workdir }}``.
    Rendering the vars to a fixpoint here (against ``target``/``target_slug``/other
    vars) resolves those before any step runs.
    """

    resolved = dict(variables)
    for _ in range(passes):
        scope = {**base, "vars": resolved}
        updated = {
            key: (render(value, scope) if isinstance(value, str) else value)
            for key, value in resolved.items()
        }
        if updated == resolved:
            break
        resolved = updated
    return resolved


def target_slug(target: str) -> str:
    """A filesystem-safe slug of the target (scheme/host/path collapsed).

    ``https://www.ex.com/a.php?id=7`` -> ``www_ex_com_a_php_id_7``. Safe to use
    as a single directory name regardless of what the target looks like.
    """

    stripped = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", (target or "").strip())
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", stripped).strip("_").lower()
    return slug[:120] or "target"


# Second-level public suffixes so ``apex_domain`` keeps the registrable part
# (e.g. ``a.b.co.uk`` -> ``b.co.uk``). Not the full PSL, but the common cases.
_MULTI_TLDS = frozenset(
    {
        "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
        "co.in", "net.in", "org.in", "gov.in", "ac.in",
        "com.au", "net.au", "org.au", "gov.au",
        "co.nz", "co.za", "co.jp", "or.jp", "ne.jp",
        "com.br", "com.cn", "com.mx", "com.sg", "com.tr",
    }
)


def host_of(value: str) -> str:
    """Extract the bare hostname from a URL or host string (lowercased)."""

    stripped = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", (value or "").strip())
    return stripped.split("/")[0].split(":")[0].lower().rstrip(".")


def apex_domain(value: str) -> str:
    """Registrable apex domain of a host/URL (best-effort, PSL-lite)."""

    host = host_of(value)
    labels = host.split(".")
    if len(labels) < 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


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

        target = self.target or ""
        return {
            "target": target,
            "target_url": target_url(target),
            "target_slug": target_slug(target),
            "run_id": self.run_id,
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
