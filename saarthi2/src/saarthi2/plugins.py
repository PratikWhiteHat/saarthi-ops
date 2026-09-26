"""Plugin system — extend Saarthi 2.0 with third-party functions/adapters/steps.

Osmedeus loads external plugins; here a plugin is a Python module that exposes any
of these module-level attributes:

    SAARTHI2_PLUGIN_NAME: str                 # optional display name
    SAARTHI2_FUNCTIONS:  dict[str, callable]  # func name -> (args, ctx) -> {"output","data"}
    SAARTHI2_ADAPTERS:   list[ToolAdapter|dict]  # named tool-adapter command templates
    SAARTHI2_STEPS:      dict[str, handler]   # uses-name -> async step handler

Plugins are discovered from two sources:

1. **Installed packages** declaring the ``saarthi2.plugins`` entry-point group
   (each entry point resolves to such a module/object).
2. **Local files** ``*.py`` dropped into the plugins directory
   (``<work_dir>/plugins`` by default) — same trust model as workflows.

``load_plugins(settings)`` discovers + merges everything into the live registries
(:data:`saarthi2.functions.FUNCTION_REGISTRY`, :data:`saarthi2.adapters.TOOL_ADAPTERS`,
:data:`saarthi2.steps.STEP_TYPES`) and is idempotent per source.
"""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Sources already applied, so repeated load_plugins() calls in one process are cheap
# and side-effect-free after the first.
_APPLIED_SOURCES: set[str] = set()


@dataclass
class PluginBundle:
    """Everything discovered from the available plugins."""

    functions: dict[str, Any] = field(default_factory=dict)
    adapters: dict[str, Any] = field(default_factory=dict)  # name -> ToolAdapter
    steps: dict[str, Any] = field(default_factory=dict)
    details: list[dict] = field(default_factory=list)

    @property
    def names(self) -> list[str]:
        return [d["name"] for d in self.details]


def _coerce_adapter(item: Any) -> Any:
    from saarthi2.adapters import ToolAdapter

    if isinstance(item, ToolAdapter):
        return item
    if isinstance(item, dict):
        name = item.get("name")
        if not name:
            raise ValueError("adapter dict requires a 'name'")
        return ToolAdapter(
            name=str(name),
            binary=str(item.get("binary", name)),
            category=str(item.get("category", "plugin")),
            template=str(item.get("template", "")),
            description=str(item.get("description", "")),
            install=str(item.get("install", "")),
        )
    raise TypeError(f"adapter must be a ToolAdapter or dict, got {type(item).__name__}")


def _harvest(module: Any, fallback_name: str, source: str, bundle: PluginBundle) -> None:
    name = str(getattr(module, "SAARTHI2_PLUGIN_NAME", fallback_name))

    funcs = getattr(module, "SAARTHI2_FUNCTIONS", None)
    n_funcs = 0
    if isinstance(funcs, dict):
        bundle.functions.update(funcs)
        n_funcs = len(funcs)

    adapters = getattr(module, "SAARTHI2_ADAPTERS", None) or []
    n_adapters = 0
    for item in adapters:
        adapter = _coerce_adapter(item)
        bundle.adapters[adapter.name] = adapter
        n_adapters += 1

    steps = getattr(module, "SAARTHI2_STEPS", None)
    n_steps = 0
    if isinstance(steps, dict):
        bundle.steps.update(steps)
        n_steps = len(steps)

    bundle.details.append(
        {
            "name": name,
            "source": source,
            "functions": n_funcs,
            "adapters": n_adapters,
            "steps": n_steps,
        }
    )


def _load_file(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(f"saarthi2_plugin_{path.stem}", path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def discover(plugins_dir: str | Path | None = None, use_entrypoints: bool = True) -> PluginBundle:
    """Discover plugins from entry points and/or a local directory (no mutation)."""

    bundle = PluginBundle()

    if use_entrypoints:
        try:
            from importlib.metadata import entry_points

            eps = list(entry_points(group="saarthi2.plugins"))
        except Exception:
            eps = []
        for ep in eps:
            try:
                _harvest(ep.load(), ep.name, "entrypoint", bundle)
            except Exception:
                continue

    if plugins_dir:
        directory = Path(plugins_dir).expanduser()
        if directory.is_dir():
            for path in sorted(directory.glob("*.py")):
                if path.name.startswith("_"):
                    continue
                try:
                    module = _load_file(path)
                    if module is not None:
                        _harvest(module, path.stem, f"file:{path.name}", bundle)
                except Exception:
                    continue

    return bundle


def apply(bundle: PluginBundle) -> list[str]:
    """Merge a discovered bundle into the live registries. Returns plugin names."""

    from saarthi2 import adapters as adapters_mod
    from saarthi2 import functions as functions_mod
    from saarthi2 import steps as steps_mod

    functions_mod.FUNCTION_REGISTRY.update(bundle.functions)
    adapters_mod.TOOL_ADAPTERS.update(bundle.adapters)
    steps_mod.STEP_TYPES.update(bundle.steps)
    steps_mod.KNOWN_USES.update(bundle.steps.keys())
    return bundle.names


def load_plugins(settings: Any, *, force: bool = False) -> list[str]:
    """Discover + apply plugins for a settings object (idempotent per source)."""

    plugins_dir = getattr(settings, "plugins_dir", None)
    source_key = str(plugins_dir or "")
    if not force and source_key in _APPLIED_SOURCES:
        return []
    bundle = discover(plugins_dir=plugins_dir)
    applied = apply(bundle)
    _APPLIED_SOURCES.add(source_key)
    return applied
