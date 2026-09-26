"""Plugin system: discover from a dir, merge into the live registries."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from saarthi2 import adapters as adapters_mod
from saarthi2 import functions as functions_mod
from saarthi2 import plugins as plugins_mod
from saarthi2 import steps as steps_mod
from saarthi2.adapters import adapter_catalog, render_adapter_command
from saarthi2.config import Settings
from saarthi2.engine.context import RunContext
from saarthi2.engine.loader import load_workflow_from_str
from saarthi2.engine.models import StepStatus
from saarthi2.engine.runner import StepDeps, WorkflowRunner
from saarthi2.plugins import apply, discover, load_plugins

_PLUGIN = '''
SAARTHI2_PLUGIN_NAME = "demo"


def _shout(args, ctx):
    text = str(args.get("text", ""))
    return {"output": text.upper(), "data": {"len": len(text)}}


SAARTHI2_FUNCTIONS = {"shout": _shout}

SAARTHI2_ADAPTERS = [
    {"name": "myscan", "binary": "myscan", "category": "vuln",
     "template": "myscan -u {target}", "description": "demo scanner"},
]


async def _my_step(step, ctx, deps):
    from saarthi2.engine.models import StepResult, StepStatus
    return StepResult(step_id=step.id, status=StepStatus.COMPLETED, output="plugin-ran")


SAARTHI2_STEPS = {"myplugin": _my_step}
'''


def _write_plugin(directory) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "demo.py").write_text(_PLUGIN)


@pytest.fixture
def clean_registries():
    """Snapshot and restore the global registries mutated by apply()."""

    snap = (
        dict(functions_mod.FUNCTION_REGISTRY),
        dict(adapters_mod.TOOL_ADAPTERS),
        dict(steps_mod.STEP_TYPES),
        set(steps_mod.KNOWN_USES),
        set(plugins_mod._APPLIED_SOURCES),
    )
    try:
        yield
    finally:
        functions_mod.FUNCTION_REGISTRY.clear()
        functions_mod.FUNCTION_REGISTRY.update(snap[0])
        adapters_mod.TOOL_ADAPTERS.clear()
        adapters_mod.TOOL_ADAPTERS.update(snap[1])
        steps_mod.STEP_TYPES.clear()
        steps_mod.STEP_TYPES.update(snap[2])
        steps_mod.KNOWN_USES.clear()
        steps_mod.KNOWN_USES.update(snap[3])
        plugins_mod._APPLIED_SOURCES.clear()
        plugins_mod._APPLIED_SOURCES.update(snap[4])


def test_discover_from_dir(tmp_path) -> None:
    _write_plugin(tmp_path / "plugins")
    bundle = discover(plugins_dir=tmp_path / "plugins", use_entrypoints=False)
    assert "shout" in bundle.functions
    assert "myscan" in bundle.adapters
    assert "myplugin" in bundle.steps
    assert bundle.details[0]["name"] == "demo"
    assert bundle.details[0]["functions"] == 1
    assert bundle.names == ["demo"]


def test_discover_skips_underscore_and_broken(tmp_path) -> None:
    d = tmp_path / "plugins"
    _write_plugin(d)
    (d / "_private.py").write_text("SAARTHI2_FUNCTIONS = {'nope': 1}")
    (d / "broken.py").write_text("raise RuntimeError('boom')")
    bundle = discover(plugins_dir=d, use_entrypoints=False)
    assert bundle.names == ["demo"]  # underscore + broken skipped


def test_apply_merges_registries(tmp_path, clean_registries) -> None:
    bundle = discover(plugins_dir=_seed(tmp_path), use_entrypoints=False)
    assert apply(bundle) == ["demo"]

    # function is callable via the registry
    result = functions_mod.FUNCTION_REGISTRY["shout"]({"text": "hi"}, RunContext(run_id="t"))
    assert result["output"] == "HI"
    # adapter renders + shows in the catalog
    assert render_adapter_command("myscan", {"target": "x"}) == "myscan -u x"
    assert "myscan" in {a["name"] for a in adapter_catalog()}
    # step type registered for validation
    assert "myplugin" in steps_mod.KNOWN_USES


def test_plugin_step_runs_in_workflow(tmp_path, clean_registries) -> None:
    apply(discover(plugins_dir=_seed(tmp_path), use_entrypoints=False))

    async def fake_run_command(cmd, *, timeout=300, shell=False):
        return (0, "", "")

    async def fake_http(*a, **k):
        raise AssertionError

    wf = load_workflow_from_str("name: p\nsteps:\n  - {id: a, uses: myplugin, with: {}}\n")
    deps = StepDeps(run_command=fake_run_command, http_request=fake_http)
    result = asyncio.run(WorkflowRunner(deps).run(wf))
    assert result.status is StepStatus.COMPLETED
    assert result.steps[0].output == "plugin-ran"


def test_load_plugins_idempotent(tmp_path, clean_registries) -> None:
    settings = Settings(work_dir=tmp_path / "work", workflows_dir=tmp_path / "wf")
    _write_plugin(settings.plugins_dir)
    assert load_plugins(settings) == ["demo"]
    assert load_plugins(settings) == []  # cached: applied once per source


def test_api_plugins_endpoint(tmp_path, clean_registries) -> None:
    from saarthi2.server import create_app

    wf_dir = tmp_path / "wf"
    wf_dir.mkdir()
    settings = Settings(work_dir=tmp_path / "work", workflows_dir=wf_dir)
    _write_plugin(settings.plugins_dir)
    client = TestClient(create_app(settings))
    listed = client.get("/api/plugins").json()
    assert any(p["name"] == "demo" for p in listed)


def _seed(tmp_path):
    directory = tmp_path / "plugins"
    _write_plugin(directory)
    return directory
