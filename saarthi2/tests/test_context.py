"""Interpolation, loop resolution, and conditions stay small and safe."""

from __future__ import annotations

from saarthi2.engine.context import (
    RunContext,
    evaluate_when,
    render,
    render_obj,
    resolve_items,
)
from saarthi2.engine.models import StepResult, StepStatus


def _scope(**kw):
    base = {"target": "", "vars": {}, "steps": {}, "item": None}
    base.update(kw)
    return base


def test_render_substitutes_dotted_paths() -> None:
    scope = _scope(target="ex.com", vars={"n": "bob"}, steps={"a": {"output": "X"}})
    assert render("host {{ target }}", scope) == "host ex.com"
    assert render("hi {{ vars.n }}", scope) == "hi bob"
    assert render("{{ steps.a.output }}", scope) == "X"


def test_render_missing_path_is_empty() -> None:
    assert render("[{{ nope.here }}]", _scope()) == "[]"


def test_render_obj_recurses() -> None:
    scope = _scope(target="t")
    out = render_obj({"cmd": "scan {{ target }}", "n": [1, "{{ target }}"]}, scope)
    assert out == {"cmd": "scan t", "n": [1, "t"]}


def test_resolve_items_from_string_lines() -> None:
    scope = _scope(steps={"subs": {"output": "a\nb\n\n c "}})
    assert resolve_items("{{ steps.subs.output }}", scope) == ["a", "b", "c"]


def test_resolve_items_from_list() -> None:
    scope = _scope(vars={"hosts": ["x", "y"]})
    assert resolve_items("{{ vars.hosts }}", scope) == ["x", "y"]


def test_resolve_items_missing_is_empty() -> None:
    assert resolve_items("{{ vars.none }}", _scope()) == []


def test_evaluate_when() -> None:
    assert evaluate_when("{{ steps.a.output }}", _scope(steps={"a": {"output": "d"}}))
    assert not evaluate_when("{{ steps.a.output }}", _scope(steps={"a": {"output": ""}}))
    assert not evaluate_when("false", _scope())
    assert evaluate_when("true", _scope())


def test_run_context_record_exposes_step_output() -> None:
    ctx = RunContext(run_id="r1", target="ex.com")
    ctx.record("a", StepResult(step_id="a", status=StepStatus.COMPLETED, output="hello"))
    assert ctx.scope()["steps"]["a"]["output"] == "hello"
    assert render("{{ steps.a.output }}", ctx.scope()) == "hello"
