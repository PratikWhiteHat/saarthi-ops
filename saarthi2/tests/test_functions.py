"""Built-in workflow functions."""

from __future__ import annotations

from saarthi2.engine.context import RunContext
from saarthi2.functions import FUNCTION_REGISTRY, function_catalog


def _ctx() -> RunContext:
    return RunContext(run_id="t")


def test_sort_unique(tmp_path) -> None:
    inp = tmp_path / "in.txt"
    inp.write_text("b\na\nb\nc\n")
    out = tmp_path / "out.txt"
    r = FUNCTION_REGISTRY["sort_unique"]({"input": str(inp), "output": str(out)}, _ctx())
    assert out.read_text().splitlines() == ["a", "b", "c"]
    assert r["data"]["count"] == 3


def test_deduplicate_preserves_order(tmp_path) -> None:
    inp = tmp_path / "in.txt"
    inp.write_text("b\na\nb\nc\na\n")
    r = FUNCTION_REGISTRY["deduplicate"]({"input": str(inp)}, _ctx())
    assert r["output"].splitlines() == ["b", "a", "c"]


def test_join_union(tmp_path) -> None:
    a = tmp_path / "a"
    a.write_text("x\ny\n")
    b = tmp_path / "b"
    b.write_text("y\nz\n")
    r = FUNCTION_REGISTRY["join"]({"inputs": [str(a), str(b)]}, _ctx())
    assert r["output"].splitlines() == ["x", "y", "z"]


def test_cat(tmp_path) -> None:
    a = tmp_path / "a"
    a.write_text("1\n2\n")
    b = tmp_path / "b"
    b.write_text("3\n")
    r = FUNCTION_REGISTRY["cat"]({"inputs": [str(a), str(b)]}, _ctx())
    assert r["output"].splitlines() == ["1", "2", "3"]


def test_grep_and_invert(tmp_path) -> None:
    inp = tmp_path / "i"
    inp.write_text("apple\nbanana\navocado\n")
    assert FUNCTION_REGISTRY["grep"](
        {"pattern": "^a", "input": str(inp)}, _ctx()
    )["output"].splitlines() == ["apple", "avocado"]
    assert FUNCTION_REGISTRY["grep"](
        {"pattern": "^a", "input": str(inp), "invert": True}, _ctx()
    )["output"].splitlines() == ["banana"]


def test_count_head_tail(tmp_path) -> None:
    inp = tmp_path / "i"
    inp.write_text("1\n2\n3\n4\n5\n")
    assert FUNCTION_REGISTRY["count"]({"input": str(inp)}, _ctx())["data"]["count"] == 5
    assert FUNCTION_REGISTRY["head"](
        {"input": str(inp), "n": 2}, _ctx()
    )["output"].splitlines() == ["1", "2"]
    assert FUNCTION_REGISTRY["tail"](
        {"input": str(inp), "n": 2}, _ctx()
    )["output"].splitlines() == ["4", "5"]


def test_write_append_read_and_create_folder(tmp_path) -> None:
    f = tmp_path / "sub" / "f.txt"
    FUNCTION_REGISTRY["write"]({"content": "hi", "output": str(f)}, _ctx())
    FUNCTION_REGISTRY["append"]({"content": "bye", "output": str(f)}, _ctx())
    out = FUNCTION_REGISTRY["read"]({"input": str(f)}, _ctx())["output"]
    assert "hi" in out and "bye" in out
    folder = tmp_path / "made"
    FUNCTION_REGISTRY["create_folder"]({"path": str(folder)}, _ctx())
    assert folder.is_dir()


def test_catalog_lists_functions() -> None:
    names = {f["name"] for f in function_catalog()}
    assert {"sort_unique", "grep", "join"} <= names


def test_function_step_persists_findings(tmp_path) -> None:
    """A function that emits `findings` records them to the store."""

    import asyncio

    from saarthi2.engine.models import Step
    from saarthi2.engine.runner import StepDeps
    from saarthi2.state import Store
    from saarthi2.steps.function import handle_function

    nuclei = tmp_path / "n.jsonl"
    nuclei.write_text(
        '{"template-id": "cve-x", "info": {"name": "boom", "severity": "high"}, '
        '"matched-at": "http://ex.com"}\n'
    )
    store = Store(tmp_path / "db.sqlite", tmp_path / "ev", tmp_path / "audit.jsonl")
    deps = StepDeps(run_command=None, http_request=None, store=store)  # type: ignore[arg-type]
    step = Step(id="p", uses="function", with_={"func": "parse_nuclei", "input": str(nuclei)})
    ctx = _ctx()

    result = asyncio.run(handle_function(step, ctx, deps))
    assert result.status.value == "completed"
    rows = store.list_findings(run_id=ctx.run_id)
    store.close()
    assert len(rows) == 1
    assert rows[0]["severity"] == "high"
    assert rows[0]["rule_id"] == "cve-x"
