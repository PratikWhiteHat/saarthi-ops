"""Built-in stdlib functions: string / url / util / json / markdown."""

from __future__ import annotations

from saarthi2.engine.context import RunContext
from saarthi2.functions import FUNCTION_REGISTRY, function_catalog


def _ctx() -> RunContext:
    return RunContext(run_id="t")


def _run(name: str, args: dict) -> dict:
    return FUNCTION_REGISTRY[name](args, _ctx())


def test_string_functions() -> None:
    assert _run("upper", {"text": "aB"})["output"] == "AB"
    assert _run("lower", {"text": "aB"})["output"] == "ab"
    assert _run("trim", {"text": "  x  "})["output"] == "x"
    assert _run("split", {"text": "a,b,c", "sep": ","})["data"]["items"] == ["a", "b", "c"]
    assert _run("str_join", {"items": ["a", "b"], "sep": "-"})["output"] == "a-b"
    replaced = _run("replace_regex", {"text": "a1b2", "pattern": r"\d", "replace": "#"})
    assert replaced["output"] == "a#b#"
    assert _run("regex_extract", {"text": "a1b2", "pattern": r"\d"})["data"]["items"] == ["1", "2"]
    assert _run("contains", {"text": "hello", "needle": "ell"})["data"]["found"] is True
    assert _run("length", {"text": "abcd"})["data"]["length"] == 4


def test_base64_roundtrip() -> None:
    enc = _run("base64_encode", {"text": "hi there"})["output"]
    assert _run("base64_decode", {"text": enc})["output"] == "hi there"
    assert _run("base64_decode", {"text": "!!not-b64!!"})["data"]["error"] == "invalid base64"


def test_prepend_append_each() -> None:
    assert _run("prepend_each", {"text": "a\nb", "prefix": "x-"})["output"] == "x-a\nx-b"
    assert _run("append_each", {"text": "a\nb", "suffix": ":1"})["output"] == "a:1\nb:1"


def test_url_functions() -> None:
    parsed = _run("url_parse", {"text": "https://ex.com:8443/p?q=1#f"})["data"]
    assert parsed["scheme"] == "https"
    assert parsed["host"] == "ex.com"
    assert parsed["port"] == 8443
    assert parsed["path"] == "/p"
    assert _run("strip_scheme", {"text": "https://ex.com/x"})["output"] == "ex.com/x"
    assert _run("url_join", {"base": "https://ex.com/a/", "ref": "b"})["output"] == "https://ex.com/a/b"


def test_apex_domain() -> None:
    assert _run("apex_domain", {"text": "a.b.example.com"})["output"] == "example.com"
    assert _run("apex_domain", {"text": "https://x.y.co.uk/path"})["output"] == "y.co.uk"
    assert _run("apex_domain", {"text": "sub.target.co.in"})["output"] == "target.co.in"


def test_util_functions() -> None:
    assert len(_run("uuid", {})["output"]) == 32
    ts = _run("timestamp", {})["data"]
    assert "iso" in ts and isinstance(ts["epoch"], int)
    assert _run("env", {"name": "SAARTHI2_DOES_NOT_EXIST", "default": "d"})["output"] == "d"


def test_json_functions() -> None:
    doc = '{"a": {"b": [10, 20]}, "c": "x"}'
    assert _run("json_get", {"text": doc, "path": "a.b[1]"})["data"]["value"] == 20
    assert _run("json_get", {"text": doc, "path": "c"})["output"] == "x"
    assert _run("json_get", {"text": "not json", "path": "a"})["data"]["error"] == "invalid json"
    assert set(_run("json_keys", {"text": doc})["data"]["items"]) == {"a", "c"}
    pretty = _run("json_pretty", {"text": doc})["output"]
    assert "\n" in pretty
    assert _run("to_json", {"text": "a\nb"})["output"] == '["a", "b"]'


def test_markdown_functions() -> None:
    table = _run("md_table", {"text": "h1,h2\nv1,v2", "sep": ","})["output"]
    assert table.splitlines()[0] == "| h1 | h2 |"
    assert "| --- | --- |" in table
    assert _run("md_heading", {"text": "Title", "level": 2})["output"] == "## Title"
    assert _run("md_bullets", {"text": "a\nb"})["output"] == "- a\n- b"


def test_file_functions(tmp_path) -> None:
    src = tmp_path / "a.txt"
    src.write_text("hi\n")
    assert _run("file_exists", {"path": str(src)})["data"]["exists"] is True
    dest = tmp_path / "b.txt"
    assert _run("copy_file", {"src": str(src), "dest": str(dest)})["data"]["copied"] is True
    assert dest.read_text() == "hi\n"
    moved = tmp_path / "c.txt"
    assert _run("move_file", {"src": str(dest), "dest": str(moved)})["data"]["moved"] is True
    assert not dest.exists() and moved.exists()
    listing = _run("list_dir", {"path": str(tmp_path)})
    assert "a.txt" in listing["output"].splitlines()
    assert _run("delete_file", {"path": str(moved)})["data"]["deleted"] is True
    assert not moved.exists()


def test_delete_file_refuses_root() -> None:
    assert _run("delete_file", {"path": "/"})["data"]["deleted"] is False


def test_clean_empty(tmp_path) -> None:
    (tmp_path / "empty.txt").write_text("")
    (tmp_path / "full.txt").write_text("x")
    assert _run("clean_empty", {"path": str(tmp_path)})["data"]["removed"] == 1
    assert not (tmp_path / "empty.txt").exists()
    assert (tmp_path / "full.txt").exists()


def test_wc(tmp_path) -> None:
    f = tmp_path / "f.txt"
    f.write_text("a b\nc\n")
    data = _run("wc", {"input": str(f)})["data"]
    assert data == {"lines": 2, "words": 3, "chars": 6}


def test_catalog_includes_stdlib() -> None:
    names = {f["name"] for f in function_catalog()}
    assert {"upper", "apex_domain", "json_get", "md_table", "uuid", "wc"} <= names
