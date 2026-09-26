"""Built-in workflow functions — Osmedeus-style data/file utilities.

Used by the ``function`` step to glue tool steps together in a pipeline
(e.g. subfinder -> sort_unique -> httpx). Each function takes a dict of
already-interpolated args plus the run context and returns
``{"output": str, "data": dict}``. Pure-Python, no external deps.
"""

from __future__ import annotations

import json
import re
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

from saarthi2.engine.context import RunContext
from saarthi2.stdlib import STDLIB_DOCS, STDLIB_FUNCTIONS


def _path(value: Any) -> Path:
    return Path(str(value)).expanduser()


def _read_lines(path: Any) -> list[str]:
    file_path = _path(path)
    if not file_path.is_file():
        return []
    return [line.rstrip("\n") for line in file_path.read_text(encoding="utf-8").splitlines()]


def _write_lines(path: Any, lines: list[str]) -> str:
    file_path = _path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return str(file_path)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _result(output: str, **data: Any) -> dict:
    return {"output": output, "data": data}


def fn_sort_unique(args: dict, ctx: RunContext) -> dict:
    lines = sorted(set(_read_lines(args.get("input"))))
    out = args.get("output")
    if out:
        _write_lines(out, lines)
    return _result("\n".join(lines), count=len(lines), output_file=out)


def fn_deduplicate(args: dict, ctx: RunContext) -> dict:
    seen: dict[str, None] = {}
    for line in _read_lines(args.get("input")):
        seen.setdefault(line, None)
    lines = list(seen)
    out = args.get("output")
    if out:
        _write_lines(out, lines)
    return _result("\n".join(lines), count=len(lines), output_file=out)


def fn_cat(args: dict, ctx: RunContext) -> dict:
    lines: list[str] = []
    for path in _as_list(args.get("inputs") or args.get("input")):
        lines.extend(_read_lines(path))
    out = args.get("output")
    if out:
        _write_lines(out, lines)
    return _result("\n".join(lines), count=len(lines), output_file=out)


def fn_join(args: dict, ctx: RunContext) -> dict:
    """Union + sort + unique across multiple inputs."""

    merged: set[str] = set()
    for path in _as_list(args.get("inputs") or args.get("input")):
        merged.update(_read_lines(path))
    lines = sorted(merged)
    out = args.get("output")
    if out:
        _write_lines(out, lines)
    return _result("\n".join(lines), count=len(lines), output_file=out)


def fn_count(args: dict, ctx: RunContext) -> dict:
    count = len(_read_lines(args.get("input")))
    return _result(str(count), count=count)


def fn_grep(args: dict, ctx: RunContext) -> dict:
    pattern = re.compile(str(args.get("pattern", "")))
    invert = bool(args.get("invert", False))
    matched = [
        line
        for line in _read_lines(args.get("input"))
        if bool(pattern.search(line)) != invert
    ]
    out = args.get("output")
    if out:
        _write_lines(out, matched)
    return _result("\n".join(matched), count=len(matched), output_file=out)


def fn_replace(args: dict, ctx: RunContext) -> dict:
    search = str(args.get("search", ""))
    replacement = str(args.get("replace", ""))
    lines = [line.replace(search, replacement) for line in _read_lines(args.get("input"))]
    out = args.get("output")
    if out:
        _write_lines(out, lines)
    return _result("\n".join(lines), count=len(lines), output_file=out)


def fn_head(args: dict, ctx: RunContext) -> dict:
    n = int(args.get("n", 10))
    lines = _read_lines(args.get("input"))[:n]
    out = args.get("output")
    if out:
        _write_lines(out, lines)
    return _result("\n".join(lines), count=len(lines), output_file=out)


def fn_tail(args: dict, ctx: RunContext) -> dict:
    n = int(args.get("n", 10))
    lines = _read_lines(args.get("input"))[-n:] if n > 0 else []
    out = args.get("output")
    if out:
        _write_lines(out, lines)
    return _result("\n".join(lines), count=len(lines), output_file=out)


def fn_create_folder(args: dict, ctx: RunContext) -> dict:
    path = _path(args.get("path"))
    path.mkdir(parents=True, exist_ok=True)
    return _result(str(path), path=str(path))


def fn_write(args: dict, ctx: RunContext) -> dict:
    content = str(args.get("content", ""))
    out = _path(args.get("output"))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    return _result(content, output_file=str(out))


def fn_append(args: dict, ctx: RunContext) -> dict:
    content = str(args.get("content", ""))
    out = _path(args.get("output"))
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as handle:
        handle.write(content + "\n")
    return _result(content, output_file=str(out))


def fn_read(args: dict, ctx: RunContext) -> dict:
    file_path = _path(args.get("input"))
    text = file_path.read_text(encoding="utf-8") if file_path.is_file() else ""
    return _result(text, chars=len(text))


def fn_lines_to_json(args: dict, ctx: RunContext) -> dict:
    lines = _read_lines(args.get("input"))
    payload = json.dumps(lines)
    out = args.get("output")
    if out:
        _write_lines(out, [payload])
    return _result(payload, count=len(lines), output_file=out)


def _read_text(path: Any) -> str:
    file_path = _path(path)
    return file_path.read_text(encoding="utf-8") if file_path.is_file() else ""


def fn_extract_ips(args: dict, ctx: RunContext) -> dict:
    from saarthi2.parsers import extract_ips

    items = extract_ips(_read_text(args.get("input")))
    out = args.get("output")
    if out:
        _write_lines(out, items)
    return _result("\n".join(items), count=len(items), output_file=out)


def fn_extract_urls(args: dict, ctx: RunContext) -> dict:
    from saarthi2.parsers import extract_urls

    items = extract_urls(_read_text(args.get("input")))
    out = args.get("output")
    if out:
        _write_lines(out, items)
    return _result("\n".join(items), count=len(items), output_file=out)


def fn_extract_hosts(args: dict, ctx: RunContext) -> dict:
    from saarthi2.parsers import extract_hosts

    items = extract_hosts(_read_text(args.get("input")))
    out = args.get("output")
    if out:
        _write_lines(out, items)
    return _result("\n".join(items), count=len(items), output_file=out)


def fn_parse_sarif(args: dict, ctx: RunContext) -> dict:
    from saarthi2.parsers import parse_sarif

    findings = parse_sarif(_read_text(args.get("input")))
    payload = json.dumps(findings)
    out = args.get("output")
    if out:
        _write_lines(out, [payload])
    return _result(payload, count=len(findings), findings=findings)


def fn_parse_nuclei(args: dict, ctx: RunContext) -> dict:
    from saarthi2.parsers import parse_nuclei_jsonl

    findings = parse_nuclei_jsonl(_read_text(args.get("input")))
    payload = json.dumps(findings)
    out = args.get("output")
    if out:
        _write_lines(out, [payload])
    return _result(payload, count=len(findings), findings=findings)


def fn_classify_cdn_waf(args: dict, ctx: RunContext) -> dict:
    from saarthi2.parsers import classify_cdn_waf

    headers = args.get("headers")
    result = classify_cdn_waf(
        headers if isinstance(headers, dict) else {}, str(args.get("body", ""))
    )
    return _result(json.dumps(result), cdn=result["cdn"], waf=result["waf"])


# --- file-system ops (Osmedeus file_functions) -------------------------------


def fn_file_exists(args: dict, ctx: RunContext) -> dict:
    exists = _path(args.get("input") or args.get("path")).exists()
    return _result("true" if exists else "false", exists=exists)


def fn_delete_file(args: dict, ctx: RunContext) -> dict:
    """Delete a single regular file (never a directory — non-destructive by design)."""

    target = _path(args.get("input") or args.get("path"))
    if not str(target).strip() or str(target) in ("/", str(Path.home())):
        return _result("", deleted=False, error="refusing to delete a root/home path")
    if target.is_file():
        target.unlink()
        return _result(str(target), deleted=True)
    return _result(str(target), deleted=False, error="not a regular file")


def fn_copy_file(args: dict, ctx: RunContext) -> dict:
    src = _path(args.get("src") or args.get("input"))
    dest = _path(args.get("dest") or args.get("output"))
    if not src.is_file():
        return _result("", copied=False, error="source is not a file")
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    return _result(str(dest), copied=True)


def fn_move_file(args: dict, ctx: RunContext) -> dict:
    src = _path(args.get("src") or args.get("input"))
    dest = _path(args.get("dest") or args.get("output"))
    if not src.exists():
        return _result("", moved=False, error="source does not exist")
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dest))
    return _result(str(dest), moved=True)


def fn_list_dir(args: dict, ctx: RunContext) -> dict:
    directory = _path(args.get("input") or args.get("path"))
    if not directory.is_dir():
        return _result("", count=0, error="not a directory")
    entries = sorted(p.name for p in directory.iterdir())
    out = args.get("output")
    if out:
        _write_lines(out, entries)
    return _result("\n".join(entries), count=len(entries), output_file=out)


def fn_clean_empty(args: dict, ctx: RunContext) -> dict:
    """Remove zero-byte files in a directory (Osmedeus-style Cleandir; safe)."""

    directory = _path(args.get("input") or args.get("path"))
    removed = 0
    if directory.is_dir():
        for child in directory.iterdir():
            if child.is_file() and child.stat().st_size == 0:
                child.unlink()
                removed += 1
    return _result(str(removed), removed=removed)


def fn_wc(args: dict, ctx: RunContext) -> dict:
    text = _read_text(args.get("input"))
    lines = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
    words = len(text.split())
    chars = len(text)
    return _result(f"{lines} {words} {chars}", lines=lines, words=words, chars=chars)


FUNCTION_REGISTRY: dict[str, Callable[[dict, RunContext], dict]] = {
    "sort_unique": fn_sort_unique,
    "deduplicate": fn_deduplicate,
    "cat": fn_cat,
    "join": fn_join,
    "count": fn_count,
    "grep": fn_grep,
    "replace": fn_replace,
    "head": fn_head,
    "tail": fn_tail,
    "create_folder": fn_create_folder,
    "write": fn_write,
    "append": fn_append,
    "read": fn_read,
    "lines_to_json": fn_lines_to_json,
    "extract_ips": fn_extract_ips,
    "extract_urls": fn_extract_urls,
    "extract_hosts": fn_extract_hosts,
    "parse_sarif": fn_parse_sarif,
    "parse_nuclei": fn_parse_nuclei,
    "classify_cdn_waf": fn_classify_cdn_waf,
    "file_exists": fn_file_exists,
    "delete_file": fn_delete_file,
    "copy_file": fn_copy_file,
    "move_file": fn_move_file,
    "list_dir": fn_list_dir,
    "clean_empty": fn_clean_empty,
    "wc": fn_wc,
    **STDLIB_FUNCTIONS,
}


def function_catalog() -> list[dict]:
    """Metadata for the API/UI: available functions and a short description."""

    docs = {
        "sort_unique": "Sort + unique the lines of a file.",
        "deduplicate": "Remove duplicate lines, preserving order.",
        "cat": "Concatenate multiple files.",
        "join": "Union + sort + unique across inputs.",
        "count": "Count lines in a file.",
        "grep": "Regex-filter lines (invert=true to negate).",
        "replace": "Replace text in each line.",
        "head": "First N lines.",
        "tail": "Last N lines.",
        "create_folder": "Create a directory.",
        "write": "Write content to a file.",
        "append": "Append a line to a file.",
        "read": "Read a file's contents.",
        "lines_to_json": "Wrap file lines as a JSON array.",
        "extract_ips": "Extract IPv4 addresses from a file.",
        "extract_urls": "Extract http(s) URLs from a file.",
        "extract_hosts": "Extract hostnames from URLs/lines.",
        "parse_sarif": "Parse SARIF (Semgrep/Trivy/CodeQL) into findings.",
        "parse_nuclei": "Parse nuclei -jsonl into findings.",
        "classify_cdn_waf": "Classify CDN/WAF from response headers.",
        "file_exists": "Whether a path exists (true/false).",
        "delete_file": "Delete a single regular file (never a directory).",
        "copy_file": "Copy a file from 'src' to 'dest'.",
        "move_file": "Move/rename a file from 'src' to 'dest'.",
        "list_dir": "List the entries of a directory.",
        "clean_empty": "Remove zero-byte files in a directory.",
        "wc": "Count lines/words/chars of a file.",
        **STDLIB_DOCS,
    }
    return [{"name": name, "description": docs.get(name, "")} for name in FUNCTION_REGISTRY]
