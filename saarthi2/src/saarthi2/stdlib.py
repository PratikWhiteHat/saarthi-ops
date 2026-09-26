"""Built-in workflow function stdlib — Osmedeus-style string/url/util/json/markdown helpers.

These extend :mod:`saarthi2.functions` with pure, dependency-light helpers that the
``function`` step can call to glue tool steps together. Each function takes a dict of
already-interpolated args plus the run context and returns ``{"output": str, "data": dict}``.

Grouped to mirror Osmedeus's ``internal/functions`` packages:
string / url / util / json (jq-lite) / markdown.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import uuid as _uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlsplit

from saarthi2.engine.context import RunContext
from saarthi2.engine.context import apex_domain as _apex_domain


def _result(output: str, **data: Any) -> dict:
    return {"output": output, "data": data}


def _text(args: dict) -> str:
    """The primary string input for a function — ``text`` or ``input``."""

    value = args.get("text")
    if value is None:
        value = args.get("input", "")
    return "" if value is None else str(value)


# --- string functions --------------------------------------------------------


def fn_upper(args: dict, ctx: RunContext) -> dict:
    out = _text(args).upper()
    return _result(out, value=out)


def fn_lower(args: dict, ctx: RunContext) -> dict:
    out = _text(args).lower()
    return _result(out, value=out)


def fn_trim(args: dict, ctx: RunContext) -> dict:
    chars = args.get("chars")
    out = _text(args).strip(str(chars)) if chars else _text(args).strip()
    return _result(out, value=out)


def fn_title(args: dict, ctx: RunContext) -> dict:
    out = _text(args).title()
    return _result(out, value=out)


def fn_split(args: dict, ctx: RunContext) -> dict:
    sep = args.get("sep")
    parts = _text(args).split(str(sep)) if sep else _text(args).split()
    return _result("\n".join(parts), items=parts, count=len(parts))


def fn_join(args: dict, ctx: RunContext) -> dict:
    sep = str(args.get("sep", ","))
    items = args.get("items")
    if isinstance(items, list):
        parts = [str(i) for i in items]
    else:
        parts = [line for line in _text(args).splitlines() if line]
    out = sep.join(parts)
    return _result(out, value=out, count=len(parts))


def fn_replace_regex(args: dict, ctx: RunContext) -> dict:
    pattern = str(args.get("pattern", ""))
    replacement = str(args.get("replace", ""))
    out = re.sub(pattern, replacement, _text(args))
    return _result(out, value=out)


def fn_regex_extract(args: dict, ctx: RunContext) -> dict:
    pattern = re.compile(str(args.get("pattern", "")))
    matches = pattern.findall(_text(args))
    # findall returns tuples for multiple groups; normalize to strings.
    flat = ["".join(m) if isinstance(m, tuple) else str(m) for m in matches]
    return _result("\n".join(flat), items=flat, count=len(flat))


def fn_contains(args: dict, ctx: RunContext) -> dict:
    needle = str(args.get("needle", args.get("substr", "")))
    found = needle in _text(args)
    return _result("true" if found else "false", found=found)


def fn_base64_encode(args: dict, ctx: RunContext) -> dict:
    out = base64.b64encode(_text(args).encode("utf-8")).decode("ascii")
    return _result(out, value=out)


def fn_base64_decode(args: dict, ctx: RunContext) -> dict:
    try:
        out = base64.b64decode(_text(args).encode("ascii")).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return _result("", value="", error="invalid base64")
    return _result(out, value=out)


def fn_length(args: dict, ctx: RunContext) -> dict:
    n = len(_text(args))
    return _result(str(n), length=n)


def fn_prepend_each(args: dict, ctx: RunContext) -> dict:
    prefix = str(args.get("prefix", ""))
    lines = [prefix + line for line in _text(args).splitlines()]
    return _result("\n".join(lines), count=len(lines))


def fn_append_each(args: dict, ctx: RunContext) -> dict:
    suffix = str(args.get("suffix", ""))
    lines = [line + suffix for line in _text(args).splitlines()]
    return _result("\n".join(lines), count=len(lines))


# --- url functions -----------------------------------------------------------


def fn_url_parse(args: dict, ctx: RunContext) -> dict:
    parts = urlsplit(_text(args))
    data = {
        "scheme": parts.scheme,
        "host": parts.hostname or "",
        "port": parts.port,
        "path": parts.path,
        "query": parts.query,
        "fragment": parts.fragment,
    }
    return _result(json.dumps(data), **data)


def fn_strip_scheme(args: dict, ctx: RunContext) -> dict:
    out = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", _text(args))
    return _result(out, value=out)


def fn_apex_domain(args: dict, ctx: RunContext) -> dict:
    apex = _apex_domain(_text(args))
    return _result(apex, apex=apex)


def fn_url_join(args: dict, ctx: RunContext) -> dict:
    base = str(args.get("base", ""))
    ref = str(args.get("ref", args.get("path", "")))
    out = urljoin(base, ref)
    return _result(out, value=out)


# --- util functions ----------------------------------------------------------


def fn_uuid(args: dict, ctx: RunContext) -> dict:
    out = _uuid.uuid4().hex
    return _result(out, value=out)


def fn_timestamp(args: dict, ctx: RunContext) -> dict:
    now = datetime.now(UTC)
    fmt = args.get("format")
    out = now.strftime(str(fmt)) if fmt else now.isoformat()
    return _result(out, iso=now.isoformat(), epoch=int(now.timestamp()))


def fn_env(args: dict, ctx: RunContext) -> dict:
    name = str(args.get("name", ""))
    default = str(args.get("default", ""))
    out = os.environ.get(name, default)
    return _result(out, value=out)


# --- json (jq-lite) functions ------------------------------------------------

_PATH_RE = re.compile(r"\[(\d+)\]|([^.\[\]]+)")


def _walk_json(data: Any, path: str) -> Any:
    """Walk a jq-lite path like ``a.b[0].c`` through parsed JSON."""

    current = data
    for index, key in _PATH_RE.findall(path):
        if current is None:
            return None
        if index != "":
            if isinstance(current, list):
                idx = int(index)
                current = current[idx] if -len(current) <= idx < len(current) else None
            else:
                return None
        else:
            current = current.get(key) if isinstance(current, dict) else None
    return current


def fn_json_get(args: dict, ctx: RunContext) -> dict:
    try:
        data = json.loads(_text(args))
    except (ValueError, TypeError):
        return _result("", value=None, error="invalid json")
    value = _walk_json(data, str(args.get("path", "")))
    out = value if isinstance(value, str) else json.dumps(value)
    return _result("" if value is None else out, value=value)


def fn_json_keys(args: dict, ctx: RunContext) -> dict:
    try:
        data = json.loads(_text(args))
    except (ValueError, TypeError):
        return _result("", items=[], error="invalid json")
    keys = list(data) if isinstance(data, dict) else []
    return _result("\n".join(map(str, keys)), items=keys, count=len(keys))


def fn_json_pretty(args: dict, ctx: RunContext) -> dict:
    try:
        data = json.loads(_text(args))
    except (ValueError, TypeError):
        return _result(_text(args), error="invalid json")
    out = json.dumps(data, indent=2, sort_keys=bool(args.get("sort", False)))
    return _result(out)


def fn_to_json(args: dict, ctx: RunContext) -> dict:
    value = args.get("value")
    if value is None:
        value = [line for line in _text(args).splitlines() if line]
    out = json.dumps(value)
    return _result(out, value=value)


# --- markdown functions ------------------------------------------------------


def fn_md_table(args: dict, ctx: RunContext) -> dict:
    """Render a Markdown table from delimited lines (first line = header)."""

    sep = str(args.get("sep", ","))
    rows = [line.split(sep) for line in _text(args).splitlines() if line.strip()]
    if not rows:
        return _result("")
    width = max(len(r) for r in rows)
    rows = [r + [""] * (width - len(r)) for r in rows]
    header, *body = rows
    lines = [
        "| " + " | ".join(c.strip() for c in header) + " |",
        "| " + " | ".join(["---"] * width) + " |",
    ]
    lines += ["| " + " | ".join(c.strip() for c in row) + " |" for row in body]
    out = "\n".join(lines)
    return _result(out, rows=len(body))


def fn_md_heading(args: dict, ctx: RunContext) -> dict:
    level = max(1, min(6, int(args.get("level", 1))))
    out = "#" * level + " " + _text(args)
    return _result(out)


def fn_md_bullets(args: dict, ctx: RunContext) -> dict:
    lines = ["- " + line for line in _text(args).splitlines() if line.strip()]
    out = "\n".join(lines)
    return _result(out, count=len(lines))


# --- registry ----------------------------------------------------------------

STDLIB_FUNCTIONS = {
    # string
    "upper": fn_upper,
    "lower": fn_lower,
    "trim": fn_trim,
    "title": fn_title,
    "split": fn_split,
    "str_join": fn_join,
    "replace_regex": fn_replace_regex,
    "regex_extract": fn_regex_extract,
    "contains": fn_contains,
    "base64_encode": fn_base64_encode,
    "base64_decode": fn_base64_decode,
    "length": fn_length,
    "prepend_each": fn_prepend_each,
    "append_each": fn_append_each,
    # url
    "url_parse": fn_url_parse,
    "strip_scheme": fn_strip_scheme,
    "apex_domain": fn_apex_domain,
    "url_join": fn_url_join,
    # util
    "uuid": fn_uuid,
    "timestamp": fn_timestamp,
    "env": fn_env,
    # json (jq-lite)
    "json_get": fn_json_get,
    "json_keys": fn_json_keys,
    "json_pretty": fn_json_pretty,
    "to_json": fn_to_json,
    # markdown
    "md_table": fn_md_table,
    "md_heading": fn_md_heading,
    "md_bullets": fn_md_bullets,
}

STDLIB_DOCS = {
    "upper": "Uppercase text.",
    "lower": "Lowercase text.",
    "trim": "Strip surrounding whitespace (or 'chars').",
    "title": "Title-case text.",
    "split": "Split text by 'sep' (or whitespace) into lines.",
    "str_join": "Join lines/items with 'sep'.",
    "replace_regex": "Regex search/replace over text.",
    "regex_extract": "Extract all regex matches as lines.",
    "contains": "Whether text contains 'needle' (true/false).",
    "base64_encode": "Base64-encode text.",
    "base64_decode": "Base64-decode text.",
    "length": "Character length of text.",
    "prepend_each": "Prepend 'prefix' to each line.",
    "append_each": "Append 'suffix' to each line.",
    "url_parse": "Parse a URL into scheme/host/port/path/query.",
    "strip_scheme": "Remove the scheme:// from a URL.",
    "apex_domain": "Registrable apex domain of a host.",
    "url_join": "Resolve 'ref' against 'base'.",
    "uuid": "Generate a random UUID hex.",
    "timestamp": "Current UTC timestamp (ISO / epoch / 'format').",
    "env": "Read an environment variable ('name', 'default').",
    "json_get": "Get a jq-lite path (a.b[0].c) from JSON.",
    "json_keys": "Top-level keys of a JSON object.",
    "json_pretty": "Pretty-print JSON.",
    "to_json": "Wrap a value / lines as JSON.",
    "md_table": "Markdown table from delimited lines (first=header).",
    "md_heading": "Markdown heading ('level' 1-6).",
    "md_bullets": "Markdown bullet list from lines.",
}
