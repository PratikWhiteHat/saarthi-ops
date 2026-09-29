"""Deterministic ``interesting_signals`` detection — grounded, not guessed.

We classify input surfaces against evidence found in CODE/responses so the model
comprehends the app against real signals rather than inventing them. Everything
here is pure (no network); the crawler supplies bodies and the active reflection
probe. Signal vocabulary (also used by the feature->vuln matrix ``requires``):

    reflects_input     a submitted value is echoed back in the response body
    numeric_id         the param value is a bare integer (sequential-id shape)
    url_like_value     the value looks like a URL, or the name is a redirect param
    file_like_value    the value/name looks like a file path or include target
    command_like       the name looks like a shell/host/command sink
    accepts_svg_html   an upload field accepts svg/html
    sql_error_leak     the response leaked a SQL error (interesting, app-level)
    stack_leak         the response leaked a stack trace / framework debug page
"""

from __future__ import annotations

import re

from saarthi2.vulnengine.models import SurfaceType

# --- param-name heuristics ----------------------------------------------------
_NUMERIC_ID_NAMES = frozenset(
    {
        "id", "uid", "pid", "user_id", "userid", "item", "item_id", "itemid",
        "order", "order_id", "orderid", "doc_id", "num", "no", "cat", "category_id",
        "product_id", "account", "account_id", "invoice", "record", "row",
    }
)
_URL_PARAM_NAMES = frozenset(
    {
        "url", "uri", "redirect", "redirect_url", "redir", "next", "return",
        "returnurl", "return_to", "returnto", "dest", "destination", "continue",
        "link", "callback", "goto", "out", "forward", "site", "u",
    }
)
_REDIRECT_NAMES = frozenset(
    {
        "redirect", "redirect_url", "redir", "next", "return", "returnurl",
        "return_to", "returnto", "dest", "destination", "continue", "goto",
        "out", "forward", "url",
    }
)
_FILE_PARAM_NAMES = frozenset(
    {
        "file", "filename", "page", "path", "template", "tpl", "include", "inc",
        "doc", "document", "load", "read", "dir", "folder", "download", "conf",
    }
)
_COMMAND_PARAM_NAMES = frozenset(
    {"ip", "host", "cmd", "command", "ping", "domain", "dns", "exec", "addr"}
)
_SEARCH_PARAM_NAMES = frozenset(
    {"q", "s", "search", "query", "keyword", "keywords", "term", "find", "name"}
)

_URL_VALUE_RE = re.compile(r"^\s*(https?:)?//", re.IGNORECASE)
_FILE_VALUE_RE = re.compile(r"[\\/]|\.[A-Za-z0-9]{1,5}$")
_SQL_ERROR_RE = re.compile(
    r"(SQL syntax|mysql_fetch|mysqli?|ORA-\d{5}|PostgreSQL.*ERROR|SQLite3?::|"
    r"ODBC SQL|Unclosed quotation mark|quoted string not properly terminated|"
    r"You have an error in your SQL)",
    re.IGNORECASE,
)
_STACK_RE = re.compile(
    r"(Traceback \(most recent call last\)|Exception in thread|"
    r"at [\w.$]+\([\w.]+\.java:\d+\)|Warning: .*on line \d+|"
    r"Fatal error:|Whitelabel Error Page|django\.|werkzeug)",
    re.IGNORECASE,
)


def _looks_numeric(value: str) -> bool:
    return value.strip().isdigit()


def _looks_url(value: str) -> bool:
    return bool(_URL_VALUE_RE.match(value or ""))


def _looks_path(value: str) -> bool:
    return bool(_FILE_VALUE_RE.search(value or ""))


def param_signals(name: str, value: str = "") -> set[str]:
    """Grounded signals for one parameter, from its name and observed value."""

    lname = (name or "").strip().lower()
    signals: set[str] = set()

    if _looks_numeric(value) or (lname in _NUMERIC_ID_NAMES and value):
        signals.add("numeric_id")
    if _looks_url(value) or lname in _URL_PARAM_NAMES:
        signals.add("url_like_value")
    if lname in _REDIRECT_NAMES or _looks_url(value):
        signals.add("redirect_param")
    if _looks_path(value) or lname in _FILE_PARAM_NAMES:
        signals.add("file_like_value")
    if lname in _COMMAND_PARAM_NAMES:
        signals.add("command_like")
    if lname in _SEARCH_PARAM_NAMES:
        signals.add("search_param")
    return signals


def detects_reflection(value: str, body: str) -> bool:
    """Whether a distinctive submitted value appears verbatim in the response."""

    value = (value or "").strip()
    # Only trust a reflection for a reasonably distinctive token to avoid matching
    # incidental substrings (a lone digit reflects everywhere).
    return len(value) >= 4 and value in (body or "")


def detect_sql_error(body: str) -> bool:
    return bool(_SQL_ERROR_RE.search(body or ""))


def detect_stack_leak(body: str) -> bool:
    return bool(_STACK_RE.search(body or ""))


def classify_surface(
    *,
    params: list[str],
    signals: set[str],
    has_password_field: bool = False,
    has_file_field: bool = False,
) -> SurfaceType:
    """Pick the most specific *primary* type for display/structural rules.

    Routing for signal rules is signal-driven (see the planner); this label is
    for the App Model, the UI, and the structural (``requires: []``) matrix rows.
    """

    if has_password_field:
        return SurfaceType.AUTH_FIELD
    if has_file_field:
        return SurfaceType.FILE_UPLOAD
    if "redirect_param" in signals:
        return SurfaceType.REDIRECT
    if "url_like_value" in signals:
        return SurfaceType.URL_PARAM
    if "search_param" in signals or "reflects_input" in signals:
        return SurfaceType.SEARCH
    if "numeric_id" in signals:
        return SurfaceType.OBJECT_REF
    return SurfaceType.GENERIC
