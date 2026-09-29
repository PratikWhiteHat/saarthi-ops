"""Shared request construction for TEST and the oracle.

Builds a *valid* request for a surface — every sibling field filled with its
observed/default value — with one parameter set to the payload. Keeping this in
one place means the tester and the oracle send byte-identical requests, so a
differential the oracle measures is caused only by the payload.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

from saarthi2.vulnengine.http import HttpSender, SentResponse
from saarthi2.vulnengine.models import InputSurface


def strip_query(url: str) -> str:
    """Drop the query string — parameters are supplied explicitly as params/data.

    A URL-query surface (e.g. ``/fi/?page=include.php``) keeps its query in
    ``surface.url`` for identity; sending with ``params=`` too would duplicate it.
    """

    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def build_base(surface: InputSurface) -> dict[str, str]:
    """Fill every field of the surface with a benign default / observed value."""

    base = {p: "1" for p in surface.params}
    base.update({k: str(v) for k, v in surface.example_values.items()})
    return base


async def send_payload(
    sender: HttpSender,
    surface: InputSurface,
    param: str | None,
    value: str,
    *,
    allow_redirects: bool = False,
    overrides: dict[str, Any] | None = None,
) -> SentResponse:
    """Send ``value`` in ``param`` (others at their defaults)."""

    base = build_base(surface)
    if overrides:
        base.update({k: str(v) for k, v in overrides.items()})
    if param is not None:
        base[param] = value
    target = strip_query(surface.url)
    if surface.method.upper() == "POST":
        return await sender.send("POST", target, data=base, allow_redirects=allow_redirects)
    return await sender.send("GET", target, params=base, allow_redirects=allow_redirects)
