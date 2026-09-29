"""The low-level sender behind the typed ``http_send`` primitive.

Owns two things the shared ``deps.http_request`` can't give the engine: precise
per-request timing (for time-based oracles) and explicit redirect control (for
the open-redirect oracle, which must SEE the ``Location`` without following it).
It carries the authenticated session (cookie jar) so every probe is sent as the
logged-in user. Tests inject a fake sender with the same ``send`` signature.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SentResponse:
    """A normalized response with the fields the engine reasons over."""

    status_code: int
    text: str
    headers: dict[str, str] = field(default_factory=dict)
    elapsed_ms: int = 0
    url: str = ""

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


class HttpSender:
    """httpx-backed sender bound to one authenticated session."""

    def __init__(
        self,
        *,
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: int = 20,
    ) -> None:
        self._cookies = dict(cookies or {})
        self._headers = dict(headers or {})
        self._timeout = timeout

    async def send(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        data: Any = None,
        headers: dict[str, str] | None = None,
        allow_redirects: bool = False,
    ) -> SentResponse:
        import httpx

        merged = {**self._headers, **(headers or {})}
        started = time.monotonic()
        async with httpx.AsyncClient(
            follow_redirects=allow_redirects,
            verify=False,
            timeout=self._timeout,
            cookies=self._cookies or None,
        ) as client:
            resp = await client.request(
                method.upper(), url, params=params, data=data, headers=merged or None
            )
            elapsed_ms = int((time.monotonic() - started) * 1000)
            return SentResponse(
                status_code=resp.status_code,
                text=resp.text,
                headers={k.lower(): v for k, v in resp.headers.items()},
                elapsed_ms=elapsed_ms,
                url=str(resp.url),
            )
