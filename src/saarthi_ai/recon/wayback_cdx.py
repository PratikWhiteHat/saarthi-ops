"""Passive historical-URL intelligence via the Wayback Machine CDX API.

Read-only Phase 3D "URL Intelligence" source: a single GET to web.archive.org's
public CDX index lists URLs already archived for the in-scope domain. This
PULLS known URLs in for endpoint discovery — it publishes nothing and sends no
requests to the target itself (same posture as the crt.sh certificate-
transparency source the platform already uses).
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

CDX_ENDPOINT = "http://web.archive.org/cdx/search/cdx"
DEFAULT_LIMIT = 500
DEFAULT_TIMEOUT = 20.0
_USER_AGENT = "saarthi-recon (authorized passive URL intelligence)"


class WaybackCdxError(RuntimeError):
    """Raised when the Wayback CDX query cannot be completed."""


@dataclass(frozen=True)
class WaybackCdxResult:
    """De-duplicated, in-scope historical URLs for a domain."""

    domain: str
    urls: tuple[str, ...]
    total: int
    truncated: bool


def _host_of(url: str) -> str:
    netloc = urlsplit(url).netloc
    return netloc.split("@")[-1].split(":")[0].lower()


def _in_scope(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def collect_wayback_urls(
    domain: str,
    *,
    limit: int = DEFAULT_LIMIT,
    timeout: float = DEFAULT_TIMEOUT,
    include_subdomains: bool = True,
    client: httpx.Client | None = None,
) -> WaybackCdxResult:
    """Return historical URLs archived for ``domain`` (and optional subdomains).

    Read-only. Results are de-duplicated and filtered to the target domain (or
    its subdomains) so nothing out-of-scope leaks in.
    """

    domain = domain.strip().lower().rstrip(".")
    if not domain:
        raise WaybackCdxError("A target domain is required.")

    params = {
        "url": domain,
        "matchType": "domain" if include_subdomains else "host",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        # Ask for one more than the cap so we can flag truncation.
        "limit": str(max(1, limit) + 1),
    }

    owns_client = client is None
    if client is None:
        client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": _USER_AGENT},
        )
    try:
        response = client.get(CDX_ENDPOINT, params=params)
        response.raise_for_status()
        payload = response.json()
    except httpx.HTTPError as exc:
        raise WaybackCdxError(f"Wayback CDX request failed: {exc}") from exc
    except ValueError as exc:  # invalid / empty JSON
        raise WaybackCdxError(f"Wayback CDX returned invalid JSON: {exc}") from exc
    finally:
        if owns_client:
            client.close()

    if not isinstance(payload, list):
        raise WaybackCdxError("Unexpected Wayback CDX response shape.")

    # First row is the field header (["original"]); the rest are URL rows.
    rows = payload[1:] if payload else []
    seen: set[str] = set()
    urls: list[str] = []
    for row in rows:
        candidate = row[0] if isinstance(row, list) and row else None
        if not isinstance(candidate, str) or not candidate:
            continue
        host = _host_of(candidate)
        if not host or not _in_scope(host, domain):
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        urls.append(candidate)

    truncated = len(urls) > limit
    return WaybackCdxResult(
        domain=domain,
        urls=tuple(urls[:limit]),
        total=min(len(urls), limit),
        truncated=truncated,
    )


__all__ = [
    "WaybackCdxError",
    "WaybackCdxResult",
    "collect_wayback_urls",
]
