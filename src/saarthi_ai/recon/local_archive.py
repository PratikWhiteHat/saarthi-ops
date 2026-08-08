"""Local page-snapshot archiver — LOCAL-FIRST alternative to public archiving.

Captures the in-scope pages the assessment already touches and stores them
LOCALLY under the run's evidence directory (HTML/body + metadata + hashes).
This is the "archive the target" value — a durable, timestamped record of what
was tested — WITHOUT publishing anything to third-party services. Nothing
leaves the box; it only reads pages that recon already discovered.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import httpx

DEFAULT_LIMIT = 15
DEFAULT_TIMEOUT = 15.0
_MAX_PAGE_BYTES = 2_000_000
_USER_AGENT = "saarthi-recon (authorized local page archive)"


@dataclass(frozen=True)
class LocalArchiveResult:
    """Summary of a local page-snapshot capture."""

    domain: str
    archived: int
    attempted: int
    index_path: Path | None
    entries: list[dict] = field(default_factory=list)


def _host_of(url: str) -> str:
    return urlsplit(url).netloc.split("@")[-1].split(":")[0].lower()


def _in_scope(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def capture_local_archive(
    urls: list[str],
    out_dir: Path,
    *,
    domain: str,
    limit: int = DEFAULT_LIMIT,
    timeout: float = DEFAULT_TIMEOUT,
    client: httpx.Client | None = None,
) -> LocalArchiveResult:
    """Fetch in-scope URLs and store each page locally under ``out_dir``.

    Read-only GETs, de-duplicated and filtered to the target domain (or its
    subdomains). Bodies are truncated to a bounded size. Per-URL failures are
    recorded and skipped — the capture never raises.
    """

    domain = domain.strip().lower().rstrip(".")
    seen: set[str] = set()
    scoped: list[str] = []
    for url in urls:
        host = _host_of(url)
        if not host or not _in_scope(host, domain) or url in seen:
            continue
        seen.add(url)
        scoped.append(url)
        if len(scoped) >= limit:
            break

    if not scoped:
        return LocalArchiveResult(
            domain=domain, archived=0, attempted=0, index_path=None
        )

    pages_dir = out_dir / "pages"
    pages_dir.mkdir(parents=True, exist_ok=True)

    owns_client = client is None
    if client is None:
        client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": _USER_AGENT},
        )

    entries: list[dict] = []
    try:
        for url in scoped:
            try:
                response = client.get(url)
                body = response.content[:_MAX_PAGE_BYTES]
                sha = hashlib.sha256(response.content).hexdigest()
                filename = f"{sha[:16]}.bin"
                (pages_dir / filename).write_bytes(body)
                entries.append(
                    {
                        "url": url,
                        "status_code": response.status_code,
                        "content_type": response.headers.get(
                            "content-type", ""
                        )[:120],
                        "sha256": sha,
                        "size_bytes": len(response.content),
                        "saved_as": f"pages/{filename}",
                    }
                )
            except (httpx.HTTPError, OSError) as exc:
                entries.append({"url": url, "error": str(exc)[:160]})
    finally:
        if owns_client:
            client.close()

    archived = sum(1 for entry in entries if "sha256" in entry)
    index_path = out_dir / "archive-index.json"
    index_path.write_text(
        json.dumps(
            {
                "domain": domain,
                "archived": archived,
                "attempted": len(scoped),
                "entries": entries,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return LocalArchiveResult(
        domain=domain,
        archived=archived,
        attempted=len(scoped),
        index_path=index_path,
        entries=entries,
    )


__all__ = [
    "DEFAULT_LIMIT",
    "LocalArchiveResult",
    "capture_local_archive",
]
