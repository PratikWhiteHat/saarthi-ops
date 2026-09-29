"""Authenticated crawl — discover the real input surface to comprehend.

Bounded, same-host BFS over the app as the logged-in user. Extracts forms
(action/method/fields, and whether they carry a password or file input) and
links (with their query parameters) using only the stdlib HTML parser — no bs4.
Its output (pages + raw surfaces) is what COMPREHEND turns into the App Model.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from saarthi2.vulnengine.http import HttpSender


@dataclass
class RawSurface:
    """One input surface discovered in the crawl (pre-classification)."""

    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    example_values: dict[str, str] = field(default_factory=dict)
    has_password: bool = False
    has_file: bool = False
    accepts: list[str] = field(default_factory=list)

    def dedup_key(self) -> tuple[str, str, tuple[str, ...]]:
        parts = urlsplit(self.url)
        base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        return (self.method.upper(), base, tuple(sorted(self.params)))


@dataclass
class CrawlPage:
    url: str
    status: int
    body: str
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class CrawlResult:
    pages: list[CrawlPage] = field(default_factory=list)
    surfaces: list[RawSurface] = field(default_factory=list)

    def title_hints(self) -> str:
        """A compact digest of what was crawled, for the App Model prompt."""

        lines = [f"{p.status} {p.url}" for p in self.pages]
        return "\n".join(lines)


class _PageParser(HTMLParser):
    """Extract links and forms (with their fields) from one HTML page."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[RawSurface] = []
        self._cur: RawSurface | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.append(urljoin(self.base_url, a["href"]))
        elif tag == "form":
            action = urljoin(self.base_url, a.get("action") or self.base_url)
            method = (a.get("method") or "GET").upper()
            self._cur = RawSurface(url=action, method="POST" if method == "POST" else "GET")
            if "multipart/form-data" in (a.get("enctype") or "").lower():
                self._cur.has_file = True
        elif tag in ("input", "select", "textarea") and self._cur is not None:
            name = a.get("name")
            itype = (a.get("type") or "text").lower()
            if itype == "password":
                self._cur.has_password = True
            if itype == "file":
                self._cur.has_file = True
                if a.get("accept"):
                    self._cur.accepts.append(a["accept"].lower())
            if name and itype not in ("submit", "button", "reset", "image"):
                if name not in self._cur.params:
                    self._cur.params.append(name)
                if a.get("value"):
                    self._cur.example_values[name] = a["value"]
            elif name and itype == "submit":
                # Keep submit names (DVWA needs Submit=Submit to run the query).
                if name not in self._cur.params:
                    self._cur.params.append(name)
                self._cur.example_values[name] = a.get("value") or "Submit"

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def _same_host(url: str, host: str) -> bool:
    return (urlsplit(url).hostname or "").lower() == host.lower()


def _surface_from_url(url: str) -> RawSurface | None:
    """A GET surface from a link that carries query parameters."""

    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    if not query:
        return None
    params = [k for k, _ in query]
    return RawSurface(
        url=url,
        method="GET",
        params=params,
        example_values={k: v for k, v in query},
    )


async def crawl_site(
    base_url: str,
    sender: HttpSender,
    *,
    max_pages: int = 40,
    max_depth: int = 2,
) -> CrawlResult:
    """BFS-crawl ``base_url`` as the current session; collect pages + surfaces."""

    host = (urlsplit(base_url).hostname or "").lower()
    seen_urls: set[str] = set()
    seen_surfaces: set[tuple[str, str, tuple[str, ...]]] = set()
    result = CrawlResult()
    queue: deque[tuple[str, int]] = deque([(base_url, 0)])

    def add_surface(surface: RawSurface) -> None:
        key = surface.dedup_key()
        if surface.params and key not in seen_surfaces:
            seen_surfaces.add(key)
            result.surfaces.append(surface)

    while queue and len(result.pages) < max_pages:
        url, depth = queue.popleft()
        norm = url.split("#", 1)[0]
        if norm in seen_urls or not _same_host(norm, host):
            continue
        seen_urls.add(norm)

        try:
            resp = await sender.send("GET", norm, allow_redirects=True)
        except Exception:
            continue
        result.pages.append(
            CrawlPage(url=norm, status=resp.status_code, body=resp.text, headers=resp.headers)
        )

        # A surface from this URL's own query string (e.g. ?page=include.php).
        own = _surface_from_url(norm)
        if own is not None:
            add_surface(own)

        ctype = resp.header("content-type")
        if "html" not in ctype.lower() and ctype:
            continue
        parser = _PageParser(norm)
        try:
            parser.feed(resp.text)
        except Exception:
            continue
        for form in parser.forms:
            add_surface(form)
        for link in parser.links:
            link = link.split("#", 1)[0]
            if not _same_host(link, host):
                continue
            surf = _surface_from_url(link)
            if surf is not None:
                add_surface(surf)
            if link not in seen_urls and depth < max_depth:
                queue.append((link, depth + 1))

    return result
