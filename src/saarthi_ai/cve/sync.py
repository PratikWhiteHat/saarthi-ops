"""Explicit, bounded downloads from official CVE intelligence feeds."""

from __future__ import annotations

import os
import re
import time
from datetime import UTC, datetime, timedelta
from typing import NamedTuple

import httpx

from saarthi_ai.cve.catalog import CveCatalog
from saarthi_ai.cve.parser import CveFeedError

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
_SAFE_CPE_PREFIX = re.compile(r"^cpe:2\.3:[aho]:[A-Za-z0-9._~-]+:[A-Za-z0-9._~-]+:")


class OnlineLookupResult(NamedTuple):
    queried_cpes: int
    imported_cves: int
    truncated: bool


def _fetch_json(client: httpx.Client, url: str, params: dict[str, str] | None = None) -> object:
    with client.stream("GET", url, params=params) as response:
        response.raise_for_status()
        payload = bytearray()
        for chunk in response.iter_bytes():
            payload.extend(chunk)
            if len(payload) > MAX_RESPONSE_BYTES:
                raise CveFeedError("Feed page exceeds the 32 MiB response limit.")
    try:
        return httpx.Response(200, content=bytes(payload)).json()
    except ValueError as exc:
        raise CveFeedError("Feed response is not valid JSON.") from exc


def sync_official_feeds(
    catalog: CveCatalog, *, days: int = 7, max_pages: int = 10,
) -> dict[str, int]:
    """Fetch recent NVD changes and the complete KEV list on explicit invocation."""

    if not 1 <= days <= 120 or not 1 <= max_pages <= 100:
        raise ValueError("days must be 1..120 and max_pages must be 1..100")
    now = datetime.now(UTC)
    start = now - timedelta(days=days)
    headers = {"User-Agent": "Saarthi-OPS-CVE-Intelligence/1.0"}
    api_key = os.environ.get("NVD_API_KEY")
    nvd_headers = {**headers, **({"apiKey": api_key} if api_key else {})}
    imported = 0
    with httpx.Client(headers=nvd_headers, timeout=30, follow_redirects=False) as client:
        for page in range(max_pages):
            params = {
                "lastModStartDate": start.isoformat(timespec="milliseconds"),
                "lastModEndDate": now.isoformat(timespec="milliseconds"),
                "resultsPerPage": "2000",
                "startIndex": str(page * 2000),
            }
            document = _fetch_json(client, NVD_URL, params)
            if not isinstance(document, dict):
                raise CveFeedError("NVD returned a non-object response.")
            entries = document.get("vulnerabilities")
            if not isinstance(entries, list):
                raise CveFeedError("NVD response is missing vulnerabilities.")
            total = document.get("totalResults")
            if not isinstance(total, int):
                raise CveFeedError("NVD response is missing totalResults.")
            if isinstance(total, int) and total > max_pages * 2000:
                raise CveFeedError(
                    "NVD results exceed max-pages; increase --max-pages to avoid partial sync."
                )
            if entries:
                imported += catalog.import_nvd(document)
            if (page + 1) * 2000 >= total:
                break
            time.sleep(2 if api_key else 6)
    with httpx.Client(headers=headers, timeout=30, follow_redirects=False) as client:
        kev_document = _fetch_json(client, KEV_URL)
        kev_imported = catalog.import_kev(kev_document)
    return {"nvd": imported, "kev": kev_imported}


def lookup_cpes_online(
    catalog: CveCatalog,
    observed_cpes: list[str],
    *,
    max_cpes: int = 5,
    max_pages_per_cpe: int = 2,
) -> OnlineLookupResult:
    """Query NVD by CPE, import returned CVEs, and never transmit target URLs.

    A versioned CPE uses ``cpeName``. Unknown versions use a broader
    ``virtualMatchString`` and are subsequently filtered by the local matcher.
    """

    if not 1 <= max_cpes <= 20 or not 1 <= max_pages_per_cpe <= 5:
        raise ValueError("Online lookup bounds are invalid.")
    unique = sorted(set(observed_cpes))
    if not unique:
        return OnlineLookupResult(0, 0, False)
    api_key = os.environ.get("NVD_API_KEY")
    headers = {"User-Agent": "Saarthi-OPS-CVE-Intelligence/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    selected = unique[:max_cpes]
    truncated = len(unique) > max_cpes
    imported = 0
    request_count = 0
    queried_cpes = 0
    with httpx.Client(headers=headers, timeout=30, follow_redirects=False) as client:
        for observed_cpe in selected:
            parts = observed_cpe.split(":")
            if (
                len(parts) < 6
                or len(observed_cpe) > 500
                or not _SAFE_CPE_PREFIX.match(observed_cpe)
            ):
                continue
            part, vendor, product, version = parts[2:6]
            if any(value in {"", "*", "-"} for value in (part, vendor, product)):
                continue
            if version in {"*", "-"}:
                query = {"virtualMatchString": ":".join(parts[:5])}
            else:
                query = {"cpeName": observed_cpe}
            queried_cpes += 1
            for page in range(max_pages_per_cpe):
                if request_count:
                    time.sleep(2 if api_key else 6)
                params = {
                    **query,
                    "resultsPerPage": "1000",
                    "startIndex": str(page * 1000),
                }
                document = _fetch_json(client, NVD_URL, params)
                request_count += 1
                if not isinstance(document, dict):
                    raise CveFeedError("NVD CPE lookup returned a non-object response.")
                entries = document.get("vulnerabilities")
                total = document.get("totalResults")
                if not isinstance(entries, list) or not isinstance(total, int):
                    raise CveFeedError("NVD CPE lookup response is incomplete.")
                if entries:
                    imported += catalog.import_nvd(document, feed="nvd-cpe")
                if (page + 1) * 1000 >= total:
                    break
                if page + 1 == max_pages_per_cpe:
                    truncated = True
    return OnlineLookupResult(queried_cpes, imported, truncated)
