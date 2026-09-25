"""Operator-facing CVE catalog commands; no scans or exploit execution."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import httpx
import typer
from rich.console import Console
from rich.table import Table

from saarthi_ai.cve.catalog import CveCatalog
from saarthi_ai.cve.matcher import match_cpe
from saarthi_ai.cve.parser import CveFeedError
from saarthi_ai.cve.sync import sync_official_feeds

app = typer.Typer(no_args_is_help=True, help="Local NVD/CISA KEV intelligence and CPE matching.")
console = Console()


def _document(path: Path) -> object:
    if not path.is_file():
        raise typer.BadParameter("Expected a regular JSON file.")
    if path.stat().st_size > 100 * 1024 * 1024:
        raise typer.BadParameter("JSON file exceeds the 100 MiB limit.")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise typer.BadParameter("File is not valid UTF-8 JSON.") from exc


@app.command("import-nvd")
def import_nvd(path: Annotated[Path, typer.Argument(help="NVD API 2.0 JSON file")]) -> None:
    """Import a previously downloaded NVD JSON page."""

    try:
        count = CveCatalog().import_nvd(_document(path))
    except CveFeedError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"Imported {count} NVD CVE records into the local catalog.")


@app.command("import-kev")
def import_kev(path: Annotated[Path, typer.Argument(help="CISA KEV JSON file")]) -> None:
    """Replace the local KEV catalog from an official full feed file."""

    try:
        count = CveCatalog().import_kev(_document(path))
    except CveFeedError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"Imported {count} CISA KEV records into the local catalog.")


@app.command()
def sync(
    days: Annotated[int, typer.Option(help="NVD modified-date lookback, 1..120")] = 7,
    max_pages: Annotated[int, typer.Option(help="Maximum NVD pages, 1..100")] = 10,
) -> None:
    """Explicitly refresh from official NVD and CISA endpoints."""

    try:
        result = sync_official_feeds(CveCatalog(), days=days, max_pages=max_pages)
    except (ValueError, CveFeedError, httpx.HTTPError) as exc:
        # Network failures should be concise in the operator CLI.
        console.print(f"CVE feed sync failed: {exc}", style="red")
        raise typer.Exit(1) from exc
    console.print(f"Imported NVD: {result['nvd']}; CISA KEV: {result['kev']}")


@app.command()
def status() -> None:
    """Show local catalog counts and feed provenance."""

    console.print_json(data=CveCatalog().stats())


@app.command()
def match(
    cpe: Annotated[str, typer.Option(help="Observed CPE 2.3 product string")],
    limit: Annotated[int, typer.Option(help="Maximum results, 1..500")] = 50,
) -> None:
    """Rank CVE candidates; product matching is not vulnerability confirmation."""

    if not 1 <= limit <= 500:
        raise typer.BadParameter("limit must be 1..500")
    try:
        candidates = match_cpe(CveCatalog(), cpe, limit=limit)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    table = Table(title="CVE candidates — review applicability before reporting")
    for column in ("CVE", "Priority", "CVSS", "KEV", "Applicability", "Reason"):
        table.add_column(column)
    for item in candidates:
        table.add_row(
            item.cve.cve_id, str(item.priority_score),
            str(item.cve.cvss_score or "—"), "yes" if item.cve.exploited_in_wild else "no",
            item.applicability, item.reason,
        )
    console.print(table)
    console.print(f"{len(candidates)} candidate(s). No vulnerability was confirmed.")
