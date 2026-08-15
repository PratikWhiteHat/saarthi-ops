"""Load the local knowledge pack (vulnerability catalog + report template)."""

from __future__ import annotations

import json
from pathlib import Path

from saarthi_ai.config import knowledge_dir
from saarthi_ai.knowledge.models import BibleCatalog

BIBLE_FILENAME = "wapt_bible.json"
TEMPLATE_FILENAME = "report_template.docx"


class BibleNotAvailableError(RuntimeError):
    """Raised when no vulnerability catalog is installed in the pack."""


def bible_catalog_path(base: Path | None = None) -> Path:
    """Return the on-disk path of the parsed vulnerability catalog."""

    root = base if base is not None else knowledge_dir()
    return root / BIBLE_FILENAME


def report_template_path(base: Path | None = None) -> Path | None:
    """Return the report-template path if it exists in the pack, else None."""

    root = base if base is not None else knowledge_dir()
    candidate = root / TEMPLATE_FILENAME
    return candidate if candidate.exists() else None


def bible_available(base: Path | None = None) -> bool:
    """Return whether a parsed vulnerability catalog is installed."""

    return bible_catalog_path(base).exists()


def load_bible_catalog(base: Path | None = None) -> BibleCatalog:
    """Load and validate the parsed vulnerability catalog from the pack.

    Raises :class:`BibleNotAvailableError` when no catalog is installed so
    callers can degrade gracefully (skip the phase) rather than crash.
    """

    path = bible_catalog_path(base)
    if not path.exists():
        raise BibleNotAvailableError(
            f"No vulnerability catalog found at {path}. Import one with "
            "`saarthi knowledge import-bible <library.docx>`."
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BibleNotAvailableError(
            f"Vulnerability catalog at {path} could not be read: {exc}"
        ) from exc
    return BibleCatalog.model_validate(payload)


def save_bible_catalog(catalog: BibleCatalog, base: Path | None = None) -> Path:
    """Persist ``catalog`` to the pack as JSON and return its path."""

    root = base if base is not None else knowledge_dir()
    root.mkdir(parents=True, exist_ok=True)
    path = root / BIBLE_FILENAME
    path.write_text(
        json.dumps(catalog.model_dump(mode="json"), indent=2),
        encoding="utf-8",
    )
    return path


__all__ = [
    "BIBLE_FILENAME",
    "TEMPLATE_FILENAME",
    "BibleNotAvailableError",
    "bible_available",
    "bible_catalog_path",
    "load_bible_catalog",
    "report_template_path",
    "save_bible_catalog",
]
