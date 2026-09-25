"""Small helpers for text substitution inside a python-docx document.

Word splits a paragraph's text across several runs, so a naive
``run.text.replace(...)`` misses phrases that straddle runs. These helpers do a
run-level pass first (preserving formatting) and fall back to a
paragraph-level rewrite when a phrase spans runs.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any


def iter_all_paragraphs(container: Any) -> Iterator[Any]:
    """Yield every paragraph in a document/cell, recursing into tables."""

    yield from getattr(container, "paragraphs", [])
    for table in getattr(container, "tables", []):
        for row in table.rows:
            for cell in row.cells:
                yield from iter_all_paragraphs(cell)


def replace_in_paragraph(paragraph: Any, mapping: Mapping[str, str]) -> None:
    """Apply ``mapping`` substitutions within a single paragraph."""

    runs = paragraph.runs
    if not runs:
        return

    # Fast path: replace within individual runs (keeps per-run formatting).
    changed_run = False
    for run in runs:
        text = run.text
        if not text:
            continue
        new_text = text
        for old, new in mapping.items():
            if old and old in new_text:
                new_text = new_text.replace(old, new)
        if new_text != text:
            run.text = new_text
            changed_run = True

    # Fallback: any target still spanning multiple runs -> paragraph rewrite.
    full = paragraph.text
    if any(old and old in full for old in mapping):
        rewritten = full
        for old, new in mapping.items():
            if old:
                rewritten = rewritten.replace(old, new)
        if rewritten != full:
            runs[0].text = rewritten
            for run in runs[1:]:
                run.text = ""
            return

    _ = changed_run


def replace_text_everywhere(document: Any, mapping: Mapping[str, str]) -> None:
    """Apply ``mapping`` substitutions across the whole document.

    Covers the body, all tables (recursively), and every section's header and
    footer.
    """

    active = {old: new for old, new in mapping.items() if old}
    if not active:
        return

    for paragraph in iter_all_paragraphs(document):
        replace_in_paragraph(paragraph, active)

    for section in getattr(document, "sections", []):
        for part in (section.header, section.footer):
            if part is None:
                continue
            for paragraph in iter_all_paragraphs(part):
                replace_in_paragraph(paragraph, active)


__all__ = [
    "iter_all_paragraphs",
    "replace_in_paragraph",
    "replace_text_everywhere",
]
