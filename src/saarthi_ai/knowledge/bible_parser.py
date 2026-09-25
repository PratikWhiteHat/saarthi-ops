"""Parse a vulnerability-library `.docx` into a structured catalog.

The library is a Word document where each finding is a two-column table keyed by
field name (Vulnerability / Affected URL(s) / Vulnerability Rating / Description /
Security Risk / Recommendation / Reference(s) / Proof of Concept). This parser is
tolerant of field-name and ordering variations so a user can supply their own
library document.
"""

from __future__ import annotations

from pathlib import Path

from saarthi_ai.knowledge.models import BibleCatalog, BibleEntry

# Map a normalized field label (lowercased, trimmed) to a builder kwarg.
_FIELD_ALIASES: dict[str, str] = {
    "vulnerability": "title",
    "vulnerability name": "title",
    "finding": "title",
    "vulnerability rating": "rating",
    "rating": "rating",
    "severity": "rating",
    "risk rating": "rating",
    "description": "description",
    "security risk": "security_risk",
    "risk": "security_risk",
    "impact": "security_risk",
    "recommendation": "recommendation",
    "recommendations": "recommendation",
    "remediation": "recommendation",
    "reference": "references",
    "references": "references",
    "reference(s)": "references",
    "proof of concept": "proof_of_concept",
    "proof of concept (poc)": "proof_of_concept",
    "poc": "proof_of_concept",
}

_TITLE_FIELD = "title"


class BibleParseError(RuntimeError):
    """Raised when a library document cannot be parsed."""


def _normalize_label(label: str) -> str:
    return " ".join(label.strip().lower().split())


def parse_bible_docx(path: str | Path) -> BibleCatalog:
    """Parse ``path`` (a .docx library) into a :class:`BibleCatalog`."""

    try:
        from docx import Document
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise BibleParseError(
            "python-docx is required to import a vulnerability library."
        ) from exc

    source = Path(path)
    if not source.exists():
        raise BibleParseError(f"Library document not found: {source}")

    document = Document(str(source))
    entries: list[BibleEntry] = []
    number = 0

    for table in document.tables:
        fields: dict[str, str] = {}
        for row in table.rows:
            if len(row.cells) < 2:
                continue
            label = _normalize_label(row.cells[0].text)
            kwarg = _FIELD_ALIASES.get(label)
            if kwarg is None:
                continue
            value = row.cells[1].text.strip()
            # First non-empty value wins (guards against merged/label rows).
            if kwarg not in fields or (not fields[kwarg] and value):
                fields[kwarg] = value

        title = fields.get(_TITLE_FIELD, "").strip()
        if not title or title.upper() in {"VULNERABILITY", "AFFECTEDURLS"}:
            # Not a finding table (e.g. a layout/definition table).
            continue

        number += 1
        entries.append(
            BibleEntry.build(
                number=number,
                title=title,
                rating=fields.get("rating", ""),
                description=fields.get("description", ""),
                security_risk=fields.get("security_risk", ""),
                recommendation=fields.get("recommendation", ""),
                references=fields.get("references", ""),
                proof_of_concept=fields.get("proof_of_concept", ""),
            )
        )

    if not entries:
        raise BibleParseError(
            f"No finding tables were recognized in {source}. Expected "
            "two-column tables keyed by 'Vulnerability', 'Vulnerability "
            "Rating', 'Description', etc."
        )

    return BibleCatalog(version="1", source=source.name, entries=entries)


__all__ = ["BibleParseError", "parse_bible_docx"]
