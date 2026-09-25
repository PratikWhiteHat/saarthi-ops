"""Import a report template into the local pack, genericizing vendor names.

The source template may hard-code a specific testing company / reviewer. On
import we replace those with neutral placeholder tokens (``TESTINGCOMPANY``,
``TESTINGCOMPANYSHORT``, ``REVIEWERNAME``) so the stored template — and anything
derived from it — is vendor-neutral. The report renderer later fills every
placeholder from configuration.
"""

from __future__ import annotations

from pathlib import Path

from saarthi_ai.knowledge.docx_text import replace_text_everywhere
from saarthi_ai.knowledge.loader import TEMPLATE_FILENAME

# Longest phrases first so a shorter alias never mangles a longer one.
DEFAULT_GENERICIZE: tuple[tuple[str, str], ...] = (
    ("Paramount Computer Systems", "TESTINGCOMPANY"),
    ("Priyank Sharma", "REVIEWERNAME"),
    ("Paramount", "TESTINGCOMPANYSHORT"),
)


class TemplateImportError(RuntimeError):
    """Raised when a report template cannot be imported."""


def import_report_template(
    source: str | Path,
    *,
    base: Path,
    replacements: tuple[tuple[str, str], ...] = DEFAULT_GENERICIZE,
) -> Path:
    """Genericize ``source`` and store it as the pack's report template.

    Returns the stored template path.
    """

    try:
        from docx import Document
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise TemplateImportError(
            "python-docx is required to import a report template."
        ) from exc

    src = Path(source)
    if not src.exists():
        raise TemplateImportError(f"Report template not found: {src}")

    document = Document(str(src))
    replace_text_everywhere(document, dict(replacements))

    base.mkdir(parents=True, exist_ok=True)
    dest = base / TEMPLATE_FILENAME
    document.save(str(dest))
    return dest


__all__ = [
    "DEFAULT_GENERICIZE",
    "TemplateImportError",
    "import_report_template",
]
