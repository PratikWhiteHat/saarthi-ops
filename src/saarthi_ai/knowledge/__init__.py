"""Local knowledge pack: a vendor-neutral vulnerability library + report template.

The library ("WAPT Bible") is a catalog of curated finding write-ups — each with
a canonical description, security risk, recommendation, reference, and
proof-of-concept — that Phase 4 matches against gathered evidence and that the
Phase 8A report renders as detailed findings. The catalog and the report
template live in a local, git-ignored knowledge directory (see
``config.knowledge_dir``); nothing proprietary ships in the repository.
"""

from saarthi_ai.knowledge.loader import (
    BibleNotAvailableError,
    load_bible_catalog,
    report_template_path,
)
from saarthi_ai.knowledge.models import (
    BibleCatalog,
    BibleEntry,
    CoverageResult,
    CoverageStatus,
    EntryCoverage,
)

__all__ = [
    "BibleCatalog",
    "BibleEntry",
    "BibleNotAvailableError",
    "CoverageResult",
    "CoverageStatus",
    "EntryCoverage",
    "load_bible_catalog",
    "report_template_path",
]
