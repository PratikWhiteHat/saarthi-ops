"""Models for the local vulnerability library and Phase-4 coverage results."""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, Field

from saarthi_ai.exploit_confirmation.models import (
    Severity,
    normalize_severity,
    severity_rank,
)

# Short stop-words dropped when deriving match keywords from a title.
_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "based",
        "by",
        "for",
        "from",
        "in",
        "is",
        "its",
        "leads",
        "not",
        "of",
        "on",
        "or",
        "set",
        "the",
        "to",
        "via",
        "with",
    }
)


def slugify(value: str) -> str:
    """Return a stable, filesystem/id-safe slug for a finding title."""

    text = value.strip().lower()
    text = text.replace("&", " and ")
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-") or "entry"


def pick_severity(rating: str) -> Severity:
    """Pick the highest severity named anywhere in a free-form rating string.

    Handles compound ratings like "Low/Medium (based on credentials header)"
    that ``normalize_severity`` alone maps to INFO.
    """

    tokens = re.split(r"[^a-z]+", (rating or "").lower())
    best = Severity.INFO
    for token in tokens:
        candidate = normalize_severity(token)
        if severity_rank(candidate) > severity_rank(best):
            best = candidate
    return best


def derive_keywords(title: str) -> list[str]:
    """Derive lowercase match keywords from a finding title."""

    tokens = re.split(r"[^a-z0-9]+", title.lower())
    seen: dict[str, None] = {}
    for token in tokens:
        if len(token) < 3 or token in _STOPWORDS:
            continue
        seen.setdefault(token, None)
    return list(seen)


class BibleEntry(BaseModel):
    """One curated finding write-up from the vulnerability library."""

    number: int = Field(ge=0)
    entry_id: str = Field(min_length=1, max_length=200)
    title: str = Field(min_length=1, max_length=400)
    rating: str = Field(default="", max_length=120)
    severity: Severity = Severity.INFO
    description: str = ""
    security_risk: str = ""
    recommendation: str = ""
    references: str = ""
    proof_of_concept: str = ""
    keywords: list[str] = Field(default_factory=list)

    @property
    def severity_rank(self) -> int:
        """Return the numeric rank of this entry's severity (higher = worse)."""

        return severity_rank(self.severity)

    @classmethod
    def build(
        cls,
        *,
        number: int,
        title: str,
        rating: str = "",
        description: str = "",
        security_risk: str = "",
        recommendation: str = "",
        references: str = "",
        proof_of_concept: str = "",
    ) -> BibleEntry:
        """Construct an entry, deriving the slug, severity, and keywords."""

        return cls(
            number=number,
            entry_id=slugify(title),
            title=title.strip(),
            rating=rating.strip(),
            severity=pick_severity(rating),
            description=description.strip(),
            security_risk=security_risk.strip(),
            recommendation=recommendation.strip(),
            references=references.strip(),
            proof_of_concept=proof_of_concept.strip(),
            keywords=derive_keywords(title),
        )


class BibleCatalog(BaseModel):
    """A loaded, versioned collection of vulnerability-library entries."""

    version: str = "1"
    source: str = ""
    entries: list[BibleEntry] = Field(default_factory=list)

    def __len__(self) -> int:
        return len(self.entries)

    def get(self, entry_id: str) -> BibleEntry | None:
        """Return the entry with ``entry_id`` if present."""

        for entry in self.entries:
            if entry.entry_id == entry_id:
                return entry
        return None


class CoverageStatus(StrEnum):
    """How a library entry maps onto the current engagement's evidence."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    MANUAL_REVIEW = "manual_review_required"
    NOT_OBSERVED = "not_observed"


class EntryCoverage(BaseModel):
    """The Phase-4 verdict for a single library entry against the evidence."""

    entry_id: str
    title: str
    severity: Severity
    status: CoverageStatus
    source: str = Field(
        default="ai",
        description="How the verdict was reached: 'deterministic' or 'ai'.",
    )
    justification: str = Field(default="", max_length=2_000)
    evidence_refs: list[str] = Field(default_factory=list)


class CoverageResult(BaseModel):
    """Aggregate Phase-4 bible-coverage outcome for one engagement/run."""

    target: str = ""
    catalog_version: str = "1"
    catalog_size: int = 0
    ai_used: bool = False
    coverage: list[EntryCoverage] = Field(default_factory=list)

    @property
    def actionable(self) -> list[EntryCoverage]:
        """Entries worth surfacing (confirmed / likely / manual review)."""

        keep = {
            CoverageStatus.CONFIRMED,
            CoverageStatus.LIKELY,
            CoverageStatus.MANUAL_REVIEW,
        }
        return [item for item in self.coverage if item.status in keep]

    @property
    def status_counts(self) -> dict[str, int]:
        """Return a count of entries per coverage status."""

        counts: dict[str, int] = {}
        for item in self.coverage:
            counts[item.status.value] = counts.get(item.status.value, 0) + 1
        return counts

    def as_dict(self) -> dict:
        """Return a JSON-serializable representation."""

        return self.model_dump(mode="json")


__all__ = [
    "BibleCatalog",
    "BibleEntry",
    "CoverageResult",
    "CoverageStatus",
    "EntryCoverage",
    "derive_keywords",
    "pick_severity",
    "slugify",
]
