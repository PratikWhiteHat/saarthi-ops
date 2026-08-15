"""Phase-4 bible coverage: match the vulnerability library against evidence.

Two mechanisms, combined:

* A deterministic keyword pass over the run's finding/evidence text. Works
  fully offline and gives a best-effort "likely / review this" signal.
* An optional local-LLM classification pass that reads the same evidence and
  classifies each library entry as confirmed / likely / manual-review /
  not-observed. This is the "AI analyze" step; it never invents findings.

The result is a complete coverage matrix over every catalog entry, so the
artifact honestly records that the whole checklist was evaluated.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from saarthi_ai.knowledge.models import (
    BibleCatalog,
    CoverageResult,
    CoverageStatus,
    EntryCoverage,
)
from saarthi_ai.llm.ollama_client import OllamaUnavailableError, SaarthiOllamaClient
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import AuditEventType
from saarthi_ai.schemas.chat import Message

MAX_CORPUS_CHARS = 6_000
MAX_COVERAGE_TOKENS = 1_400

BIBLE_COVERAGE_SYSTEM_PROMPT = (
    "You are a senior application-security analyst mapping an AUTHORIZED VAPT "
    "run's evidence against a checklist of known web vulnerabilities. For each "
    "checklist item you are asked about, decide, using ONLY the evidence "
    "provided, one of:\n"
    "  confirmed  — the evidence clearly shows this issue is present.\n"
    "  likely     — the evidence strongly suggests it, not yet proven.\n"
    "  manual     — cannot decide from this evidence; a human must test it.\n"
    "Never invent findings, hosts, or data. Only output items you can justify "
    "from the evidence. Output one item per line in the exact format:\n"
    "  <entry_id> | <confirmed|likely|manual> | <one short reason>\n"
    "Do not output items that are not observable in the evidence at all. No "
    "preamble, no markdown, no bullet points."
)


@dataclass
class EvidenceCorpus:
    """The run's evidence rendered as text for matching."""

    target: str = ""
    finding_lines: list[str] = field(default_factory=list)
    signal_lines: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        """Return the joined, bounded corpus text."""

        joined = "\n".join([*self.finding_lines, *self.signal_lines])
        return joined[:MAX_CORPUS_CHARS]

    @property
    def lower(self) -> str:
        return self.text.lower()


def build_evidence_corpus(
    database: SaarthiDatabase,
    orchestration_id: str,
) -> EvidenceCorpus:
    """Collect a run's findings + evidence signals into a text corpus."""

    corpus = EvidenceCorpus()
    try:
        executions = database.list_executions(limit=1_000)
    except Exception:
        return corpus

    for execution in executions:
        meta = execution.metadata or {}
        if meta.get("orchestration_id") != orchestration_id:
            continue
        if not corpus.target and execution.targets:
            corpus.target = str(execution.targets[0])
        phase = str(meta.get("phase_code", "-"))

        for event in database.list_audit_events(execution.execution_id):
            if event.event_type in (
                AuditEventType.FINDING_CREATED,
                AuditEventType.TOOL_OUTPUT,
            ):
                details = event.details or {}
                severity = details.get("severity") or details.get("risk") or ""
                suffix = f" [{severity}]" if severity else ""
                corpus.finding_lines.append(
                    f"[{phase}] {event.message}{suffix}"[:300]
                )

        for evidence in database.list_evidence(execution.execution_id):
            bits = [f"{k}={v}" for k, v in (evidence.metadata or {}).items()]
            if bits:
                corpus.signal_lines.append(
                    f"[{phase}] {evidence.evidence_type.value}: "
                    + ", ".join(bits)[:200]
                )

    return corpus


def classify_deterministic(
    catalog: BibleCatalog,
    corpus: EvidenceCorpus,
) -> CoverageResult:
    """Keyword-match each catalog entry against the evidence corpus.

    Produces a complete coverage matrix: entries with keyword support are
    marked ``likely`` (source ``deterministic``); the rest ``not_observed``.
    """

    haystack = corpus.lower
    coverage: list[EntryCoverage] = []

    for entry in catalog.entries:
        keywords = entry.keywords or []
        hits = [kw for kw in keywords if kw in haystack]
        # 1-keyword titles need the sole keyword; longer titles need >=2 hits
        # so generic single words ("session", "cookie") don't over-match.
        threshold = 1 if len(keywords) <= 1 else 2
        if keywords and len(hits) >= threshold:
            status = CoverageStatus.LIKELY
            justification = "Keyword evidence match: " + ", ".join(hits[:5])
            source = "deterministic"
        else:
            status = CoverageStatus.NOT_OBSERVED
            justification = ""
            source = "deterministic"
        coverage.append(
            EntryCoverage(
                entry_id=entry.entry_id,
                title=entry.title,
                severity=entry.severity,
                status=status,
                source=source,
                justification=justification,
            )
        )

    return CoverageResult(
        target=corpus.target,
        catalog_version=catalog.version,
        catalog_size=len(catalog),
        ai_used=False,
        coverage=coverage,
    )


def _build_coverage_prompt(catalog: BibleCatalog, corpus: EvidenceCorpus) -> str:
    lines = [
        f"Target: {corpus.target or 'unknown'}",
        "",
        "Checklist items (entry_id :: title [rating]):",
    ]
    lines += [
        f"  {entry.entry_id} :: {entry.title} [{entry.severity.value}]"
        for entry in catalog.entries
    ]
    lines += [
        "",
        "Evidence gathered during the run:",
        corpus.text or "  (no notable evidence recorded)",
        "",
        "Classify only the checklist items the evidence supports.",
    ]
    return "\n".join(lines)


def parse_ai_classifications(
    text: str,
    valid_ids: set[str],
) -> dict[str, tuple[CoverageStatus, str]]:
    """Parse ``entry_id | status | reason`` lines into a verdict map."""

    status_map = {
        "confirmed": CoverageStatus.CONFIRMED,
        "likely": CoverageStatus.LIKELY,
        "manual": CoverageStatus.MANUAL_REVIEW,
        "manual_review_required": CoverageStatus.MANUAL_REVIEW,
        "review": CoverageStatus.MANUAL_REVIEW,
    }
    verdicts: dict[str, tuple[CoverageStatus, str]] = {}
    for raw in text.splitlines():
        line = raw.strip().lstrip("-*• ").strip()
        if "|" not in line:
            continue
        parts = [part.strip() for part in line.split("|")]
        if len(parts) < 2:
            continue
        entry_id = parts[0].strip().strip("`")
        if entry_id not in valid_ids:
            continue
        status = status_map.get(parts[1].strip().lower())
        if status is None:
            continue
        reason = parts[2].strip() if len(parts) >= 3 else ""
        verdicts[entry_id] = (status, reason[:500])
    return verdicts


async def classify_with_llm(
    client: SaarthiOllamaClient,
    catalog: BibleCatalog,
    corpus: EvidenceCorpus,
    *,
    num_predict: int = MAX_COVERAGE_TOKENS,
) -> dict[str, tuple[CoverageStatus, str]]:
    """Ask the local model to classify catalog entries against the evidence.

    Raises :class:`OllamaUnavailableError` if the model cannot be reached; the
    caller decides whether to fall back to deterministic-only coverage.
    """

    prompt = _build_coverage_prompt(catalog, corpus)
    content, _thinking = await client.chat(
        [Message(role="user", content=prompt)],
        system_prompt=BIBLE_COVERAGE_SYSTEM_PROMPT,
        num_predict=num_predict,
    )
    valid_ids = {entry.entry_id for entry in catalog.entries}
    return parse_ai_classifications(content, valid_ids)


def apply_ai_classifications(
    result: CoverageResult,
    ai_verdicts: dict[str, tuple[CoverageStatus, str]],
) -> CoverageResult:
    """Overlay AI verdicts onto a deterministic coverage result.

    AI verdicts take precedence for any entry they name; deterministic
    ``likely`` matches are preserved where the model was silent.
    """

    updated: list[EntryCoverage] = []
    for item in result.coverage:
        verdict = ai_verdicts.get(item.entry_id)
        if verdict is not None:
            status, reason = verdict
            updated.append(
                EntryCoverage(
                    entry_id=item.entry_id,
                    title=item.title,
                    severity=item.severity,
                    status=status,
                    source="ai",
                    justification=reason or item.justification,
                    evidence_refs=item.evidence_refs,
                )
            )
        else:
            updated.append(item)

    return CoverageResult(
        target=result.target,
        catalog_version=result.catalog_version,
        catalog_size=result.catalog_size,
        ai_used=True,
        coverage=updated,
    )


__all__ = [
    "BIBLE_COVERAGE_SYSTEM_PROMPT",
    "EvidenceCorpus",
    "OllamaUnavailableError",
    "apply_ai_classifications",
    "build_evidence_corpus",
    "classify_deterministic",
    "classify_with_llm",
    "parse_ai_classifications",
]
