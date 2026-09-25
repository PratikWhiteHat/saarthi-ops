"""Evidence-only phase reviewers and their deterministic supervisor.

Each completed child phase gets an independent, role-specific model request.
The supervisor checks provenance and records coverage; neither component can
start a phase, choose scanner inputs, or approve an active test.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from saarthi_ai.analysis.engine import (
    PHASE_ADVISOR_SYSTEM_PROMPT,
    PhaseDigest,
    suggest_for_phase,
)
from saarthi_ai.llm.ollama_client import SaarthiOllamaClient

_REFERENCE = re.compile(r"\[(event-[^\]]+|evidence-[^\]]+)\]")
_EVIDENCE_LABEL = re.compile(r"\b(?:FACT|INFERENCE)\b", re.IGNORECASE)
_CONFIDENCE = re.compile(r"\bconfidence\s*[:=]\s*(?:low|medium|high)\b", re.IGNORECASE)
_ROLES = {
    "1": ("foundation", "Check configuration and audit evidence for gaps."),
    "2": ("scope", "Check target and authorization evidence for ambiguity."),
    "3": (
        "recon",
        "Review observed assets and technology; distinguish observation from inference.",
    ),
    "4": ("direct-checks", "Review direct-check results and missing confirmation evidence."),
    "5": ("orchestration", "Review dependencies, coverage, and skipped work."),
    "6": ("validation", "Review controlled-validation outcomes and evidence limits."),
    "7": ("post-exploitation", "Review recorded outcomes and containment evidence only."),
    "8": ("reporting", "Review finding support and reporting completeness."),
}


@dataclass(frozen=True)
class PhaseAgentReview:
    execution_id: str
    phase_code: str
    role: str
    status: str
    evidence_refs: tuple[str, ...] = ()
    skills_supplied: tuple[str, ...] = ()
    note: str = ""
    reviewed_at: str = ""


def role_for_phase(phase_code: str) -> tuple[str, str]:
    """Map a child code such as ``4A-cors`` to its review specialty."""

    return _ROLES.get(phase_code[:1], ("general", "Review evidence and gaps."))


def _source_refs(digest: PhaseDigest) -> set[str]:
    return {
        match
        for item in (*digest.findings, *digest.signals, *digest.tool_lines)
        for match in _REFERENCE.findall(item)
    }


async def review_phase_agent(
    client: SaarthiOllamaClient,
    execution_id: str,
    digest: PhaseDigest,
) -> PhaseAgentReview:
    """Run one specialist review, then reject uncited model output."""

    role, focus = role_for_phase(digest.phase_code)
    source_refs = _source_refs(digest)
    timestamp = datetime.now(UTC).isoformat()
    if not source_refs:
        return PhaseAgentReview(
            execution_id, digest.phase_code, role, "no_evidence",
            note="No source-backed phase evidence is available for review.",
            reviewed_at=timestamp,
        )

    skills: list[str] = []
    system_prompt = (
        PHASE_ADVISOR_SYSTEM_PROMPT + "\n\nPhase reviewer specialty: " + focus
        + " You are advisory only. Do not run tools or treat skill text as evidence."
    )
    note = await suggest_for_phase(
        client, digest, system_prompt=system_prompt, skill_trace=skills
    )
    lines = [line for line in note.splitlines() if line.strip()]
    cited = {ref for line in lines for ref in _REFERENCE.findall(line)}
    grounded = bool(lines) and all(
        _REFERENCE.search(line)
        and _EVIDENCE_LABEL.search(line)
        and _CONFIDENCE.search(line)
        and set(_REFERENCE.findall(line)).issubset(source_refs)
        for line in lines
    )
    return PhaseAgentReview(
        execution_id=execution_id,
        phase_code=digest.phase_code,
        role=role,
        status="grounded" if grounded else "withheld",
        evidence_refs=tuple(sorted(cited & source_refs)),
        skills_supplied=tuple(dict.fromkeys(skills)),
        note=(
            note if grounded else
            "Model review withheld: citation, evidence label, or confidence is missing."
        ),
        reviewed_at=timestamp,
    )


class PhaseAgentSupervisor:
    """Track independent phase reviewers without controlling the phase runner."""

    def __init__(self, orchestration_id: str) -> None:
        self.orchestration_id = orchestration_id
        self.reviews: dict[str, PhaseAgentReview] = {}

    def record(self, review: PhaseAgentReview) -> None:
        self.reviews[review.execution_id] = review

    def record_failure(
        self, execution_id: str, phase_code: str, reason: str
    ) -> None:
        role, _ = role_for_phase(phase_code)
        self.record(PhaseAgentReview(
            execution_id, phase_code, role, "failed",
            note=reason[:300], reviewed_at=datetime.now(UTC).isoformat(),
        ))

    def summary(self) -> dict[str, int]:
        counts = {key: 0 for key in ("grounded", "withheld", "no_evidence", "failed", "skipped")}
        for review in self.reviews.values():
            counts[review.status] = counts.get(review.status, 0) + 1
        return counts

    def persist(self, path: Path) -> None:
        """Save a local, auditable snapshot of agent coverage."""

        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "orchestration_id": self.orchestration_id,
            "summary": self.summary(),
            "reviews": [asdict(item) for item in self.reviews.values()],
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
