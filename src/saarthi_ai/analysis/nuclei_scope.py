"""Non-executable AI advice about the breadth of a planned Nuclei review.

Only aggregate, integrity-checked Phase 3C metadata reaches the model. Its
response is reduced to fixed labels and is never passed to the tool runner.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from saarthi_ai.schemas.chat import Message

MAX_EVIDENCE_BYTES = 2_000_000
MODES = frozenset({"quick", "balanced", "comprehensive"})
AREAS = frozenset({
    "http-metadata",
    "tls-configuration",
    "technology-fingerprints",
    "exposure-inventory",
})

SYSTEM_PROMPT = (
    "Review aggregate HTTP reconnaissance metadata for an authorized assessment. "
    "This is advisory analysis only. Do not name templates, template IDs, tags, "
    "paths, commands, payloads, or vulnerabilities. Do not instruct tool use. "
    'Return only JSON: {"mode":"quick|balanced|comprehensive",'
    '"areas":["http-metadata","tls-configuration",'
    '"technology-fingerprints","exposure-inventory"]}. '
    "Choose a breadth for human review; your output will not control a scan."
)


class ChatClient(Protocol):
    async def chat(
        self, messages: list[Message], **kwargs: object
    ) -> tuple[str, str | None]: ...


@dataclass(frozen=True)
class NucleiScopeAdvice:
    mode: str
    areas: tuple[str, ...]
    live_services: int


def _aggregate_http_evidence(path: Path, expected_sha256: str) -> dict[str, int]:
    if not expected_sha256 or len(expected_sha256) != 64:
        raise ValueError("Phase 3C evidence has no usable SHA-256.")
    if not path.is_file() or path.stat().st_size > MAX_EVIDENCE_BYTES:
        raise ValueError("Phase 3C evidence is missing or too large.")
    raw = path.read_bytes()
    if len(raw) > MAX_EVIDENCE_BYTES:
        raise ValueError("Phase 3C evidence is too large.")
    if hashlib.sha256(raw).hexdigest() != expected_sha256.lower():
        raise ValueError("Phase 3C evidence hash mismatch.")
    payload = json.loads(raw)
    if not isinstance(payload, dict) or not isinstance(payload.get("records"), list):
        raise ValueError("Phase 3C evidence has an invalid schema.")
    records = [item for item in payload["records"][:100] if isinstance(item, dict)]
    if not records:
        raise ValueError("Phase 3C has no live services to review.")
    return {
        "live_services": len(records),
        "tls_services": sum(item.get("scheme") == "https" for item in records),
        "technology_observations": sum(
            bool(item.get("technologies")) for item in records
        ),
        "redirect_observations": sum(
            bool(item.get("redirect_chain")) for item in records
        ),
    }


async def recommend_nuclei_scope(
    client: ChatClient,
    evidence_path: Path,
    evidence_sha256: str,
) -> NucleiScopeAdvice:
    """Return fixed-label advice; never return executable template selectors."""

    facts = _aggregate_http_evidence(evidence_path, evidence_sha256)
    answer, _thinking = await client.chat(
        [Message(role="user", content=json.dumps(facts, sort_keys=True))],
        system_prompt=SYSTEM_PROMPT,
        json_mode=True,
        num_predict=180,
        use_skills=False,
    )
    payload = json.loads(answer)
    if not isinstance(payload, dict) or payload.get("mode") not in MODES:
        raise ValueError("AI returned an invalid Nuclei review breadth.")
    raw_areas = payload.get("areas")
    if not isinstance(raw_areas, list) or any(
        not isinstance(area, str) or area not in AREAS for area in raw_areas
    ):
        raise ValueError("AI returned an invalid Nuclei review area.")
    return NucleiScopeAdvice(
        mode=payload["mode"],
        areas=tuple(dict.fromkeys(raw_areas))[:4],
        live_services=facts["live_services"],
    )
