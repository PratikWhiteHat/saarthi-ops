"""Automatic, read-only CVE correlation from verified Phase 3C CPE evidence."""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx

from saarthi_ai.cve.catalog import CveCatalog
from saarthi_ai.cve.matcher import match_cpe
from saarthi_ai.cve.parser import CveFeedError
from saarthi_ai.cve.sync import lookup_cpes_online, sync_official_feeds
from saarthi_ai.orchestration.models import (
    OrchestrationContext,
    OrchestrationPhase,
    OrchestrationPhaseResult,
)
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.http_workflow import fail_execution_safely
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceCreate,
    EvidenceType,
)
from saarthi_ai.persistence.orchestration_workflow import (
    complete_phase_execution,
    create_phase_execution,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class CveWorkflowResult:
    phase: OrchestrationPhaseResult
    observed_cpes: int
    candidates: int
    catalog_cves: int
    refresh_status: str
    online_status: str
    online_queried_cpes: int
    online_imported_cves: int


def _source_file(path: str) -> Path:
    supplied = Path(path)
    return supplied if supplied.is_absolute() else PROJECT_ROOT / supplied


def _needs_refresh(stats: dict[str, object]) -> bool:
    feeds = stats.get("feeds")
    if not isinstance(feeds, list):
        return True
    recent = {}
    for row in feeds:
        if not isinstance(row, dict):
            continue
        try:
            recent[str(row["feed"])] = datetime.fromisoformat(str(row["imported_at"]))
        except (KeyError, ValueError):
            continue
    threshold = datetime.now(UTC) - timedelta(hours=24)
    return any(recent.get(feed, datetime.min.replace(tzinfo=UTC)) < threshold
               for feed in ("nvd", "kev"))


def run_cve_intelligence(
    database: SaarthiDatabase,
    context: OrchestrationContext,
    source: OrchestrationPhaseResult,
    *,
    evidence_root: Path,
    catalog_path: Path | None = None,
    refresh: bool = True,
    actor: str = "saarthi-cve-intelligence",
) -> CveWorkflowResult:
    """Run Phase 5E; online requests include CPEs but never target URLs/hosts."""

    if source.phase is not OrchestrationPhase.HTTP_INTELLIGENCE:
        raise ValueError("CVE intelligence requires Phase 3C source evidence.")
    if not source.execution_id or not source.evidence_id or not source.evidence_path:
        raise ValueError("Phase 3C evidence is unavailable for CVE intelligence.")
    child = create_phase_execution(
        database, context, phase=OrchestrationPhase.CVE_INTELLIGENCE,
        phase_name="CVE Intelligence", active_testing_allowed=False,
        previous_execution_id=source.execution_id,
    )
    try:
        evidence_record = next(
            (item for item in database.list_evidence(source.execution_id)
             if item.evidence_id == source.evidence_id),
            None,
        )
        if evidence_record is None or not evidence_record.sha256:
            raise ValueError("Phase 3C evidence is not registered with a SHA-256 hash.")
        source_path = _source_file(source.evidence_path)
        source_bytes = source_path.read_bytes()
        if len(source_bytes) > 50 * 1024 * 1024:
            raise ValueError("Phase 3C evidence exceeds the 50 MiB analysis limit.")
        source_sha256 = hashlib.sha256(source_bytes).hexdigest()
        if source_sha256 != evidence_record.sha256:
            raise ValueError("Phase 3C evidence hash mismatch; CVE matching stopped.")
        payload = json.loads(source_bytes)
        if not isinstance(payload, dict) or not isinstance(payload.get("records"), list):
            raise ValueError("Phase 3C evidence has no valid records array.")

        database.add_audit_event(
            child.execution_id, event_type=AuditEventType.TOOL_STARTED,
            actor=actor, message="Public and local CVE intelligence correlation started.",
            details={"phase_code": "5E", "source_evidence_id": source.evidence_id},
        )
        catalog = CveCatalog(catalog_path)
        refresh_status = "fresh"
        refresh_error = None
        if refresh and _needs_refresh(catalog.stats()):
            try:
                sync_official_feeds(catalog)
                refresh_status = "refreshed"
            except (httpx.HTTPError, CveFeedError, ValueError) as exc:
                refresh_status = "offline_or_unavailable"
                refresh_error = str(exc)[:500]

        observations: dict[str, set[str]] = {}
        for record in payload["records"][:500]:
            if not isinstance(record, dict) or not isinstance(record.get("url"), str):
                continue
            cpes = record.get("cpes")
            if not isinstance(cpes, list):
                continue
            for cpe in cpes[:30]:
                if isinstance(cpe, str) and cpe.startswith("cpe:2.3:"):
                    parsed_url = urlsplit(record["url"])
                    safe_url = urlunsplit((
                        parsed_url.scheme, parsed_url.netloc,
                        parsed_url.path or "/", "", "",
                    ))
                    observations.setdefault(cpe, set()).add(safe_url[:2048])

        online_status = "no_cpe" if not observations else "not_run"
        online_error = None
        online_queried_cpes = 0
        online_imported_cves = 0
        online_truncated = False
        if refresh and observations:
            try:
                if refresh_status == "refreshed":
                    time.sleep(2 if os.environ.get("NVD_API_KEY") else 6)
                online_result = lookup_cpes_online(catalog, list(observations))
                online_queried_cpes = online_result.queried_cpes
                online_imported_cves = online_result.imported_cves
                online_truncated = online_result.truncated
                online_status = "partial" if online_truncated else "complete"
            except (httpx.HTTPError, CveFeedError, ValueError) as exc:
                online_status = "unavailable"
                online_error = str(exc)[:500]

        matches = []
        for cpe, urls in sorted(observations.items())[:150]:
            try:
                candidates = match_cpe(catalog, cpe, limit=50)
            except ValueError:
                continue
            for candidate in candidates:
                matches.append({**asdict(candidate), "observed_urls": sorted(urls)[:20]})
        matches = sorted(
            matches, key=lambda row: (-row["priority_score"], row["cve"]["cve_id"])
        )[:500]
        stats = catalog.stats()
        result = {
            "schema_version": "1.0",
            "phase_code": "5E",
            "source_evidence_id": source.evidence_id,
            "source_sha256": source_sha256,
            "catalog": stats,
            "refresh_status": refresh_status,
            "refresh_error": refresh_error,
            "online_status": online_status,
            "online_error": online_error,
            "online_queried_cpes": online_queried_cpes,
            "online_imported_cves": online_imported_cves,
            "online_truncated": online_truncated,
            "observed_cpe_count": len(observations),
            "candidate_count": len(matches),
            "candidates": matches,
            "disclaimer": "Candidates only; applicability and impact are not confirmed.",
        }
        evidence_root.mkdir(parents=True, exist_ok=True)
        output_path = evidence_root / "cve-intelligence.json"
        output_bytes = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
        output_path.write_bytes(output_bytes)
        output_sha256 = hashlib.sha256(output_bytes).hexdigest()
        evidence = database.add_evidence(
            child.execution_id,
            EvidenceCreate(
                evidence_type=EvidenceType.CVE_INTELLIGENCE_RESULT,
                source="saarthi-public-and-local-cve-intelligence", path=str(output_path),
                sha256=output_sha256, size_bytes=len(output_bytes),
                content_type="application/json", step_id="cve-intelligence-001",
                tool_name="saarthi-cve-intelligence",
                metadata={
                    "phase_code": "5E", "source_evidence_id": source.evidence_id,
                    "observed_cpe_count": len(observations),
                    "candidate_count": len(matches), "refresh_status": refresh_status,
                    "online_status": online_status,
                    "online_queried_cpes": online_queried_cpes,
                    "catalog_cves": stats["counts"]["cves"],
                },
            ), actor=actor,
        )
        complete_phase_execution(
            database, child.execution_id, actor=actor,
            reason="Read-only CVE candidate correlation completed.",
        )
        database.add_audit_event(
            child.execution_id, event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor, message="CVE intelligence evidence persisted.",
            details={
                "phase_code": "5E", "candidate_count": len(matches),
                "observed_cpe_count": len(observations),
                "evidence_id": evidence.evidence_id,
                "refresh_status": refresh_status,
                "online_status": online_status,
            },
        )
        return CveWorkflowResult(
            phase=OrchestrationPhaseResult(
                phase=OrchestrationPhase.CVE_INTELLIGENCE, required=False,
                execution_id=child.execution_id, evidence_id=evidence.evidence_id,
                evidence_path=str(output_path),
                metrics={"candidate_count": len(matches),
                         "observed_cpe_count": len(observations)},
            ),
            observed_cpes=len(observations), candidates=len(matches),
            catalog_cves=int(stats["counts"]["cves"]),
            refresh_status=refresh_status,
            online_status=online_status,
            online_queried_cpes=online_queried_cpes,
            online_imported_cves=online_imported_cves,
        )
    except Exception as exc:
        fail_execution_safely(
            database, child.execution_id, actor=actor,
            reason=f"CVE intelligence failed: {exc}",
        )
        raise
