"""Persistent Phase 3D crawling and URL intelligence workflow."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.http_intelligence_workflow import (
    _domain_in_execution_scope,
)
from saarthi_ai.persistence.http_workflow import (
    advance_execution_to_running,
    fail_execution_safely,
)
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceCreate,
    EvidenceRecord,
    EvidenceType,
    ExecutionRecord,
    ExecutionState,
)
from saarthi_ai.recon.crawl_collector import (
    CrawlCollectionError,
    collect_crawl_intelligence,
)
from saarthi_ai.recon.crawl_models import (
    CrawlCollectionResult,
    CrawlUrlRecord,
)


class TrackedCrawlResult:
    """Combined persistent Phase 3D crawl workflow result."""

    def __init__(
        self,
        *,
        execution: ExecutionRecord,
        collection: CrawlCollectionResult,
        evidence: EvidenceRecord,
    ) -> None:
        self.execution = execution
        self.collection = collection
        self.evidence = evidence


def run_tracked_crawl(
    database: SaarthiDatabase,
    execution_id: str,
    source_evidence_path: Path,
    *,
    actor: str = "crawl-collector",
    evidence_root: Path | None = None,
) -> TrackedCrawlResult:
    """Run Phase 3D crawling with persistence and auditing."""

    execution = database.get_execution(execution_id)

    if not execution.authorization_confirmed:
        raise InvalidStateTransitionError("Execution does not have confirmed authorization.")

    if not execution.active_testing_allowed:
        raise InvalidStateTransitionError("Execution does not allow active testing.")

    execution = advance_execution_to_running(
        database,
        execution,
        actor=actor,
    )

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_STARTED,
        actor=actor,
        message="ProjectDiscovery Katana crawl collector started.",
        details={
            "tool": "projectdiscovery-katana",
            "source_evidence_path": str(source_evidence_path),
            "mode": "active-low-risk",
            "depth": 2,
            "crawl_duration": "20s",
            "rate_limit": 2,
        },
    )

    progress_lock = threading.Lock()
    progress_event_count = 0
    maximum_progress_events = 80
    observed_urls: set[str] = set()

    def record_progress(record: CrawlUrlRecord) -> None:
        nonlocal progress_event_count

        parsed = urlsplit(record.url)
        safe_url = urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path or "/",
                "",
                "",
            )
        )

        with progress_lock:
            if safe_url in observed_urls:
                return

            if progress_event_count >= maximum_progress_events:
                return

            observed_urls.add(safe_url)
            progress_event_count += 1

            status = (
                str(record.status_code)
                if record.status_code is not None
                else "unknown"
            )

            kind = (
                "javascript"
                if record.is_javascript
                else "websocket"
                if record.is_websocket
                else "url"
            )

            database.add_audit_event(
                execution_id,
                event_type=AuditEventType.TOOL_OUTPUT,
                actor=actor,
                message=(
                    f"[3D][katana] {record.method} "
                    f"{safe_url} status={status} type={kind}"
                ),
                details={
                    "phase_code": "3D",
                    "tool": "projectdiscovery-katana",
                    "method": record.method,
                    "url": safe_url,
                    "host": record.host,
                    "path": record.path,
                    "status_code": record.status_code,
                    "content_type": (
                        record.content_type[:120]
                        if record.content_type
                        else None
                    ),
                    "is_javascript": record.is_javascript,
                    "is_websocket": record.is_websocket,
                    "parameter_names": [
                        parameter.name
                        for parameter in record.parameters[:25]
                    ],
                    "sequence": progress_event_count,
                },
            )

    try:
        collection = collect_crawl_intelligence(
            source_evidence_path,
            evidence_root=evidence_root,
            progress_callback=record_progress,
        )

        if not _domain_in_execution_scope(
            collection.domain,
            execution,
        ):
            raise InvalidStateTransitionError(
                f"Domain '{collection.domain}' is not associated with this execution."
            )

        evidence = database.add_evidence(
            execution_id,
            EvidenceCreate(
                evidence_type=EvidenceType.CRAWL_RESULT,
                source="projectdiscovery-katana",
                path=collection.evidence_path,
                sha256=collection.evidence_sha256,
                size_bytes=collection.evidence_size_bytes,
                content_type="application/json",
                step_id="recon-crawl-001",
                tool_name="projectdiscovery-katana",
                metadata={
                    "domain": collection.domain,
                    "input_service_count": collection.input_service_count,
                    "crawled_service_count": collection.crawled_service_count,
                    "discovered_url_count": collection.discovered_url_count,
                    "form_count": collection.form_count,
                    "parameter_count": collection.parameter_count,
                    "javascript_url_count": collection.javascript_url_count,
                    "websocket_url_count": collection.websocket_url_count,
                    "malformed_line_count": collection.malformed_line_count,
                    "rejected_input_count": len(collection.rejected_inputs),
                    "rejected_result_count": len(collection.rejected_results),
                    "collector_execution_id": collection.collector_execution_id,
                    "collector_evidence_id": collection.collector_evidence_id,
                    "source_collector_execution_id": (collection.source_collector_execution_id),
                    "source_collector_evidence_id": (collection.source_collector_evidence_id),
                },
            ),
            actor=actor,
        )

        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message="ProjectDiscovery Katana crawl collector completed.",
            details={
                "tool": "projectdiscovery-katana",
                "domain": collection.domain,
                "discovered_url_count": collection.discovered_url_count,
                "form_count": collection.form_count,
                "evidence_id": evidence.evidence_id,
            },
        )

        # Phase 3D "URL Intelligence": passive historical URLs from the
        # Wayback Machine CDX (read-only; publishes nothing). Best-effort —
        # a CDX hiccup must never fail the required crawl phase.
        _collect_wayback_url_intelligence(
            database,
            execution_id,
            collection.domain,
            evidence_root=evidence_root,
            actor=actor,
        )

        # Local page-snapshot archive (LOCAL-FIRST): store in-scope pages under
        # the run's evidence dir. Non-fatal; publishes nothing externally.
        _capture_local_page_archive(
            database,
            execution_id,
            collection.domain,
            evidence_root=evidence_root,
            actor=actor,
        )

        execution = database.transition_execution(
            execution_id,
            ExecutionState.ANALYZING,
            actor=actor,
            reason="Crawl and URL intelligence evidence is ready for analysis.",
        )

        execution = database.transition_execution(
            execution_id,
            ExecutionState.COMPLETED,
            actor=actor,
            reason="Phase 3D crawling and URL intelligence workflow completed.",
        )

        return TrackedCrawlResult(
            execution=execution,
            collection=collection,
            evidence=evidence,
        )

    except (
        CrawlCollectionError,
        InvalidStateTransitionError,
    ) as exc:
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message="ProjectDiscovery Katana crawl collector failed.",
            details={
                "tool": "projectdiscovery-katana",
                "error": str(exc),
            },
        )

        fail_execution_safely(
            database,
            execution_id,
            actor=actor,
            reason=str(exc),
        )

        raise


def _collect_wayback_url_intelligence(
    database: SaarthiDatabase,
    execution_id: str,
    domain: str,
    *,
    evidence_root: Path | None,
    actor: str,
    max_logged: int = 60,
) -> None:
    """Passive Wayback CDX URL discovery, logged as a Phase 3D sub-step.

    Non-fatal: any failure is recorded and swallowed so it never breaks the
    required crawl phase. Read-only — it queries the public Wayback index and
    publishes nothing to the target.
    """

    from saarthi_ai.recon.wayback_cdx import collect_wayback_urls

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_STARTED,
        actor=actor,
        message=(
            "[3D][wayback] Historical URL intelligence (Wayback CDX) started."
        ),
        details={
            "phase_code": "3D",
            "tool": "wayback-cdx",
            "domain": domain,
            "mode": "passive-read-only",
        },
    )

    try:
        result = collect_wayback_urls(domain)
    except Exception as exc:  # non-fatal enrichment; never fail the phase
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message=f"[3D][wayback] URL intelligence skipped: {exc}",
            details={
                "phase_code": "3D",
                "tool": "wayback-cdx",
                "error": str(exc),
            },
        )
        return

    for sequence, url in enumerate(result.urls[:max_logged], start=1):
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_OUTPUT,
            actor=actor,
            message=f"[3D][wayback] {url}",
            details={
                "phase_code": "3D",
                "tool": "wayback-cdx",
                "url": url,
                "sequence": sequence,
            },
        )

    if evidence_root is not None:
        try:
            evidence_root.mkdir(parents=True, exist_ok=True)
            artifact = evidence_root / f"wayback-cdx-{domain}.json"
            artifact.write_text(
                json.dumps(
                    {
                        "domain": result.domain,
                        "url_count": result.total,
                        "truncated": result.truncated,
                        "urls": list(result.urls),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        except OSError:
            pass

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_COMPLETED,
        actor=actor,
        message=(
            f"[3D][wayback] Historical URL intelligence completed: "
            f"{result.total} URLs"
            + (" (truncated)" if result.truncated else "")
            + "."
        ),
        details={
            "phase_code": "3D",
            "tool": "wayback-cdx",
            "domain": domain,
            "url_count": result.total,
            "truncated": result.truncated,
        },
    )


def _capture_local_page_archive(
    database: SaarthiDatabase,
    execution_id: str,
    domain: str,
    *,
    evidence_root: Path | None,
    actor: str,
    limit: int = 15,
) -> None:
    """Snapshot in-scope pages LOCALLY as a Phase 3D sub-step.

    Non-fatal and local-only: reads pages recon already discovered (Wayback CDX
    artifact + domain base) and stores them under the run's evidence dir. It
    publishes nothing externally.
    """

    if evidence_root is None:
        return

    from saarthi_ai.recon.local_archive import capture_local_archive

    urls: list[str] = []
    cdx_artifact = evidence_root / f"wayback-cdx-{domain}.json"
    try:
        if cdx_artifact.exists():
            data = json.loads(cdx_artifact.read_text(encoding="utf-8"))
            urls.extend(str(url) for url in data.get("urls", []) or [])
    except (OSError, json.JSONDecodeError):
        pass
    urls.extend([f"https://{domain}/", f"http://{domain}/"])

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_STARTED,
        actor=actor,
        message="[3D][archive] Local page-snapshot archive started.",
        details={
            "phase_code": "3D",
            "tool": "local-archive",
            "domain": domain,
            "mode": "local-only-read",
        },
    )
    try:
        result = capture_local_archive(
            urls,
            evidence_root / "archive",
            domain=domain,
            limit=limit,
        )
    except Exception as exc:  # non-fatal enrichment; never fail the phase
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message=f"[3D][archive] Local archive skipped: {exc}",
            details={
                "phase_code": "3D",
                "tool": "local-archive",
                "error": str(exc),
            },
        )
        return

    for entry in result.entries[:40]:
        if "sha256" not in entry:
            continue
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_OUTPUT,
            actor=actor,
            message=(
                f"[3D][archive] {entry['url']} -> {entry['saved_as']} "
                f"({entry['status_code']})"
            ),
            details={
                "phase_code": "3D",
                "tool": "local-archive",
                "url": entry["url"],
                "saved_as": entry["saved_as"],
            },
        )

    database.add_audit_event(
        execution_id,
        event_type=AuditEventType.TOOL_COMPLETED,
        actor=actor,
        message=(
            f"[3D][archive] Local page archive completed: "
            f"{result.archived}/{result.attempted} pages saved locally."
        ),
        details={
            "phase_code": "3D",
            "tool": "local-archive",
            "domain": domain,
            "archived": result.archived,
            "attempted": result.attempted,
        },
    )
