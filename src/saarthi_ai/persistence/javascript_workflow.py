"""Persistent Phase 3E JavaScript intelligence workflow."""

from __future__ import annotations

import asyncio
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
from saarthi_ai.recon.javascript_collector import (
    JavaScriptCollectionError,
    collect_javascript_intelligence,
)
from saarthi_ai.recon.javascript_models import (
    JavaScriptAssetRecord,
    JavaScriptCollectionResult,
)


class TrackedJavaScriptResult:
    """Combined persistent Phase 3E JavaScript workflow result."""

    def __init__(
        self,
        *,
        execution: ExecutionRecord,
        collection: JavaScriptCollectionResult,
        evidence: EvidenceRecord,
    ) -> None:
        self.execution = execution
        self.collection = collection
        self.evidence = evidence


def run_tracked_javascript_intelligence(
    database: SaarthiDatabase,
    execution_id: str,
    source_evidence_path: Path,
    *,
    actor: str = "javascript-intelligence-collector",
    evidence_root: Path | None = None,
) -> TrackedJavaScriptResult:
    """Run Phase 3E JavaScript intelligence with persistence and auditing."""

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
        message="Saarthi JavaScript intelligence collector started.",
        details={
            "tool": "saarthi-javascript-intelligence",
            "source_evidence_path": str(source_evidence_path),
            "mode": "active-low-risk",
            "max_javascript_assets": 100,
            "max_body_bytes": 524_288,
            "fetch_concurrency": 3,
            "fetch_timeout_seconds": 10.0,
            "stores_full_javascript_source": False,
        },
    )

    progress_lock = threading.Lock()
    progress_event_count = 0
    maximum_progress_events = 50
    observed_urls: set[str] = set()

    def record_progress(
        asset: JavaScriptAssetRecord,
    ) -> None:
        nonlocal progress_event_count

        parsed = urlsplit(asset.fetch.url)
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

            if asset.fetch.error:
                database.add_audit_event(
                    execution_id,
                    event_type=AuditEventType.TOOL_OUTPUT,
                    actor=actor,
                    message=(
                        "[3E][javascript] "
                        f"Fetch failed: {safe_url}"
                    ),
                    details={
                        "phase_code": "3E",
                        "tool": (
                            "saarthi-javascript-intelligence"
                        ),
                        "url": safe_url,
                        "status": "failed",
                        "error": asset.fetch.error[:300],
                        "sequence": progress_event_count,
                    },
                )
                return

            status_code = asset.fetch.status_code
            endpoint_count = len(asset.endpoints)
            parameter_count = len(asset.parameters)
            websocket_count = len(asset.websocket_urls)
            source_map_count = len(asset.source_map_urls)
            secret_candidate_count = len(
                asset.secret_candidates
            )

            database.add_audit_event(
                execution_id,
                event_type=AuditEventType.TOOL_OUTPUT,
                actor=actor,
                message=(
                    "[3E][javascript] "
                    f"{safe_url} HTTP {status_code}; "
                    f"endpoints={endpoint_count}; "
                    f"parameters={parameter_count}; "
                    f"websockets={websocket_count}; "
                    f"source_maps={source_map_count}; "
                    f"secret_candidates="
                    f"{secret_candidate_count}"
                ),
                details={
                    "phase_code": "3E",
                    "tool": (
                        "saarthi-javascript-intelligence"
                    ),
                    "url": safe_url,
                    "status_code": status_code,
                    "content_type": (
                        asset.fetch.content_type[:120]
                        if asset.fetch.content_type
                        else None
                    ),
                    "body_bytes_captured": (
                        asset.fetch.body_bytes_captured
                    ),
                    "body_truncated": (
                        asset.fetch.body_truncated
                    ),
                    "endpoint_count": endpoint_count,
                    "parameter_names": [
                        parameter.name
                        for parameter in asset.parameters[:25]
                    ],
                    "websocket_count": websocket_count,
                    "source_map_count": source_map_count,
                    "framework_indicators": list(
                        asset.framework_indicators[:15]
                    ),
                    "secret_candidate_count": (
                        secret_candidate_count
                    ),
                    "secret_values_stored": False,
                    "sequence": progress_event_count,
                },
            )

    try:
        collection = asyncio.run(
            collect_javascript_intelligence(
                source_evidence_path,
                evidence_root=evidence_root,
                progress_callback=record_progress,
            )
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
                evidence_type=(EvidenceType.JAVASCRIPT_INTELLIGENCE_RESULT),
                source="saarthi-javascript-intelligence",
                path=collection.evidence_path,
                sha256=collection.evidence_sha256,
                size_bytes=collection.evidence_size_bytes,
                content_type="application/json",
                step_id="recon-javascript-001",
                tool_name="saarthi-javascript-intelligence",
                metadata={
                    "domain": collection.domain,
                    "input_javascript_count": (collection.input_javascript_count),
                    "fetched_javascript_count": (collection.fetched_javascript_count),
                    "failed_fetch_count": (collection.failed_fetch_count),
                    "endpoint_count": collection.endpoint_count,
                    "parameter_count": collection.parameter_count,
                    "websocket_count": collection.websocket_count,
                    "source_map_count": collection.source_map_count,
                    "secret_candidate_count": (collection.secret_candidate_count),
                    "rejected_input_count": len(collection.rejected_inputs),
                    "collector_execution_id": (collection.collector_execution_id),
                    "collector_evidence_id": (collection.collector_evidence_id),
                    "source_collector_execution_id": (collection.source_collector_execution_id),
                    "source_collector_evidence_id": (collection.source_collector_evidence_id),
                    "stores_full_javascript_source": False,
                },
            ),
            actor=actor,
        )

        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message="Saarthi JavaScript intelligence collector completed.",
            details={
                "tool": "saarthi-javascript-intelligence",
                "domain": collection.domain,
                "fetched_javascript_count": (collection.fetched_javascript_count),
                "endpoint_count": collection.endpoint_count,
                "source_map_count": collection.source_map_count,
                "secret_candidate_count": (collection.secret_candidate_count),
                "evidence_id": evidence.evidence_id,
            },
        )

        execution = database.transition_execution(
            execution_id,
            ExecutionState.ANALYZING,
            actor=actor,
            reason=("JavaScript intelligence evidence is ready for analysis."),
        )

        execution = database.transition_execution(
            execution_id,
            ExecutionState.COMPLETED,
            actor=actor,
            reason=("Phase 3E JavaScript intelligence workflow completed."),
        )

        return TrackedJavaScriptResult(
            execution=execution,
            collection=collection,
            evidence=evidence,
        )

    except (
        JavaScriptCollectionError,
        InvalidStateTransitionError,
    ) as exc:
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message="Saarthi JavaScript intelligence collector failed.",
            details={
                "tool": "saarthi-javascript-intelligence",
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
