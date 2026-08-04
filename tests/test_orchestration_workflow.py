from __future__ import annotations

import json
from pathlib import Path

import pytest

from saarthi_ai.checks.models import DirectCheckRequest
from saarthi_ai.orchestration.models import (
    OrchestrationPhase,
    OrchestrationPhaseResult,
)
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import ExecutionState
from saarthi_ai.persistence.orchestration_workflow import (
    OrchestrationWorkflowError,
    create_orchestration,
    create_phase_execution,
    normalize_target_domain,
    run_assessment_pipeline,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "orchestration.db")
    repository.initialize()
    return repository


def test_normalize_target_domain() -> None:
    assert (
        normalize_target_domain(
            "https://Example.COM:8443/application/"
        )
        == "example.com"
    )


def test_orchestration_rejects_non_http_target() -> None:
    with pytest.raises(
        OrchestrationWorkflowError,
        match="HTTP or HTTPS",
    ):
        normalize_target_domain("ftp://example.com/")


def test_create_orchestration_prepares_parent(
    database: SaarthiDatabase,
) -> None:
    context = create_orchestration(
        database,
        assessment_name="Full Authorized Assessment",
        target_url="https://example.com/",
        active_testing_allowed=True,
        rate_limit_per_second=2,
        project_id="project-001",
        project_slug="example-project",
    )

    parent = database.get_execution(
        context.parent_execution_id
    )

    assert parent.state is ExecutionState.PLANNED
    assert parent.metadata["execution_role"] == (
        "orchestration_parent"
    )
    assert parent.metadata["orchestration_id"] == (
        context.orchestration_id
    )
    assert parent.metadata["project_id"] == "project-001"
    assert context.target_domain == "example.com"


def test_create_phase_execution_links_child_to_parent(
    database: SaarthiDatabase,
) -> None:
    context = create_orchestration(
        database,
        assessment_name="Full Authorized Assessment",
        target_url="https://example.com/",
        active_testing_allowed=True,
    )

    child = create_phase_execution(
        database,
        context,
        phase=OrchestrationPhase.DNS,
        phase_name="DNS Intelligence",
        active_testing_allowed=False,
    )

    assert child.state is ExecutionState.CREATED
    assert child.metadata["execution_role"] == (
        "orchestration_child"
    )
    assert child.metadata["parent_execution_id"] == (
        context.parent_execution_id
    )
    assert child.metadata["orchestration_id"] == (
        context.orchestration_id
    )
    assert child.metadata["phase_code"] == "3A"
    assert child.metadata["previous_execution_id"] is None


def test_child_preserves_project_membership(
    database: SaarthiDatabase,
) -> None:
    context = create_orchestration(
        database,
        assessment_name="Project Assessment",
        target_url="https://example.com/",
        active_testing_allowed=True,
        project_id="project-001",
        project_slug="example-project",
    )

    child = create_phase_execution(
        database,
        context,
        phase=OrchestrationPhase.SUBDOMAINS,
        phase_name="Subdomain Enumeration",
        active_testing_allowed=False,
        previous_execution_id="execution-previous",
    )

    assert child.metadata["project_id"] == "project-001"
    assert child.metadata["project_slug"] == "example-project"
    assert child.metadata["previous_execution_id"] == (
        "execution-previous"
    )


def test_intrusive_requires_active(
    database: SaarthiDatabase,
) -> None:
    with pytest.raises(
        OrchestrationWorkflowError,
        match="requires active testing",
    ):
        create_orchestration(
            database,
            assessment_name="Invalid Assessment",
            target_url="https://example.com/",
            active_testing_allowed=False,
            intrusive_testing_allowed=True,
        )


def test_initial_recon_chains_dns_and_subdomains(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch,
) -> None:
    import saarthi_ai.persistence.orchestration_workflow as workflow_module

    calls: list[tuple[str, str]] = []

    def fake_dns(
        database,
        execution_id,
        domain,
        *,
        actor,
        evidence_root,
    ):
        calls.append(("dns", execution_id))

        return type(
            "DnsResult",
            (),
            {
                "evidence": type(
                    "Evidence",
                    (),
                    {
                        "evidence_id": "evidence-dns",
                        "path": str(evidence_root / "dns.json"),
                    },
                )()
            },
        )()

    def fake_subdomains(
        database,
        execution_id,
        domain,
        *,
        actor,
        evidence_root,
    ):
        calls.append(("subdomains", execution_id))

        return type(
            "SubdomainResult",
            (),
            {
                "evidence": type(
                    "Evidence",
                    (),
                    {
                        "evidence_id": "evidence-subdomains",
                        "path": str(
                            evidence_root / "subdomains.json"
                        ),
                    },
                )()
            },
        )()

    monkeypatch.setattr(
        workflow_module,
        "run_tracked_dns_collection",
        fake_dns,
    )
    monkeypatch.setattr(
        workflow_module,
        "run_tracked_subdomain_collection",
        fake_subdomains,
    )

    context = create_orchestration(
        database,
        assessment_name="Automated Recon",
        target_url="https://example.com/",
        active_testing_allowed=True,
    )

    result = workflow_module.run_initial_recon(
        database,
        context,
        evidence_root=tmp_path / "workflow-evidence",
    )

    parent = database.get_execution(
        context.parent_execution_id
    )

    dns_child = database.get_execution(
        result.dns.execution_id
    )
    subdomain_child = database.get_execution(
        result.subdomains.execution_id
    )

    assert parent.state is ExecutionState.RUNNING
    assert result.context.status.value == "running"
    assert result.dns.evidence_id == "evidence-dns"
    assert result.subdomains.evidence_id == (
        "evidence-subdomains"
    )

    assert dns_child.metadata["phase_code"] == "3A"
    assert subdomain_child.metadata["phase_code"] == "3B"
    assert subdomain_child.metadata["previous_execution_id"] == (
        dns_child.execution_id
    )

    assert [name for name, _ in calls] == [
        "dns",
        "subdomains",
    ]


def test_initial_recon_failure_marks_parent_failed(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch,
) -> None:
    import saarthi_ai.persistence.orchestration_workflow as workflow_module

    def failing_dns(*args, **kwargs):
        raise RuntimeError("simulated DNS failure")

    monkeypatch.setattr(
        workflow_module,
        "run_tracked_dns_collection",
        failing_dns,
    )

    context = create_orchestration(
        database,
        assessment_name="Failing Recon",
        target_url="https://example.com/",
        active_testing_allowed=True,
    )

    with pytest.raises(
        RuntimeError,
        match="simulated DNS failure",
    ):
        workflow_module.run_initial_recon(
            database,
            context,
            evidence_root=tmp_path / "workflow-evidence",
        )

    parent = database.get_execution(
        context.parent_execution_id
    )

    assert parent.state is ExecutionState.FAILED
    assert "simulated DNS failure" in (
        parent.failure_reason or ""
    )


def test_recon_pipeline_adds_http_intelligence_child(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch,
) -> None:
    import saarthi_ai.persistence.orchestration_workflow as workflow_module

    def fake_dns(
        database,
        execution_id,
        domain,
        *,
        actor,
        evidence_root,
    ):
        return type(
            "Result",
            (),
            {
                "evidence": type(
                    "Evidence",
                    (),
                    {
                        "evidence_id": "evidence-dns",
                        "path": str(evidence_root / "dns.json"),
                    },
                )()
            },
        )()

    def fake_subdomains(
        database,
        execution_id,
        domain,
        *,
        actor,
        evidence_root,
    ):
        return type(
            "Result",
            (),
            {
                "evidence": type(
                    "Evidence",
                    (),
                    {
                        "evidence_id": "evidence-subdomains",
                        "path": str(evidence_root / "subdomains.json"),
                    },
                )()
            },
        )()

    captured: dict[str, object] = {}

    def fake_http_intelligence(
        database,
        execution_id,
        source_evidence_path,
        *,
        actor,
        evidence_root,
    ):
        captured["source_evidence_path"] = source_evidence_path
        captured["http_execution_id"] = execution_id

        return type(
            "Result",
            (),
            {
                "evidence": type(
                    "Evidence",
                    (),
                    {
                        "evidence_id": "evidence-http",
                        "path": str(evidence_root / "http.json"),
                    },
                )()
            },
        )()

    monkeypatch.setattr(
        workflow_module,
        "run_tracked_dns_collection",
        fake_dns,
    )
    monkeypatch.setattr(
        workflow_module,
        "run_tracked_subdomain_collection",
        fake_subdomains,
    )
    monkeypatch.setattr(
        workflow_module,
        "run_tracked_http_intelligence",
        fake_http_intelligence,
    )

    context = create_orchestration(
        database,
        assessment_name="Automated Recon Pipeline",
        target_url="https://example.com/",
        active_testing_allowed=True,
    )

    result = workflow_module.run_recon_pipeline(
        database,
        context,
        evidence_root=tmp_path / "workflow-evidence",
    )

    http_child = database.get_execution(
        result.http_intelligence.execution_id
    )

    assert result.http_intelligence.phase is (
        OrchestrationPhase.HTTP_INTELLIGENCE
    )
    assert result.http_intelligence.evidence_id == "evidence-http"
    assert captured["source_evidence_path"] == Path(
        result.subdomains.evidence_path
    )
    assert http_child.metadata["phase_code"] == "3C"
    assert http_child.metadata["previous_execution_id"] == (
        result.subdomains.execution_id
    )

    parent = database.get_execution(
        context.parent_execution_id
    )
    assert parent.state is ExecutionState.RUNNING


def test_phase_3c_failure_marks_parent_failed(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch,
) -> None:
    import saarthi_ai.persistence.orchestration_workflow as workflow_module

    def fake_success(*args, evidence_root, **kwargs):
        return type(
            "Result",
            (),
            {
                "evidence": type(
                    "Evidence",
                    (),
                    {
                        "evidence_id": "evidence-ok",
                        "path": str(evidence_root / "result.json"),
                    },
                )()
            },
        )()

    def failing_http(*args, **kwargs):
        raise RuntimeError("simulated Phase 3C failure")

    monkeypatch.setattr(
        workflow_module,
        "run_tracked_dns_collection",
        fake_success,
    )
    monkeypatch.setattr(
        workflow_module,
        "run_tracked_subdomain_collection",
        fake_success,
    )
    monkeypatch.setattr(
        workflow_module,
        "run_tracked_http_intelligence",
        failing_http,
    )

    context = create_orchestration(
        database,
        assessment_name="Failing Recon Pipeline",
        target_url="https://example.com/",
        active_testing_allowed=True,
    )

    with pytest.raises(
        RuntimeError,
        match="simulated Phase 3C failure",
    ):
        workflow_module.run_recon_pipeline(
            database,
            context,
            evidence_root=tmp_path / "workflow-evidence",
        )

    parent = database.get_execution(
        context.parent_execution_id
    )

    assert parent.state is ExecutionState.FAILED
    assert "simulated Phase 3C failure" in (
        parent.failure_reason or ""
    )


def test_discovery_pipeline_adds_crawl_child(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch,
) -> None:
    import saarthi_ai.persistence.orchestration_workflow as workflow_module

    context = create_orchestration(
        database,
        assessment_name="Automated Discovery Pipeline",
        target_url="https://example.com/",
        active_testing_allowed=True,
    )

    fake_context = context.model_copy(
        update={"status": "running"}
    )

    http_execution = create_phase_execution(
        database,
        fake_context,
        phase=OrchestrationPhase.HTTP_INTELLIGENCE,
        phase_name="Live Host Intelligence",
        active_testing_allowed=True,
    )

    fake_recon = type(
        "ReconResult",
        (),
        {
            "context": fake_context,
            "dns": OrchestrationPhaseResult(
                phase=OrchestrationPhase.DNS,
                execution_id="execution-dns",
                evidence_id="evidence-dns",
                evidence_path="evidence/dns.json",
            ),
            "subdomains": OrchestrationPhaseResult(
                phase=OrchestrationPhase.SUBDOMAINS,
                execution_id="execution-subdomains",
                evidence_id="evidence-subdomains",
                evidence_path="evidence/subdomains.json",
            ),
            "http_intelligence": OrchestrationPhaseResult(
                phase=OrchestrationPhase.HTTP_INTELLIGENCE,
                execution_id=http_execution.execution_id,
                evidence_id="evidence-http",
                evidence_path=str(
                    tmp_path / "http-intelligence.json"
                ),
            ),
        },
    )()

    captured: dict[str, object] = {}

    def fake_recon_pipeline(*args, **kwargs):
        return fake_recon

    def fake_crawl(
        database,
        execution_id,
        source_evidence_path,
        *,
        actor,
        evidence_root,
    ):
        captured["execution_id"] = execution_id
        captured["source_evidence_path"] = source_evidence_path

        return type(
            "Result",
            (),
            {
                "evidence": type(
                    "Evidence",
                    (),
                    {
                        "evidence_id": "evidence-crawl",
                        "path": str(evidence_root / "crawl.json"),
                    },
                )()
            },
        )()

    monkeypatch.setattr(
        workflow_module,
        "run_recon_pipeline",
        fake_recon_pipeline,
    )
    monkeypatch.setattr(
        workflow_module,
        "run_tracked_crawl",
        fake_crawl,
    )

    result = workflow_module.run_discovery_pipeline(
        database,
        context,
        evidence_root=tmp_path / "workflow-evidence",
    )

    crawl_child = database.get_execution(
        result.crawl.execution_id
    )

    assert result.crawl.phase is OrchestrationPhase.CRAWL
    assert result.crawl.evidence_id == "evidence-crawl"
    assert captured["source_evidence_path"] == Path(
        fake_recon.http_intelligence.evidence_path
    )
    assert crawl_child.metadata["phase_code"] == "3D"
    assert crawl_child.metadata["previous_execution_id"] == (
        http_execution.execution_id
    )


def test_phase_3d_failure_marks_parent_failed(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch,
) -> None:
    import saarthi_ai.persistence.orchestration_workflow as workflow_module

    context = create_orchestration(
        database,
        assessment_name="Failing Discovery Pipeline",
        target_url="https://example.com/",
        active_testing_allowed=True,
    )

    parent = database.get_execution(context.parent_execution_id)
    database.transition_execution(
        parent.execution_id,
        ExecutionState.RUNNING,
        actor="test",
        reason="Test orchestration started.",
    )

    fake_context = context.model_copy(
        update={"status": "running"}
    )

    fake_recon = type(
        "ReconResult",
        (),
        {
            "context": fake_context,
            "dns": object(),
            "subdomains": object(),
            "http_intelligence": type(
                "PhaseResult",
                (),
                {
                    "execution_id": "execution-http",
                    "evidence_path": str(
                        tmp_path / "http-intelligence.json"
                    ),
                },
            )(),
        },
    )()

    monkeypatch.setattr(
        workflow_module,
        "run_recon_pipeline",
        lambda *args, **kwargs: fake_recon,
    )

    monkeypatch.setattr(
        workflow_module,
        "run_tracked_crawl",
        lambda *args, **kwargs: (
            (_ for _ in ()).throw(
                RuntimeError("simulated Phase 3D failure")
            )
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="simulated Phase 3D failure",
    ):
        workflow_module.run_discovery_pipeline(
            database,
            context,
            evidence_root=tmp_path / "workflow-evidence",
        )

    parent = database.get_execution(
        context.parent_execution_id
    )

    assert parent.state is ExecutionState.FAILED
    assert "simulated Phase 3D failure" in (
        parent.failure_reason or ""
    )


def test_intelligence_pipeline_adds_javascript_child(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch,
) -> None:
    import saarthi_ai.persistence.orchestration_workflow as workflow_module

    context = create_orchestration(
        database,
        assessment_name="Automated Intelligence Pipeline",
        target_url="https://example.com/",
        active_testing_allowed=True,
    )

    fake_context = context.model_copy(
        update={"status": "running"}
    )

    crawl_execution = create_phase_execution(
        database,
        fake_context,
        phase=OrchestrationPhase.CRAWL,
        phase_name="Crawling and URL Intelligence",
        active_testing_allowed=True,
    )

    fake_discovery = type(
        "DiscoveryResult",
        (),
        {
            "context": fake_context,
            "dns": OrchestrationPhaseResult(
                phase=OrchestrationPhase.DNS,
                execution_id="execution-dns",
                evidence_id="evidence-dns",
                evidence_path="evidence/dns.json",
            ),
            "subdomains": OrchestrationPhaseResult(
                phase=OrchestrationPhase.SUBDOMAINS,
                execution_id="execution-subdomains",
                evidence_id="evidence-subdomains",
                evidence_path="evidence/subdomains.json",
            ),
            "http_intelligence": OrchestrationPhaseResult(
                phase=OrchestrationPhase.HTTP_INTELLIGENCE,
                execution_id="execution-http",
                evidence_id="evidence-http",
                evidence_path="evidence/http.json",
            ),
            "crawl": OrchestrationPhaseResult(
                phase=OrchestrationPhase.CRAWL,
                execution_id=crawl_execution.execution_id,
                evidence_id="evidence-crawl",
                evidence_path=str(tmp_path / "crawl.json"),
            ),
        },
    )()

    crawl_evidence_path = tmp_path / "crawl.json"
    crawl_evidence_path.write_text(
        json.dumps(
            {
                "domain": "example.com",
                "urls": [
                    {
                        "url": "https://example.com/app.js",
                        "is_javascript": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    captured: dict[str, object] = {}

    monkeypatch.setattr(
        workflow_module,
        "run_discovery_pipeline",
        lambda *args, **kwargs: fake_discovery,
    )

    def fake_javascript(
        database,
        execution_id,
        source_evidence_path,
        *,
        actor,
        evidence_root,
    ):
        captured["execution_id"] = execution_id
        captured["source_evidence_path"] = source_evidence_path

        return type(
            "Result",
            (),
            {
                "evidence": type(
                    "Evidence",
                    (),
                    {
                        "evidence_id": "evidence-javascript",
                        "path": str(evidence_root / "javascript.json"),
                    },
                )()
            },
        )()

    monkeypatch.setattr(
        workflow_module,
        "run_tracked_javascript_intelligence",
        fake_javascript,
    )

    result = workflow_module.run_intelligence_pipeline(
        database,
        context,
        evidence_root=tmp_path / "workflow-evidence",
    )

    javascript_child = database.get_execution(
        result.javascript.execution_id
    )

    assert result.javascript.phase is OrchestrationPhase.JAVASCRIPT
    assert result.javascript.evidence_id == "evidence-javascript"
    assert captured["source_evidence_path"] == Path(
        fake_discovery.crawl.evidence_path
    )
    assert javascript_child.metadata["phase_code"] == "3E"
    assert javascript_child.metadata["previous_execution_id"] == (
        crawl_execution.execution_id
    )


def test_phase_3e_failure_marks_parent_failed(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch,
) -> None:
    import saarthi_ai.persistence.orchestration_workflow as workflow_module

    context = create_orchestration(
        database,
        assessment_name="Failing Intelligence Pipeline",
        target_url="https://example.com/",
        active_testing_allowed=True,
    )

    parent = database.get_execution(context.parent_execution_id)
    database.transition_execution(
        parent.execution_id,
        ExecutionState.RUNNING,
        actor="test",
        reason="Test orchestration started.",
    )

    fake_context = context.model_copy(
        update={"status": "running"}
    )

    fake_discovery = type(
        "DiscoveryResult",
        (),
        {
            "context": fake_context,
            "dns": object(),
            "subdomains": object(),
            "http_intelligence": object(),
            "crawl": OrchestrationPhaseResult(
                phase=OrchestrationPhase.CRAWL,
                execution_id="execution-crawl",
                evidence_id="evidence-crawl",
                evidence_path=str(tmp_path / "crawl.json"),
            ),
        },
    )()

    crawl_evidence_path = tmp_path / "crawl.json"
    crawl_evidence_path.write_text(
        json.dumps(
            {
                "domain": "example.com",
                "urls": [
                    {
                        "url": "https://example.com/app.js",
                        "is_javascript": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        workflow_module,
        "run_discovery_pipeline",
        lambda *args, **kwargs: fake_discovery,
    )

    def failing_javascript(*args, **kwargs):
        raise RuntimeError("simulated Phase 3E failure")

    monkeypatch.setattr(
        workflow_module,
        "run_tracked_javascript_intelligence",
        failing_javascript,
    )

    with pytest.raises(
        RuntimeError,
        match="simulated Phase 3E failure",
    ):
        workflow_module.run_intelligence_pipeline(
            database,
            context,
            evidence_root=tmp_path / "workflow-evidence",
        )

    parent = database.get_execution(
        context.parent_execution_id
    )

    assert parent.state is ExecutionState.FAILED
    assert "simulated Phase 3E failure" in (
        parent.failure_reason or ""
    )


def test_child_cannot_escalate_active_testing_permission(
    database: SaarthiDatabase,
) -> None:
    context = create_orchestration(
        database,
        assessment_name="Passive Assessment",
        target_url="https://example.com/",
        active_testing_allowed=False,
    )

    with pytest.raises(
        OrchestrationWorkflowError,
        match="cannot enable active testing",
    ):
        create_phase_execution(
            database,
            context,
            phase=OrchestrationPhase.CORS,
            phase_name="CORS Configuration",
            active_testing_allowed=True,
        )


def test_child_cannot_escalate_intrusive_testing_permission(
    database: SaarthiDatabase,
) -> None:
    context = create_orchestration(
        database,
        assessment_name="Active Non-Intrusive Assessment",
        target_url="https://example.com/",
        active_testing_allowed=True,
        intrusive_testing_allowed=False,
    )

    with pytest.raises(
        OrchestrationWorkflowError,
        match="cannot enable intrusive testing",
    ):
        create_phase_execution(
            database,
            context,
            phase=OrchestrationPhase.CORS,
            phase_name="Invalid Intrusive Child",
            active_testing_allowed=True,
            intrusive_testing_allowed=True,
        )


def test_intrusive_child_requires_active_testing(
    database: SaarthiDatabase,
) -> None:
    context = create_orchestration(
        database,
        assessment_name="Intrusive Assessment",
        target_url="https://example.com/",
        active_testing_allowed=True,
        intrusive_testing_allowed=True,
    )

    with pytest.raises(
        OrchestrationWorkflowError,
        match="requires active testing",
    ):
        create_phase_execution(
            database,
            context,
            phase=OrchestrationPhase.CORS,
            phase_name="Invalid Intrusive Child",
            active_testing_allowed=False,
            intrusive_testing_allowed=True,
        )


def test_assessment_pipeline_runs_phase_4a_and_completes_parent(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch,
) -> None:
    import saarthi_ai.persistence.orchestration_workflow as workflow_module

    context = create_orchestration(
        database,
        assessment_name="Complete Automated Assessment",
        target_url="https://example.com/",
        active_testing_allowed=True,
    )

    parent = database.get_execution(context.parent_execution_id)
    database.transition_execution(
        parent.execution_id,
        ExecutionState.RUNNING,
        actor="test",
        reason="Simulated intelligence pipeline started.",
    )

    running_context = context.model_copy(
        update={"status": "running"}
    )

    def phase_result(
        phase: OrchestrationPhase,
        name: str,
    ) -> OrchestrationPhaseResult:
        return OrchestrationPhaseResult(
            phase=phase,
            execution_id=f"execution-{name}",
            evidence_id=f"evidence-{name}",
            evidence_path=str(tmp_path / f"{name}.json"),
        )

    fake_intelligence = type(
        "IntelligenceResult",
        (),
        {
            "context": running_context,
            "dns": phase_result(OrchestrationPhase.DNS, "dns"),
            "subdomains": phase_result(
                OrchestrationPhase.SUBDOMAINS,
                "subdomains",
            ),
            "http_intelligence": phase_result(
                OrchestrationPhase.HTTP_INTELLIGENCE,
                "http",
            ),
            "crawl": phase_result(
                OrchestrationPhase.CRAWL,
                "crawl",
            ),
            "javascript": phase_result(
                OrchestrationPhase.JAVASCRIPT,
                "javascript",
            ),
        },
    )()

    monkeypatch.setattr(
        workflow_module,
        "run_intelligence_pipeline",
        lambda *args, **kwargs: fake_intelligence,
    )

    requests: list[DirectCheckRequest] = []

    def fake_direct_check(
        database,
        request,
        *,
        actor,
        evidence_root,
    ):
        requests.append(request)

        return type(
            "Result",
            (),
            {
                "evidence": type(
                    "Evidence",
                    (),
                    {
                        "evidence_id": (
                            f"evidence-{request.check_id}"
                        ),
                        "path": str(
                            evidence_root
                            / f"{request.check_id}.json"
                        ),
                    },
                )()
            },
        )()

    monkeypatch.setattr(
        workflow_module,
        "run_tracked_direct_check",
        fake_direct_check,
    )

    result = workflow_module.run_assessment_pipeline(
        database,
        context,
        evidence_root=tmp_path / "workflow-evidence",
        explicitly_approved=True,
    )

    parent = database.get_execution(context.parent_execution_id)
    headers_child = database.get_execution(
        result.security_headers.execution_id
    )
    cors_child = database.get_execution(
        result.cors.execution_id
    )

    assert parent.state is ExecutionState.COMPLETED
    assert result.context.status.value == "completed"
    assert result.calculated_status.value == "completed"
    assert result.cors.required is False

    parent_events = database.list_audit_events(
        parent.execution_id,
    )
    outcome_events = [
        event
        for event in parent_events
        if event.message.startswith(
            "[5C][orchestrator] Assessment outcome calculated:"
        )
    ]

    assert len(outcome_events) == 1
    assert (
        outcome_events[0].details["orchestration_status"]
        == "completed"
    )

    assert [request.check_id for request in requests] == [
        "security-headers",
        "cors-configuration",
    ]

    assert requests[0].active_testing is False
    assert requests[0].requested_requests == 1
    assert requests[1].active_testing is True
    assert requests[1].requested_requests == 3

    assert headers_child.metadata["phase_code"] == (
        "4A-security-headers"
    )
    assert headers_child.metadata["previous_execution_id"] == (
        fake_intelligence.javascript.execution_id
    )

    assert cors_child.metadata["phase_code"] == "4A-cors"
    assert cors_child.metadata["previous_execution_id"] == (
        headers_child.execution_id
    )


def test_assessment_pipeline_requires_explicit_approval(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    context = create_orchestration(
        database,
        assessment_name="Unapproved Assessment",
        target_url="https://example.com/",
        active_testing_allowed=True,
    )

    with pytest.raises(
        OrchestrationWorkflowError,
        match="Explicit operator approval",
    ):
        run_assessment_pipeline(
            database,
            context,
            evidence_root=tmp_path / "workflow-evidence",
            explicitly_approved=False,
        )

    parent = database.get_execution(context.parent_execution_id)
    assert parent.state is ExecutionState.PLANNED


def test_assessment_pipeline_requires_active_parent(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    context = create_orchestration(
        database,
        assessment_name="Passive Assessment",
        target_url="https://example.com/",
        active_testing_allowed=False,
    )

    with pytest.raises(
        OrchestrationWorkflowError,
        match="requires active testing approval",
    ):
        run_assessment_pipeline(
            database,
            context,
            evidence_root=tmp_path / "workflow-evidence",
            explicitly_approved=True,
        )

    parent = database.get_execution(context.parent_execution_id)
    assert parent.state is ExecutionState.PLANNED


def test_orchestration_phase_result_defaults_to_completed() -> None:
    result = OrchestrationPhaseResult(
        phase=OrchestrationPhase.DNS,
        execution_id="execution-dns",
        evidence_id="evidence-dns",
        evidence_path="evidence/dns.json",
    )

    assert result.completed is True
    assert result.skipped is False
    assert result.failed is False
    assert result.required is True
    assert result.outcome.value == "completed"


def test_orchestration_phase_result_can_represent_skipped_phase() -> None:
    from saarthi_ai.orchestration.models import (
        OrchestrationPhaseOutcome,
    )

    result = OrchestrationPhaseResult(
        phase=OrchestrationPhase.JAVASCRIPT,
        outcome=OrchestrationPhaseOutcome.SKIPPED,
        required=False,
        reason="No in-scope JavaScript assets were discovered.",
        metrics={
            "input_javascript_count": 0,
        },
    )

    assert result.completed is False
    assert result.skipped is True
    assert result.failed is False
    assert result.execution_id is None
    assert result.evidence_id is None
    assert result.evidence_path is None


def test_orchestration_status_supports_partial() -> None:
    from saarthi_ai.orchestration.models import OrchestrationStatus

    assert OrchestrationStatus.PARTIAL.value == "partial"


def test_calculate_orchestration_status_completed() -> None:
    from saarthi_ai.orchestration.models import (
        calculate_orchestration_status,
    )

    results = [
        OrchestrationPhaseResult(
            phase=OrchestrationPhase.DNS,
            execution_id="execution-dns",
            evidence_id="evidence-dns",
            evidence_path="dns.json",
        ),
        OrchestrationPhaseResult(
            phase=OrchestrationPhase.CRAWL,
            required=False,
            execution_id="execution-crawl",
            evidence_id="evidence-crawl",
            evidence_path="crawl.json",
        ),
    ]

    assert calculate_orchestration_status(results).value == "completed"


def test_calculate_orchestration_status_partial_for_optional_skip() -> None:
    from saarthi_ai.orchestration.models import (
        OrchestrationPhaseOutcome,
        calculate_orchestration_status,
    )

    results = [
        OrchestrationPhaseResult(
            phase=OrchestrationPhase.DNS,
            execution_id="execution-dns",
            evidence_id="evidence-dns",
            evidence_path="dns.json",
        ),
        OrchestrationPhaseResult(
            phase=OrchestrationPhase.JAVASCRIPT,
            outcome=OrchestrationPhaseOutcome.SKIPPED,
            required=False,
            reason="No JavaScript assets discovered.",
        ),
    ]

    assert calculate_orchestration_status(results).value == "partial"


def test_calculate_orchestration_status_failed_for_required_failure() -> None:
    from saarthi_ai.orchestration.models import (
        OrchestrationPhaseOutcome,
        calculate_orchestration_status,
    )

    results = [
        OrchestrationPhaseResult(
            phase=OrchestrationPhase.HTTP_INTELLIGENCE,
            outcome=OrchestrationPhaseOutcome.FAILED,
            required=True,
            error_summary="HTTP intelligence failed.",
        ),
    ]

    assert calculate_orchestration_status(results).value == "failed"


def test_calculate_orchestration_status_partial_for_optional_failure() -> None:
    from saarthi_ai.orchestration.models import (
        OrchestrationPhaseOutcome,
        calculate_orchestration_status,
    )

    results = [
        OrchestrationPhaseResult(
            phase=OrchestrationPhase.DNS,
            execution_id="execution-dns",
            evidence_id="evidence-dns",
            evidence_path="dns.json",
        ),
        OrchestrationPhaseResult(
            phase=OrchestrationPhase.CORS,
            outcome=OrchestrationPhaseOutcome.FAILED,
            required=False,
            error_summary="CORS validation failed.",
        ),
    ]

    assert calculate_orchestration_status(results).value == "partial"


def test_calculate_orchestration_status_fails_without_results() -> None:
    from saarthi_ai.orchestration.models import (
        calculate_orchestration_status,
    )

    assert calculate_orchestration_status([]).value == "failed"


def test_assessment_result_exposes_ordered_phase_results() -> None:
    from saarthi_ai.orchestration.models import (
        AssessmentPipelineResult,
        OrchestrationContext,
    )

    context = OrchestrationContext(
        orchestration_id="orchestration-test",
        parent_execution_id="execution-parent",
        target_url="https://example.com/",
        target_domain="example.com",
    )

    def result(
        phase: OrchestrationPhase,
        name: str,
    ) -> OrchestrationPhaseResult:
        return OrchestrationPhaseResult(
            phase=phase,
            execution_id=f"execution-{name}",
            evidence_id=f"evidence-{name}",
            evidence_path=f"{name}.json",
        )

    assessment = AssessmentPipelineResult(
        context=context,
        dns=result(OrchestrationPhase.DNS, "dns"),
        subdomains=result(
            OrchestrationPhase.SUBDOMAINS,
            "subdomains",
        ),
        http_intelligence=result(
            OrchestrationPhase.HTTP_INTELLIGENCE,
            "http",
        ),
        crawl=result(OrchestrationPhase.CRAWL, "crawl"),
        javascript=result(
            OrchestrationPhase.JAVASCRIPT,
            "javascript",
        ),
        security_headers=result(
            OrchestrationPhase.SECURITY_HEADERS,
            "headers",
        ),
        cors=result(OrchestrationPhase.CORS, "cors"),
    )

    assert [
        phase.phase
        for phase in assessment.phase_results
    ] == [
        OrchestrationPhase.DNS,
        OrchestrationPhase.SUBDOMAINS,
        OrchestrationPhase.HTTP_INTELLIGENCE,
        OrchestrationPhase.CRAWL,
        OrchestrationPhase.JAVASCRIPT,
        OrchestrationPhase.SECURITY_HEADERS,
        OrchestrationPhase.CORS,
    ]

    assert assessment.calculated_status.value == "completed"


def test_assessment_result_calculates_partial_status() -> None:
    from saarthi_ai.orchestration.models import (
        AssessmentPipelineResult,
        OrchestrationContext,
        OrchestrationPhaseOutcome,
    )

    context = OrchestrationContext(
        orchestration_id="orchestration-test",
        parent_execution_id="execution-parent",
        target_url="https://example.com/",
        target_domain="example.com",
    )

    def completed(
        phase: OrchestrationPhase,
        name: str,
    ) -> OrchestrationPhaseResult:
        return OrchestrationPhaseResult(
            phase=phase,
            execution_id=f"execution-{name}",
            evidence_id=f"evidence-{name}",
            evidence_path=f"{name}.json",
        )

    assessment = AssessmentPipelineResult(
        context=context,
        dns=completed(OrchestrationPhase.DNS, "dns"),
        subdomains=completed(
            OrchestrationPhase.SUBDOMAINS,
            "subdomains",
        ),
        http_intelligence=completed(
            OrchestrationPhase.HTTP_INTELLIGENCE,
            "http",
        ),
        crawl=completed(OrchestrationPhase.CRAWL, "crawl"),
        javascript=OrchestrationPhaseResult(
            phase=OrchestrationPhase.JAVASCRIPT,
            outcome=OrchestrationPhaseOutcome.SKIPPED,
            required=False,
            reason="No JavaScript assets discovered.",
        ),
        security_headers=completed(
            OrchestrationPhase.SECURITY_HEADERS,
            "headers",
        ),
        cors=completed(OrchestrationPhase.CORS, "cors"),
    )

    assert assessment.calculated_status.value == "partial"


def test_count_crawl_javascript_assets(
    tmp_path: Path,
) -> None:
    import json

    from saarthi_ai.persistence.orchestration_workflow import (
        count_crawl_javascript_assets,
    )

    evidence_path = tmp_path / "crawl.json"
    evidence_path.write_text(
        json.dumps(
            {
                "domain": "example.com",
                "urls": [
                    {
                        "url": "https://example.com/",
                        "is_javascript": False,
                    },
                    {
                        "url": "https://example.com/app.js",
                        "is_javascript": True,
                    },
                    {
                        "url": "https://example.com/vendor.js",
                        "is_javascript": True,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    assert count_crawl_javascript_assets(evidence_path) == 2


def test_count_crawl_javascript_assets_rejects_invalid_schema(
    tmp_path: Path,
) -> None:
    import json

    evidence_path = tmp_path / "crawl.json"
    evidence_path.write_text(
        json.dumps(
            {
                "domain": "example.com",
                "records": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        OrchestrationWorkflowError,
        match="does not contain a urls list",
    ):
        from saarthi_ai.persistence.orchestration_workflow import (
            count_crawl_javascript_assets,
        )

        count_crawl_javascript_assets(evidence_path)


def test_intelligence_pipeline_skips_javascript_when_none_found(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch,
) -> None:
    import json

    import saarthi_ai.persistence.orchestration_workflow as workflow_module

    context = create_orchestration(
        database,
        assessment_name="Assessment Without JavaScript",
        target_url="https://example.com/",
        active_testing_allowed=True,
    )

    parent = database.get_execution(context.parent_execution_id)
    database.transition_execution(
        parent.execution_id,
        ExecutionState.RUNNING,
        actor="test",
        reason="Test orchestration started.",
    )

    running_context = context.model_copy(
        update={"status": "running"}
    )

    crawl_evidence_path = tmp_path / "crawl.json"
    crawl_evidence_path.write_text(
        json.dumps(
            {
                "domain": "example.com",
                "urls": [
                    {
                        "url": "https://example.com/",
                        "is_javascript": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    crawl_execution = create_phase_execution(
        database,
        running_context,
        phase=OrchestrationPhase.CRAWL,
        phase_name="Crawling and URL Intelligence",
        active_testing_allowed=True,
    )

    fake_discovery = type(
        "DiscoveryResult",
        (),
        {
            "context": running_context,
            "dns": OrchestrationPhaseResult(
                phase=OrchestrationPhase.DNS,
                execution_id="execution-dns",
                evidence_id="evidence-dns",
                evidence_path="evidence/dns.json",
            ),
            "subdomains": OrchestrationPhaseResult(
                phase=OrchestrationPhase.SUBDOMAINS,
                execution_id="execution-subdomains",
                evidence_id="evidence-subdomains",
                evidence_path="evidence/subdomains.json",
            ),
            "http_intelligence": OrchestrationPhaseResult(
                phase=OrchestrationPhase.HTTP_INTELLIGENCE,
                execution_id="execution-http",
                evidence_id="evidence-http",
                evidence_path="evidence/http.json",
            ),
            "crawl": OrchestrationPhaseResult(
                phase=OrchestrationPhase.CRAWL,
                execution_id=crawl_execution.execution_id,
                evidence_id="evidence-crawl",
                evidence_path=str(crawl_evidence_path),
            ),
        },
    )()

    monkeypatch.setattr(
        workflow_module,
        "run_discovery_pipeline",
        lambda *args, **kwargs: fake_discovery,
    )

    javascript_called = False

    def unexpected_javascript_call(*args, **kwargs):
        nonlocal javascript_called
        javascript_called = True
        raise AssertionError(
            "JavaScript collector must not run without assets."
        )

    monkeypatch.setattr(
        workflow_module,
        "run_tracked_javascript_intelligence",
        unexpected_javascript_call,
    )

    result = workflow_module.run_intelligence_pipeline(
        database,
        context,
        evidence_root=tmp_path / "workflow-evidence",
    )

    assert javascript_called is False
    assert result.javascript.skipped is True
    assert result.javascript.required is False
    assert result.javascript.execution_id is None
    assert result.javascript.evidence_id is None
    assert result.javascript.evidence_path is None
    assert result.javascript.metrics == {
        "input_javascript_count": 0,
    }

    children = database.list_executions(limit=100)
    javascript_children = [
        child
        for child in children
        if child.metadata.get("phase_code") == "3E"
    ]

    assert javascript_children == []


def test_assessment_pipeline_marks_optional_skip_as_partial(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch,
) -> None:
    import saarthi_ai.persistence.orchestration_workflow as workflow_module
    from saarthi_ai.orchestration.models import (
        OrchestrationPhaseOutcome,
    )

    context = create_orchestration(
        database,
        assessment_name="Partial Automated Assessment",
        target_url="https://example.com/",
        active_testing_allowed=True,
    )

    parent = database.get_execution(context.parent_execution_id)
    database.transition_execution(
        parent.execution_id,
        ExecutionState.RUNNING,
        actor="test",
        reason="Simulated intelligence pipeline started.",
    )

    running_context = context.model_copy(
        update={"status": "running"}
    )

    def completed_phase(
        phase: OrchestrationPhase,
        name: str,
    ) -> OrchestrationPhaseResult:
        return OrchestrationPhaseResult(
            phase=phase,
            execution_id=f"execution-{name}",
            evidence_id=f"evidence-{name}",
            evidence_path=str(tmp_path / f"{name}.json"),
        )

    fake_intelligence = type(
        "IntelligenceResult",
        (),
        {
            "context": running_context,
            "dns": completed_phase(
                OrchestrationPhase.DNS,
                "dns",
            ),
            "subdomains": completed_phase(
                OrchestrationPhase.SUBDOMAINS,
                "subdomains",
            ),
            "http_intelligence": completed_phase(
                OrchestrationPhase.HTTP_INTELLIGENCE,
                "http",
            ),
            "crawl": completed_phase(
                OrchestrationPhase.CRAWL,
                "crawl",
            ),
            "javascript": OrchestrationPhaseResult(
                phase=OrchestrationPhase.JAVASCRIPT,
                outcome=OrchestrationPhaseOutcome.SKIPPED,
                required=False,
                reason="No JavaScript assets discovered.",
                metrics={
                    "input_javascript_count": 0,
                },
            ),
        },
    )()

    monkeypatch.setattr(
        workflow_module,
        "run_intelligence_pipeline",
        lambda *args, **kwargs: fake_intelligence,
    )

    def fake_direct_check(
        database,
        request,
        *,
        actor,
        evidence_root,
    ):
        return type(
            "Result",
            (),
            {
                "evidence": type(
                    "Evidence",
                    (),
                    {
                        "evidence_id": (
                            f"evidence-{request.check_id}"
                        ),
                        "path": str(
                            evidence_root
                            / f"{request.check_id}.json"
                        ),
                    },
                )()
            },
        )()

    monkeypatch.setattr(
        workflow_module,
        "run_tracked_direct_check",
        fake_direct_check,
    )

    result = workflow_module.run_assessment_pipeline(
        database,
        context,
        evidence_root=tmp_path / "workflow-evidence",
        explicitly_approved=True,
    )

    parent = database.get_execution(context.parent_execution_id)

    assert parent.state is ExecutionState.COMPLETED
    assert result.context.status.value == "partial"
    assert result.calculated_status.value == "partial"
    assert result.javascript.skipped is True

    parent_events = database.list_audit_events(
        parent.execution_id,
    )
    outcome_events = [
        event
        for event in parent_events
        if event.message
        == (
            "[5C][orchestrator] Assessment outcome "
            "calculated: partial"
        )
    ]

    assert len(outcome_events) == 1
    assert (
        outcome_events[0].details["orchestration_status"]
        == "partial"
    )
