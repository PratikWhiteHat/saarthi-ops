from __future__ import annotations

from pathlib import Path

import pytest

from saarthi_ai.orchestration.models import OrchestrationPhase
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import ExecutionState
from saarthi_ai.persistence.orchestration_workflow import (
    OrchestrationWorkflowError,
    create_orchestration,
    create_phase_execution,
    normalize_target_domain,
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
