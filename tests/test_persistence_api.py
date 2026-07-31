from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from saarthi_ai.main import app
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.router import get_database


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    """Create an API client backed by an isolated SQLite database."""

    database = SaarthiDatabase(tmp_path / "api-test.db")
    database.initialize()

    app.dependency_overrides[get_database] = lambda: database

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


def execution_payload() -> dict[str, object]:
    """Return a valid authorized execution request."""

    return {
        "assessment_name": "Authorized Web VAPT",
        "plan_version": "0.1.0",
        "asset_types": ["web"],
        "targets": ["https://example.com/"],
        "authorization_confirmed": True,
        "active_testing_allowed": True,
        "intrusive_testing_allowed": False,
        "metadata": {
            "owner": "security-team",
        },
    }


def create_execution(client: TestClient) -> dict[str, object]:
    """Create and return one execution through the API."""

    response = client.post(
        "/v1/executions",
        json=execution_payload(),
    )

    assert response.status_code == 201
    return response.json()


def test_create_and_get_execution(client: TestClient) -> None:
    """An execution should be created and retrieved."""

    created = create_execution(client)
    execution_id = created["execution_id"]

    response = client.get(f"/v1/executions/{execution_id}")

    assert response.status_code == 200
    assert response.json()["state"] == "created"
    assert response.json()["assessment_name"] == "Authorized Web VAPT"


def test_unauthorized_execution_is_rejected(
    client: TestClient,
) -> None:
    """Execution creation must require confirmed authorization."""

    payload = execution_payload()
    payload["authorization_confirmed"] = False

    response = client.post(
        "/v1/executions",
        json=payload,
    )

    assert response.status_code == 400
    assert "confirmed authorization" in response.json()["detail"]


def test_execution_state_transition(client: TestClient) -> None:
    """A valid lifecycle transition should be persisted."""

    created = create_execution(client)
    execution_id = created["execution_id"]

    response = client.post(
        f"/v1/executions/{execution_id}/transition",
        json={
            "new_state": "validated",
            "actor": "scope-engine",
            "reason": "Authorized scope passed validation.",
        },
    )

    assert response.status_code == 200
    assert response.json()["state"] == "validated"


def test_invalid_transition_returns_conflict(
    client: TestClient,
) -> None:
    """Invalid skipped transitions should return HTTP 409."""

    created = create_execution(client)
    execution_id = created["execution_id"]

    response = client.post(
        f"/v1/executions/{execution_id}/transition",
        json={
            "new_state": "completed",
            "actor": "tester",
        },
    )

    assert response.status_code == 409
    assert "created -> completed" in response.json()["detail"]


def test_execution_audit_history(client: TestClient) -> None:
    """Creation and transitions should appear in audit history."""

    created = create_execution(client)
    execution_id = created["execution_id"]

    client.post(
        f"/v1/executions/{execution_id}/transition",
        json={
            "new_state": "validated",
            "actor": "scope-engine",
        },
    )

    response = client.get(f"/v1/executions/{execution_id}/audit")

    assert response.status_code == 200

    events = response.json()

    assert len(events) == 2
    assert events[0]["event_type"] == "execution_created"
    assert events[1]["event_type"] == "state_changed"


def test_add_and_list_evidence(client: TestClient) -> None:
    """Evidence should be linked to its execution."""

    created = create_execution(client)
    execution_id = created["execution_id"]

    response = client.post(
        f"/v1/executions/{execution_id}/evidence",
        json={
            "evidence_type": "http_metadata",
            "source": "internal-http-collector",
            "path": "evidence/http/result.json",
            "sha256": "a" * 64,
            "size_bytes": 1024,
            "content_type": "application/json",
            "step_id": "recon-001",
            "tool_name": "internal-http-collector",
            "metadata": {
                "status_code": 200,
            },
        },
    )

    assert response.status_code == 201

    list_response = client.get(f"/v1/executions/{execution_id}/evidence")

    assert list_response.status_code == 200

    items = list_response.json()

    assert len(items) == 1
    assert items[0]["evidence_type"] == "http_metadata"
    assert items[0]["step_id"] == "recon-001"


def test_list_executions(client: TestClient) -> None:
    """Execution history should return stored records."""

    create_execution(client)

    response = client.get("/v1/executions")

    assert response.status_code == 200
    assert len(response.json()) == 1


def test_missing_execution_returns_not_found(
    client: TestClient,
) -> None:
    """Unknown execution identifiers should return HTTP 404."""

    response = client.get("/v1/executions/execution-missing")

    assert response.status_code == 404


def test_tracked_http_endpoint_rejects_unknown_execution(
    client: TestClient,
) -> None:
    """Tracked collection should reject an unknown execution."""

    response = client.post(
        "/v1/executions/execution-missing/http-metadata",
        json={
            "assessment": {
                "name": "Authorized Web VAPT",
                "targets": [
                    {
                        "asset_type": "web",
                        "value": "https://example.com",
                    }
                ],
                "authorization_confirmed": True,
            },
            "target": "https://example.com",
        },
    )

    assert response.status_code == 404
