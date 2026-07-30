from __future__ import annotations

from fastapi.testclient import TestClient

from saarthi_ai.main import app

client = TestClient(app)


def test_create_web_assessment_plan() -> None:
    """The API should create a structured web plan."""

    response = client.post(
        "/v1/assessments/plan",
        json={
            "name": "Authorized Web VAPT",
            "targets": [
                {
                    "asset_type": "web",
                    "value": "https://example.com",
                }
            ],
            "authorization_confirmed": True,
            "allow_active_testing": True,
            "allow_intrusive_testing": False,
        },
    )

    assert response.status_code == 200

    data = response.json()
    step_ids = {step["id"] for step in data["steps"]}

    assert data["plan_version"] == "0.1.0"
    assert "web-attack-surface-001" in step_ids
    assert "web-authorization-001" in step_ids
    assert "reporting-001" in step_ids


def test_plan_rejects_unsupported_ip_target() -> None:
    """The Web/API planner should reject an IP target."""

    response = client.post(
        "/v1/assessments/plan",
        json={
            "name": "Network VAPT",
            "targets": [
                {
                    "asset_type": "ip",
                    "value": "192.0.2.10",
                }
            ],
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 400
    assert "supports only web and API" in response.json()["detail"]
