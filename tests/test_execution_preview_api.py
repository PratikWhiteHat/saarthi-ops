from __future__ import annotations

from fastapi.testclient import TestClient

from saarthi_ai.main import app

client = TestClient(app)


def test_preview_passive_execution() -> None:
    """The API should preview a passive reconnaissance invocation."""

    response = client.post(
        "/v1/assessments/execution/preview",
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
                "allow_active_testing": True,
            },
            "step_id": "recon-001",
            "approval_granted": False,
            "dry_run": True,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "ready"
    assert data["selected_tool"] == "httpx"
    assert data["invocation"]["tool"] == "httpx"


def test_preview_unknown_step_is_rejected() -> None:
    """The API should reject an unknown assessment step."""

    response = client.post(
        "/v1/assessments/execution/preview",
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
            "step_id": "missing-step",
            "dry_run": True,
        },
    )

    assert response.status_code == 400
    assert "does not contain step" in response.json()["detail"]
