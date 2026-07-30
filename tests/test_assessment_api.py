from __future__ import annotations

from fastapi.testclient import TestClient

from saarthi_ai.main import app

client = TestClient(app)


def test_validate_authorized_web_assessment() -> None:
    """The API should accept and normalize an authorized web target."""

    response = client.post(
        "/v1/assessments/validate",
        json={
            "name": "Authorized Web VAPT",
            "targets": [
                {
                    "asset_type": "web",
                    "value": "https://Example.com",
                    "label": "Customer portal",
                }
            ],
            "authorization_confirmed": True,
            "allow_active_testing": True,
            "allow_intrusive_testing": False,
            "rate_limit_per_second": 3,
            "excluded_targets": [],
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["valid"] is True
    assert data["assessment_name"] == "Authorized Web VAPT"
    assert data["targets"][0]["asset_type"] == "web"
    assert data["targets"][0]["normalized_value"] == ("https://example.com/")
    assert data["permitted_execution_levels"] == [
        "passive",
        "active",
    ]
    assert data["rate_limit_per_second"] == 3


def test_validate_authorized_ip_assessment() -> None:
    """The API should accept a valid authorized IP target."""

    response = client.post(
        "/v1/assessments/validate",
        json={
            "name": "Authorized Network VAPT",
            "targets": [
                {
                    "asset_type": "ip",
                    "value": "192.0.2.10",
                }
            ],
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 200
    assert response.json()["targets"][0]["normalized_value"] == ("192.0.2.10")


def test_reject_unconfirmed_authorization() -> None:
    """The API must reject requests without authorization."""

    response = client.post(
        "/v1/assessments/validate",
        json={
            "name": "Unauthorized Assessment",
            "targets": [
                {
                    "asset_type": "web",
                    "value": "https://example.com",
                }
            ],
            "authorization_confirmed": False,
        },
    )

    assert response.status_code == 422


def test_reject_excluded_target() -> None:
    """The API must block explicitly excluded targets."""

    response = client.post(
        "/v1/assessments/validate",
        json={
            "name": "Scoped Web VAPT",
            "targets": [
                {
                    "asset_type": "web",
                    "value": "https://excluded.example.com",
                }
            ],
            "authorization_confirmed": True,
            "excluded_targets": [
                "https://excluded.example.com",
            ],
        },
    )

    assert response.status_code == 400
    assert "explicitly excluded" in response.json()["detail"]


def test_reject_invalid_ip_address() -> None:
    """The API must reject malformed IP targets."""

    response = client.post(
        "/v1/assessments/validate",
        json={
            "name": "Invalid Network Target",
            "targets": [
                {
                    "asset_type": "ip",
                    "value": "999.999.999.999",
                }
            ],
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 400
    assert "Invalid IP address" in response.json()["detail"]
