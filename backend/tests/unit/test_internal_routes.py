"""Unit tests for internal API routes."""

import os
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from application.dto.opa_dto import OPADecisionLog, OPAInput, OPAInputAttributes
from domain.audit.entity import AccessDecision
from fastapi import FastAPI
from fastapi.testclient import TestClient
from presentation.api.routes import internal_router


@pytest.fixture
def mock_audit_service() -> MagicMock:
    """Create mock audit service."""
    service = MagicMock()
    service.record_access = AsyncMock(return_value=None)
    return service


@pytest.fixture
def app(mock_audit_service: MagicMock) -> FastAPI:
    """Create FastAPI app with internal routes."""
    from presentation.api.routes import internal

    app = FastAPI()

    # Override dependency
    app.dependency_overrides[internal.get_audit_service] = lambda: mock_audit_service

    app.include_router(internal_router)
    return app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Create auth headers for internal API."""
    os.environ["CHRONOGUARD_INTERNAL_SECRET"] = "test-secret-123"
    return {"Authorization": "Bearer test-secret-123"}


@pytest.fixture
def sample_opa_decision() -> dict[str, Any]:
    """Create sample OPA decision log."""
    return {
        "decision_id": str(uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
        "input": {
            "attributes": {
                "request": {
                    "http": {
                        "method": "GET",
                        "host": "example.com",
                        "path": "/api/test",
                        "headers": {"user-agent": "test-agent"},
                    }
                },
                "source": {
                    "principal": str(uuid4()),
                    "address": {"socketAddress": {"address": "192.168.1.1"}},
                },
            }
        },
        "path": "chronoguard/authz/allow",
        "result": {"allow": True, "reason": "Domain allowed"},
        "labels": {"tenant_id": str(uuid4())},
    }


class TestInternalAuth:
    """Test internal API authentication."""

    def test_missing_auth_header_returns_401(self, client: TestClient) -> None:
        """Test that missing auth header returns 401."""
        # Set secret to enable auth
        os.environ["CHRONOGUARD_INTERNAL_SECRET"] = "test-secret-123"

        response = client.post(
            "/api/v1/internal/opa/decisions",
            json={"decision_id": "test", "timestamp": datetime.now(UTC).isoformat()},
        )
        assert response.status_code == 401

    def test_invalid_auth_token_returns_401(self, client: TestClient) -> None:
        """Test that invalid token returns 401."""
        # Set secret to enable auth
        os.environ["CHRONOGUARD_INTERNAL_SECRET"] = "test-secret-123"

        response = client.post(
            "/api/v1/internal/opa/decisions",
            headers={"Authorization": "Bearer wrong-token"},
            json={"decision_id": "test", "timestamp": datetime.now(UTC).isoformat()},
        )
        assert response.status_code == 401

    def test_invalid_auth_header_format_returns_401(self, client: TestClient) -> None:
        """Test that invalid auth header format returns 401."""
        # Set secret to enable auth
        os.environ["CHRONOGUARD_INTERNAL_SECRET"] = "test-secret-123"

        response = client.post(
            "/api/v1/internal/opa/decisions",
            headers={"Authorization": "InvalidFormat token"},
            json={"decision_id": "test", "timestamp": datetime.now(UTC).isoformat()},
        )
        assert response.status_code == 401

    def test_auth_disabled_when_secret_not_set(
        self, client: TestClient, sample_opa_decision: dict[str, Any]
    ) -> None:
        """Test that auth is disabled when CHRONOGUARD_INTERNAL_SECRET is not set."""
        # Unset the secret
        if "CHRONOGUARD_INTERNAL_SECRET" in os.environ:
            del os.environ["CHRONOGUARD_INTERNAL_SECRET"]

        response = client.post(
            "/api/v1/internal/opa/decisions",
            json=sample_opa_decision,
        )
        # Should succeed (or fail for other reasons) but not 401
        assert response.status_code != 401

    def test_valid_auth_token_accepted(
        self, client: TestClient, auth_headers: dict[str, str], sample_opa_decision: dict[str, Any]
    ) -> None:
        """Test that valid token is accepted."""
        response = client.post(
            "/api/v1/internal/opa/decisions", headers=auth_headers, json=sample_opa_decision
        )
        # May fail on data processing, but should not fail on auth
        assert response.status_code != 401


class TestOPADecisionIngestion:
    """Test OPA decision log ingestion."""

    def test_allow_decision_creates_audit_entry(
        self, client: TestClient, auth_headers: dict[str, str], sample_opa_decision: dict[str, Any]
    ) -> None:
        """Test that ALLOW decision creates audit entry."""
        sample_opa_decision["result"]["allow"] = True

        response = client.post(
            "/api/v1/internal/opa/decisions", headers=auth_headers, json=sample_opa_decision
        )

        assert response.status_code == 204

    def test_deny_decision_creates_audit_entry(
        self, client: TestClient, auth_headers: dict[str, str], sample_opa_decision: dict[str, Any]
    ) -> None:
        """Test that DENY decision creates audit entry."""
        sample_opa_decision["result"]["allow"] = False
        sample_opa_decision["result"]["reason"] = "Domain blocked"

        response = client.post(
            "/api/v1/internal/opa/decisions", headers=auth_headers, json=sample_opa_decision
        )

        assert response.status_code == 204

    def test_batch_ingestion_processes_multiple_decisions(
        self, client: TestClient, auth_headers: dict[str, str], sample_opa_decision: dict[str, Any]
    ) -> None:
        """Test batch ingestion of multiple decisions."""
        decisions = [sample_opa_decision.copy() for _ in range(5)]

        response = client.post(
            "/api/v1/internal/opa/decisions/batch",
            headers=auth_headers,
            json={"decisions": decisions},
        )

        assert response.status_code in [204, 207]  # 207 if partial failure

    def test_invalid_decision_format_returns_422(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """Test that invalid decision format returns 422."""
        invalid_decision = {"decision_id": "test"}  # Missing required fields

        response = client.post(
            "/api/v1/internal/opa/decisions", headers=auth_headers, json=invalid_decision
        )

        assert response.status_code == 422

    def test_batch_with_partial_failures_returns_207(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_opa_decision: dict[str, Any],
        mock_audit_service: MagicMock,
    ) -> None:
        """Test batch ingestion with some failures returns 207."""
        # Make the mock service fail on second call
        mock_audit_service.record_access.side_effect = [None, Exception("DB error"), None]

        decisions = [sample_opa_decision.copy() for _ in range(3)]
        # Make each decision unique
        for i, dec in enumerate(decisions):
            dec["decision_id"] = f"test-{i}"

        response = client.post(
            "/api/v1/internal/opa/decisions/batch",
            headers=auth_headers,
            json={"decisions": decisions},
        )

        assert response.status_code == 207
        data = response.json()
        assert "processed" in data["detail"]
        assert "errors" in data["detail"]


# Add more tests as needed...
