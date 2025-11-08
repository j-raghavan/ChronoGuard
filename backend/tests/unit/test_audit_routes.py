"""Tests for audit API routes."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from presentation.api.routes.audit import router
from starlette.testclient import TestClient as StarletteClient


@pytest.fixture
def test_client() -> StarletteClient:
    """Create a test client for the audit router."""
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


@pytest.fixture
def valid_tenant_id() -> UUID:
    """Valid tenant ID for testing."""
    return UUID("550e8400-e29b-41d4-a716-446655440000")


class TestTemporalAnalyticsEndpoint:
    """Tests for temporal analytics endpoint."""

    async def test_get_temporal_analytics_invalid_time_range(
        self,
        test_client: StarletteClient,
        valid_tenant_id: UUID,
    ) -> None:
        """Test temporal analytics with invalid time range."""
        # Setup - end_time before start_time
        start_time = datetime.now(UTC)
        end_time = start_time - timedelta(days=1)

        # Execute
        response = test_client.get(
            "/api/v1/audit/analytics",
            params={
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
            },
            headers={"X-Tenant-ID": str(valid_tenant_id)},
        )

        # Verify
        assert response.status_code == 400
        assert "end_time must be after start_time" in response.json()["detail"]


class TestQueryEndpoint:
    """Tests for audit query endpoint."""

    async def test_query_audit_entries_validation_error(
        self,
        test_client: StarletteClient,
    ) -> None:
        """Test that audit query endpoint validates page parameters."""
        response = test_client.post(
            "/api/v1/audit/query",
            json={
                "page": 0,  # Invalid - must be >= 1
                "page_size": 50,
            },
        )

        # FastAPI/Pydantic returns 422 for validation errors
        assert response.status_code == 422
        assert "detail" in response.json()

    async def test_query_audit_entries_page_size_validation(
        self,
        test_client: StarletteClient,
        valid_tenant_id: UUID,
    ) -> None:
        """Test page_size validation."""
        response = test_client.post(
            "/api/v1/audit/query",
            json={
                "tenant_id": str(valid_tenant_id),
                "page": 1,
                "page_size": 2000,  # Invalid - max is 1000
            },
        )

        # FastAPI/Pydantic validation
        assert response.status_code == 422

    async def test_analytics_missing_tenant_header(
        self,
        test_client: StarletteClient,
    ) -> None:
        """Test analytics endpoint requires tenant header."""
        from datetime import datetime, timedelta

        start = datetime.now() - timedelta(days=7)
        end = datetime.now()

        response = test_client.get(
            "/api/v1/audit/analytics",
            params={
                "start_time": start.isoformat(),
                "end_time": end.isoformat(),
            },
            # No X-Tenant-ID header
        )

        assert response.status_code == 401

    async def test_export_invalid_time_range(
        self,
        test_client: StarletteClient,
        valid_tenant_id: UUID,
    ) -> None:
        """Test export with invalid time range."""
        response = test_client.post(
            "/api/v1/audit/export",
            json={
                "tenant_id": str(valid_tenant_id),
                "start_time": "2025-01-31T00:00:00Z",
                "end_time": "2025-01-01T00:00:00Z",  # Before start
                "format": "csv",
            },
        )

        # Pydantic validation error
        assert response.status_code == 422
