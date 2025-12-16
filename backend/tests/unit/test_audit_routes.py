"""Tests for audit API routes."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.testclient import TestClient as StarletteClient

from core.security import create_access_token
from presentation.api.routes.audit import router


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


@pytest.fixture
def auth_headers_factory():
    """Factory to produce auth headers with signed JWTs."""

    def _factory(tenant_id: UUID, user_id: UUID | None = None) -> dict[str, str]:
        actual_user_id = user_id or tenant_id
        token = create_access_token(
            {
                "sub": str(actual_user_id),
                "user_id": str(actual_user_id),
                "tenant_id": str(tenant_id),
            }
        )
        return {
            "Authorization": f"Bearer {token}",
            "X-Tenant-ID": str(tenant_id),
            "X-User-ID": str(actual_user_id),
        }

    return _factory


class TestTemporalAnalyticsEndpoint:
    """Tests for temporal analytics endpoint."""

    async def test_get_temporal_analytics_invalid_time_range(
        self,
        test_client: StarletteClient,
        valid_tenant_id: UUID,
        auth_headers_factory,
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
            headers=auth_headers_factory(valid_tenant_id),
        )

        # Verify
        assert response.status_code == 400
        assert "end_time must be after start_time" in response.json()["detail"]


class TestQueryEndpoint:
    """Tests for audit query endpoint."""

    async def test_query_audit_entries_validation_error(
        self,
        test_client: StarletteClient,
        valid_tenant_id: UUID,
        auth_headers_factory,
    ) -> None:
        """Test that audit query endpoint validates page parameters."""
        response = test_client.post(
            "/api/v1/audit/query",
            json={
                "tenant_id": str(valid_tenant_id),
                "page": 0,  # Invalid - must be >= 1
                "page_size": 50,
            },
            headers=auth_headers_factory(valid_tenant_id),
        )

        # FastAPI/Pydantic returns 422 for validation errors
        assert response.status_code == 422
        assert "detail" in response.json()

    async def test_query_audit_entries_page_size_validation(
        self,
        test_client: StarletteClient,
        valid_tenant_id: UUID,
        auth_headers_factory,
    ) -> None:
        """Test page_size validation."""
        response = test_client.post(
            "/api/v1/audit/query",
            json={
                "tenant_id": str(valid_tenant_id),
                "page": 1,
                "page_size": 2000,  # Invalid - max is 1000
            },
            headers=auth_headers_factory(valid_tenant_id),
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
        auth_headers_factory,
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
            headers=auth_headers_factory(valid_tenant_id),
        )

        # Pydantic validation error
        assert response.status_code == 422

    async def test_query_tenant_mismatch(
        self,
        test_client: StarletteClient,
        valid_tenant_id: UUID,
        auth_headers_factory,
    ) -> None:
        """Test that query endpoint rejects tenant ID mismatch."""
        other_tenant_id = uuid4()

        response = test_client.post(
            "/api/v1/audit/query",
            json={
                "tenant_id": str(other_tenant_id),  # Different from header
                "page": 1,
                "page_size": 50,
            },
            headers=auth_headers_factory(valid_tenant_id),
        )

        # Should return 403 Forbidden
        assert response.status_code == 403
        assert "Tenant ID mismatch" in response.json()["detail"]

    async def test_export_tenant_mismatch(
        self,
        test_client: StarletteClient,
        valid_tenant_id: UUID,
        auth_headers_factory,
    ) -> None:
        """Test that export endpoint rejects tenant ID mismatch."""
        other_tenant_id = uuid4()

        response = test_client.post(
            "/api/v1/audit/export",
            json={
                "tenant_id": str(other_tenant_id),  # Different from header
                "start_time": "2025-01-01T00:00:00Z",
                "end_time": "2025-01-31T23:59:59Z",
                "format": "csv",
            },
            headers=auth_headers_factory(valid_tenant_id),
        )

        # Should return 403 Forbidden
        assert response.status_code == 403
        assert "Tenant ID mismatch" in response.json()["detail"]

    async def test_export_json_tenant_mismatch(
        self,
        test_client: StarletteClient,
        valid_tenant_id: UUID,
        auth_headers_factory,
    ) -> None:
        """Test that export JSON endpoint also rejects tenant ID mismatch."""
        other_tenant_id = uuid4()

        response = test_client.post(
            "/api/v1/audit/export",
            json={
                "tenant_id": str(other_tenant_id),  # Different from header
                "start_time": "2025-01-01T00:00:00Z",
                "end_time": "2025-01-31T23:59:59Z",
                "format": "json",  # Test JSON format
            },
            headers=auth_headers_factory(valid_tenant_id),
        )

        # Should return 403 Forbidden
        assert response.status_code == 403
        assert "Tenant ID mismatch" in response.json()["detail"]


class TestAuditSuccessPaths:
    """Tests for successful audit operations to increase coverage."""

    @pytest.fixture
    def app(self) -> FastAPI:
        """Create FastAPI app."""
        app = FastAPI()
        app.include_router(router)
        return app

    @pytest.fixture
    def client(self, app: FastAPI) -> StarletteClient:
        """Create test client."""
        return TestClient(app)

    async def test_query_successful_execution(
        self, app: FastAPI, client: StarletteClient, valid_tenant_id: UUID, auth_headers_factory
    ) -> None:
        """Test successful query execution covers happy path."""
        from application.dto import AuditListResponse
        from application.queries.get_audit import GetAuditEntriesQuery
        from presentation.api.routes.audit import get_audit_entries_query

        # Mock successful query
        mock_query = MagicMock(spec=GetAuditEntriesQuery)
        mock_result = AuditListResponse(
            entries=[], total_count=0, page=1, page_size=50, has_more=False
        )
        mock_query.execute = AsyncMock(return_value=mock_result)

        app.dependency_overrides[get_audit_entries_query] = lambda: mock_query

        try:
            response = client.post(
                "/api/v1/audit/query",
                json={"tenant_id": str(valid_tenant_id), "page": 1, "page_size": 50},
                headers=auth_headers_factory(valid_tenant_id),
            )

            assert response.status_code == 200
            assert response.json()["total"] == 0
        finally:
            app.dependency_overrides.clear()

    async def test_query_value_error_handling(
        self, app: FastAPI, client: StarletteClient, valid_tenant_id: UUID, auth_headers_factory
    ) -> None:
        """Test query ValueError exception handling."""
        from application.queries.get_audit import GetAuditEntriesQuery
        from presentation.api.routes.audit import get_audit_entries_query

        # Mock query to raise ValueError
        mock_query = MagicMock(spec=GetAuditEntriesQuery)
        mock_query.execute = AsyncMock(side_effect=ValueError("Invalid page number"))

        app.dependency_overrides[get_audit_entries_query] = lambda: mock_query

        try:
            response = client.post(
                "/api/v1/audit/query",
                json={"tenant_id": str(valid_tenant_id), "page": 1, "page_size": 50},
                headers=auth_headers_factory(valid_tenant_id),
            )

            # ValueError should be converted to 400
            assert response.status_code == 400
            assert "Invalid page number" in response.json()["detail"]
        finally:
            app.dependency_overrides.clear()

    async def test_analytics_successful_execution(
        self, app: FastAPI, client: StarletteClient, valid_tenant_id: UUID, auth_headers_factory
    ) -> None:
        """Test successful analytics execution covers return path."""
        from application.queries.temporal_analytics import TemporalAnalyticsQuery, TemporalPattern
        from presentation.api.routes.audit import get_temporal_analytics_query

        # Mock successful analytics
        start = datetime.now(UTC) - timedelta(days=7)
        end = datetime.now(UTC)
        mock_pattern = TemporalPattern(
            tenant_id=valid_tenant_id,
            start_time=start,
            end_time=end,
            compliance_score=95.0,
        )
        mock_analytics = MagicMock(spec=TemporalAnalyticsQuery)
        mock_analytics.execute = AsyncMock(return_value=mock_pattern)

        app.dependency_overrides[get_temporal_analytics_query] = lambda: mock_analytics

        try:
            response = client.get(
                "/api/v1/audit/analytics",
                params={"start_time": start.isoformat(), "end_time": end.isoformat()},
                headers=auth_headers_factory(valid_tenant_id),
            )

            assert response.status_code == 200
            data = response.json()
            assert data["compliance_score"] == 95.0
        finally:
            app.dependency_overrides.clear()

    async def test_export_json_successful(
        self, app: FastAPI, client: StarletteClient, valid_tenant_id: UUID, auth_headers_factory
    ) -> None:
        """Test successful JSON export execution."""
        from application.queries.audit_export import AuditExporter
        from presentation.api.routes.audit import get_audit_exporter

        # Mock successful JSON export
        mock_exporter = MagicMock(spec=AuditExporter)
        mock_exporter.export_to_json = AsyncMock(return_value='{"entries": []}')

        app.dependency_overrides[get_audit_exporter] = lambda: mock_exporter

        try:
            response = client.post(
                "/api/v1/audit/export",
                json={
                    "tenant_id": str(valid_tenant_id),
                    "start_time": "2025-01-01T00:00:00Z",
                    "end_time": "2025-01-31T23:59:59Z",
                    "format": "json",
                },
                headers=auth_headers_factory(valid_tenant_id),
            )

            assert response.status_code == 200
            assert "application/json" in response.headers.get("content-type", "")
        finally:
            app.dependency_overrides.clear()
