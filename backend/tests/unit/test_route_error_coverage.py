"""Tests for route error handling paths to reach 95% coverage."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest
from application.dto import AuditListResponse
from application.queries import GetAuditEntriesQuery
from fastapi import FastAPI
from fastapi.testclient import TestClient
from presentation.api.routes.audit import router as audit_router


class TestAuditRouteErrorPaths:
    """Test error paths in audit routes."""

    @pytest.fixture
    def app(self) -> FastAPI:
        """Create FastAPI app with audit routes."""
        app = FastAPI()
        app.include_router(audit_router)
        return app

    @pytest.fixture
    def client(self, app: FastAPI) -> TestClient:
        """Create test client."""
        return TestClient(app)

    async def test_audit_query_general_error_handling(self, client: TestClient) -> None:
        """Test audit query endpoint handles general exceptions."""
        tenant_id = "550e8400-e29b-41d4-a716-446655440000"

        from presentation.api.routes import audit

        # Mock the query to raise general exception
        mock_query = MagicMock(spec=GetAuditEntriesQuery)
        mock_query.execute = AsyncMock(side_effect=Exception("Database connection failed"))

        original_dep = audit.get_audit_entries_query
        audit.get_audit_entries_query = lambda: mock_query

        try:
            response = client.post(
                "/api/v1/audit/query",
                json={
                    "tenant_id": tenant_id,
                    "page": 1,
                    "page_size": 50,
                },
            )

            # Should convert to 500
            assert response.status_code == 500
            assert "Failed to query audit entries" in response.json()["detail"]
        finally:
            audit.get_audit_entries_query = original_dep

    async def test_temporal_analytics_general_error(self, client: TestClient) -> None:
        """Test temporal analytics error handling."""
        tenant_id = "550e8400-e29b-41d4-a716-446655440000"
        start = (datetime.now(UTC) - timedelta(days=7)).isoformat()
        end = datetime.now(UTC).isoformat()

        from application.queries.temporal_analytics import TemporalAnalyticsQuery
        from presentation.api.routes import audit

        # Mock to raise error
        mock_analytics = MagicMock(spec=TemporalAnalyticsQuery)
        mock_analytics.execute = AsyncMock(side_effect=Exception("Analytics failed"))

        original_dep = audit.get_temporal_analytics_query
        audit.get_temporal_analytics_query = lambda: mock_analytics

        try:
            response = client.get(
                "/api/v1/audit/analytics",
                params={"start_time": start, "end_time": end},
                headers={"X-Tenant-ID": tenant_id},
            )

            # Should convert to 500
            assert response.status_code == 500
            assert "Failed to generate temporal analytics" in response.json()["detail"]
        finally:
            audit.get_temporal_analytics_query = original_dep

    async def test_export_csv_error_handling(self, client: TestClient) -> None:
        """Test export endpoint error handling."""
        tenant_id = "550e8400-e29b-41d4-a716-446655440000"

        from application.queries.audit_export import AuditExporter
        from presentation.api.routes import audit

        # Mock exporter to raise error
        mock_exporter = MagicMock(spec=AuditExporter)
        mock_exporter.export_to_csv = AsyncMock(side_effect=Exception("Export failed"))

        original_dep = audit.get_audit_exporter
        audit.get_audit_exporter = lambda: mock_exporter

        try:
            response = client.post(
                "/api/v1/audit/export",
                json={
                    "tenant_id": tenant_id,
                    "start_time": "2025-01-01T00:00:00Z",
                    "end_time": "2025-01-31T23:59:59Z",
                    "format": "csv",
                },
            )

            # Should convert to 500
            assert response.status_code == 500
            assert "Failed to export audit logs" in response.json()["detail"]
        finally:
            audit.get_audit_exporter = original_dep
