"""Tests for audit API module."""

from datetime import datetime, timedelta

import pytest
import respx
from chronoguard_sdk import ChronoGuard, ChronoGuardSync
from chronoguard_sdk.exceptions import ValidationError
from chronoguard_sdk.models import AuditListResponse
from httpx import Response


class TestAuditAPI:
    """Tests for async audit API."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_query_audit_entries(self, base_url, tenant_id, sample_audit_entry):
        """Test querying audit entries."""
        response_data = {
            "entries": [sample_audit_entry.model_dump(mode="json")],
            "total_count": 1,
            "page": 1,
            "page_size": 50,
            "has_more": False,
        }

        respx.post(f"{base_url}/api/v1/audit/query").mock(
            return_value=Response(200, json=response_data)
        )

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.audit.query(tenant_id=tenant_id)

            assert isinstance(result, AuditListResponse)
            assert len(result.entries) == 1
            assert result.total_count == 1
            assert result.has_more is False

    @pytest.mark.asyncio
    @respx.mock
    async def test_query_audit_with_filters(self, base_url, tenant_id, agent_id, sample_audit_entry):
        """Test querying audit with filters."""
        response_data = {
            "entries": [sample_audit_entry.model_dump(mode="json")],
            "total_count": 1,
            "page": 1,
            "page_size": 50,
            "has_more": False,
        }

        respx.post(f"{base_url}/api/v1/audit/query").mock(
            return_value=Response(200, json=response_data)
        )

        now = datetime.utcnow()
        start_time = now - timedelta(days=7)

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.audit.query(
                tenant_id=tenant_id,
                agent_id=agent_id,
                domain="example.com",
                decision="allow",
                start_time=start_time,
                end_time=now,
                page=1,
                page_size=50,
            )

            assert isinstance(result, AuditListResponse)

    @pytest.mark.asyncio
    @respx.mock
    async def test_query_audit_pagination(self, base_url, tenant_id, sample_audit_entry):
        """Test querying audit with pagination."""
        response_data = {
            "entries": [sample_audit_entry.model_dump(mode="json")],
            "total_count": 100,
            "page": 2,
            "page_size": 25,
            "has_more": True,
        }

        respx.post(f"{base_url}/api/v1/audit/query").mock(
            return_value=Response(200, json=response_data)
        )

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.audit.query(
                tenant_id=tenant_id,
                page=2,
                page_size=25,
            )

            assert result.page == 2
            assert result.page_size == 25
            assert result.has_more is True

    @pytest.mark.asyncio
    @respx.mock
    async def test_export_audit_csv(self, base_url, tenant_id):
        """Test exporting audit logs to CSV."""
        csv_content = "timestamp,agent_id,domain,decision\n2025-01-01,123,example.com,allow"

        respx.post(f"{base_url}/api/v1/audit/export").mock(
            return_value=Response(200, text=csv_content)
        )

        now = datetime.utcnow()
        start_time = now - timedelta(days=7)

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.audit.export(
                tenant_id=tenant_id,
                start_time=start_time,
                end_time=now,
                export_format="csv",
            )

            assert isinstance(result, str)
            assert "timestamp" in result
            assert "example.com" in result

    @pytest.mark.asyncio
    @respx.mock
    async def test_export_audit_json(self, base_url, tenant_id):
        """Test exporting audit logs to JSON."""
        json_content = '{"entries": [{"domain": "example.com"}]}'

        respx.post(f"{base_url}/api/v1/audit/export").mock(
            return_value=Response(200, text=json_content)
        )

        now = datetime.utcnow()
        start_time = now - timedelta(days=7)

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.audit.export(
                tenant_id=tenant_id,
                start_time=start_time,
                end_time=now,
                export_format="json",
                pretty_json=True,
            )

            assert isinstance(result, str)
            assert "example.com" in result

    @pytest.mark.asyncio
    async def test_export_invalid_time_range(self, base_url, tenant_id):
        """Test exporting with invalid time range."""
        from pydantic import ValidationError as PydanticValidationError

        now = datetime.utcnow()
        start_time = now
        end_time = now - timedelta(days=7)  # End before start

        async with ChronoGuard(api_url=base_url) as client:
            with pytest.raises(PydanticValidationError):
                await client.audit.export(
                    tenant_id=tenant_id,
                    start_time=start_time,
                    end_time=end_time,
                )

    @pytest.mark.asyncio
    async def test_export_too_large_range(self, base_url, tenant_id):
        """Test exporting with too large time range."""
        from pydantic import ValidationError as PydanticValidationError

        now = datetime.utcnow()
        start_time = now - timedelta(days=100)  # Over 90 day limit

        async with ChronoGuard(api_url=base_url) as client:
            with pytest.raises(PydanticValidationError):
                await client.audit.export(
                    tenant_id=tenant_id,
                    start_time=start_time,
                    end_time=now,
                )


class TestAuditSyncAPI:
    """Tests for sync audit API."""

    @respx.mock
    def test_sync_query_audit(self, base_url, tenant_id, sample_audit_entry):
        """Test sync querying audit entries."""
        response_data = {
            "entries": [sample_audit_entry.model_dump(mode="json")],
            "total_count": 1,
            "page": 1,
            "page_size": 50,
            "has_more": False,
        }

        respx.post(f"{base_url}/api/v1/audit/query").mock(
            return_value=Response(200, json=response_data)
        )

        with ChronoGuardSync(api_url=base_url) as client:
            result = client.audit.query(tenant_id=tenant_id)

            assert isinstance(result, AuditListResponse)

    @respx.mock
    def test_sync_export_audit(self, base_url, tenant_id):
        """Test sync exporting audit logs."""
        csv_content = "timestamp,domain\n2025-01-01,example.com"

        respx.post(f"{base_url}/api/v1/audit/export").mock(
            return_value=Response(200, text=csv_content)
        )

        now = datetime.utcnow()
        start_time = now - timedelta(days=7)

        with ChronoGuardSync(api_url=base_url) as client:
            result = client.audit.export(
                tenant_id=tenant_id,
                start_time=start_time,
                end_time=now,
            )

            assert isinstance(result, str)
