"""Audit log API for ChronoGuard SDK.

This module provides methods for querying and exporting audit logs.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from chronoguard_sdk.models import AuditExportRequest, AuditListResponse, AuditQueryRequest

if TYPE_CHECKING:
    from httpx import AsyncClient, Client


class AuditAPI:
    """Audit log API interface.

    Provides methods for querying and exporting audit logs.
    """

    def __init__(self, client: AsyncClient, base_url: str) -> None:
        """Initialize audit API.

        Args:
            client: HTTP client instance
            base_url: Base URL for API endpoints
        """
        self._client = client
        self._base_url = base_url

    async def query(
        self,
        tenant_id: str,
        agent_id: str | None = None,
        domain: str | None = None,
        decision: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> AuditListResponse:
        """Query audit log entries with filtering and pagination.

        Args:
            tenant_id: Tenant identifier
            agent_id: Optional agent ID filter
            domain: Optional domain filter
            decision: Optional decision filter (allow, deny, block, etc.)
            start_time: Optional start time filter
            end_time: Optional end time filter
            page: Page number (default: 1)
            page_size: Items per page (default: 50, max: 1000)

        Returns:
            Paginated list of audit entries

        Raises:
            ValidationError: If query parameters are invalid
            APIError: If the API request fails
        """
        request = AuditQueryRequest(
            tenant_id=UUID(tenant_id) if isinstance(tenant_id, str) else tenant_id,
            agent_id=UUID(agent_id) if isinstance(agent_id, str) and agent_id else None,
            domain=domain,
            decision=decision,
            start_time=start_time,
            end_time=end_time,
            page=page,
            page_size=page_size,
        )

        response = await self._client.post(
            f"{self._base_url}/api/v1/audit/query",
            json=request.model_dump(mode="json", exclude_none=True),
        )
        response.raise_for_status()
        return AuditListResponse(**response.json())

    async def export(
        self,
        tenant_id: str,
        start_time: datetime,
        end_time: datetime,
        export_format: str = "csv",
        include_metadata: bool = True,
        pretty_json: bool = False,
    ) -> str:
        """Export audit log entries to CSV or JSON format.

        Args:
            tenant_id: Tenant identifier
            start_time: Export start time
            end_time: Export end time (max 90 days from start_time)
            export_format: Export format ("csv" or "json", default: "csv")
            include_metadata: Include metadata in export (default: True)
            pretty_json: Pretty-print JSON output (default: False)

        Returns:
            Exported data as string (CSV or JSON)

        Raises:
            ValidationError: If request parameters are invalid
            APIError: If the API request fails
        """
        request = AuditExportRequest(
            tenant_id=UUID(tenant_id) if isinstance(tenant_id, str) else tenant_id,
            start_time=start_time,
            end_time=end_time,
            format=export_format,
            include_metadata=include_metadata,
            pretty_json=pretty_json,
        )

        response = await self._client.post(
            f"{self._base_url}/api/v1/audit/export",
            json=request.model_dump(mode="json"),
        )
        response.raise_for_status()
        return response.text


class AuditSyncAPI:
    """Synchronous audit log API interface.

    Provides synchronous methods for querying and exporting audit logs.
    """

    def __init__(self, client: Client, base_url: str) -> None:
        """Initialize audit API.

        Args:
            client: HTTP client instance
            base_url: Base URL for API endpoints
        """
        self._client = client
        self._base_url = base_url

    def query(
        self,
        tenant_id: str,
        agent_id: str | None = None,
        domain: str | None = None,
        decision: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> AuditListResponse:
        """Query audit log entries with filtering and pagination.

        Args:
            tenant_id: Tenant identifier
            agent_id: Optional agent ID filter
            domain: Optional domain filter
            decision: Optional decision filter (allow, deny, block, etc.)
            start_time: Optional start time filter
            end_time: Optional end time filter
            page: Page number (default: 1)
            page_size: Items per page (default: 50, max: 1000)

        Returns:
            Paginated list of audit entries

        Raises:
            ValidationError: If query parameters are invalid
            APIError: If the API request fails
        """
        request = AuditQueryRequest(
            tenant_id=UUID(tenant_id) if isinstance(tenant_id, str) else tenant_id,
            agent_id=UUID(agent_id) if isinstance(agent_id, str) and agent_id else None,
            domain=domain,
            decision=decision,
            start_time=start_time,
            end_time=end_time,
            page=page,
            page_size=page_size,
        )

        response = self._client.post(
            f"{self._base_url}/api/v1/audit/query",
            json=request.model_dump(mode="json", exclude_none=True),
        )
        response.raise_for_status()
        return AuditListResponse(**response.json())

    def export(
        self,
        tenant_id: str,
        start_time: datetime,
        end_time: datetime,
        export_format: str = "csv",
        include_metadata: bool = True,
        pretty_json: bool = False,
    ) -> str:
        """Export audit log entries to CSV or JSON format.

        Args:
            tenant_id: Tenant identifier
            start_time: Export start time
            end_time: Export end time (max 90 days from start_time)
            export_format: Export format ("csv" or "json", default: "csv")
            include_metadata: Include metadata in export (default: True)
            pretty_json: Pretty-print JSON output (default: False)

        Returns:
            Exported data as string (CSV or JSON)

        Raises:
            ValidationError: If request parameters are invalid
            APIError: If the API request fails
        """
        request = AuditExportRequest(
            tenant_id=UUID(tenant_id) if isinstance(tenant_id, str) else tenant_id,
            start_time=start_time,
            end_time=end_time,
            format=export_format,
            include_metadata=include_metadata,
            pretty_json=pretty_json,
        )

        response = self._client.post(
            f"{self._base_url}/api/v1/audit/export",
            json=request.model_dump(mode="json"),
        )
        response.raise_for_status()
        return response.text
