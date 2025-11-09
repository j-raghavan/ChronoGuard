"""Analytics API for ChronoGuard SDK.

This module provides methods for accessing temporal analytics and patterns.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from chronoguard_sdk.models import TemporalPattern

if TYPE_CHECKING:
    from httpx import AsyncClient, Client


class AnalyticsAPI:
    """Analytics API interface.

    Provides methods for accessing temporal analytics and pattern analysis.
    """

    def __init__(self, client: AsyncClient, base_url: str) -> None:
        """Initialize analytics API.

        Args:
            client: HTTP client instance
            base_url: Base URL for API endpoints
        """
        self._client = client
        self._base_url = base_url

    async def get_temporal_patterns(
        self,
        tenant_id: str,
        start_time: datetime,
        end_time: datetime,
    ) -> TemporalPattern:
        """Get temporal analytics for audit access patterns.

        Args:
            tenant_id: Tenant identifier
            start_time: Start of analysis period
            end_time: End of analysis period

        Returns:
            Temporal pattern analysis with hourly/daily distributions,
            anomalies, and compliance score

        Raises:
            ValidationError: If time range is invalid
            APIError: If the API request fails
        """
        params = {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
        }

        # Add tenant_id as header
        headers = {"X-Tenant-ID": tenant_id}

        response = await self._client.get(
            f"{self._base_url}/api/v1/audit/analytics",
            params=params,
            headers=headers,
        )
        response.raise_for_status()
        return TemporalPattern(**response.json())


class AnalyticsSyncAPI:
    """Synchronous analytics API interface.

    Provides synchronous methods for accessing temporal analytics and pattern analysis.
    """

    def __init__(self, client: Client, base_url: str) -> None:
        """Initialize analytics API.

        Args:
            client: HTTP client instance
            base_url: Base URL for API endpoints
        """
        self._client = client
        self._base_url = base_url

    def get_temporal_patterns(
        self,
        tenant_id: str,
        start_time: datetime,
        end_time: datetime,
    ) -> TemporalPattern:
        """Get temporal analytics for audit access patterns.

        Args:
            tenant_id: Tenant identifier
            start_time: Start of analysis period
            end_time: End of analysis period

        Returns:
            Temporal pattern analysis with hourly/daily distributions,
            anomalies, and compliance score

        Raises:
            ValidationError: If time range is invalid
            APIError: If the API request fails
        """
        params = {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
        }

        headers = {"X-Tenant-ID": tenant_id}

        response = self._client.get(
            f"{self._base_url}/api/v1/audit/analytics",
            params=params,
            headers=headers,
        )
        response.raise_for_status()
        return TemporalPattern(**response.json())
