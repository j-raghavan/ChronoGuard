"""ChronoGuard SDK client.

This module provides the main client classes for interacting with the ChronoGuard API.
"""

from __future__ import annotations

from typing import Any

import httpx
from chronoguard_sdk.agents import AgentsAPI, AgentsSyncAPI
from chronoguard_sdk.analytics import AnalyticsAPI, AnalyticsSyncAPI
from chronoguard_sdk.audit import AuditAPI, AuditSyncAPI
from chronoguard_sdk.exceptions import (
    APIError,
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    NotFoundError,
    RateLimitError,
    ValidationError,
)
from chronoguard_sdk.policies import PoliciesAPI, PoliciesSyncAPI


class ChronoGuard:
    """Async ChronoGuard SDK client.

    Main client for interacting with the ChronoGuard API using async/await.

    Example:
        async with ChronoGuard(api_url="http://localhost:8000") as client:
            agents = await client.agents.list()
    """

    def __init__(
        self,
        api_url: str,
        tenant_id: str | None = None,
        user_id: str | None = None,
        timeout: float = 30.0,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Initialize ChronoGuard client.

        Args:
            api_url: Base URL for ChronoGuard API
            tenant_id: Optional default tenant ID (can be set via X-Tenant-ID header)
            user_id: Optional default user ID (can be set via X-User-ID header)
            timeout: Request timeout in seconds (default: 30.0)
            headers: Optional additional headers to include in all requests
        """
        self._api_url = api_url.rstrip("/")
        self._tenant_id = tenant_id
        self._user_id = user_id
        self._timeout = timeout

        # Build default headers
        default_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        if tenant_id:
            default_headers["X-Tenant-ID"] = tenant_id
        if user_id:
            default_headers["X-User-ID"] = user_id

        if headers:
            default_headers.update(headers)

        # Create HTTP client with event hooks for error handling
        self._http_client = httpx.AsyncClient(
            timeout=timeout,
            headers=default_headers,
            event_hooks={"response": [self._handle_response_errors]},
        )

        # Initialize API modules
        self.agents = AgentsAPI(self._http_client, self._api_url, tenant_id)
        self.policies = PoliciesAPI(self._http_client, self._api_url, tenant_id, user_id)
        self.audit = AuditAPI(self._http_client, self._api_url)
        self.analytics = AnalyticsAPI(self._http_client, self._api_url)

    async def _handle_response_errors(self, response: httpx.Response) -> None:
        """Handle HTTP response errors.

        Args:
            response: HTTP response object

        Raises:
            Various SDK exceptions based on status code
        """
        if response.is_success:
            return

        # Read response content first
        await response.aread()

        try:
            error_data = response.json()
        except Exception:
            error_data = {}

        status_code = response.status_code
        detail = error_data.get("detail", response.text or "Unknown error")

        if status_code == 400:
            raise ValidationError(detail, error_data.get("field_errors"))
        if status_code == 401:
            raise AuthenticationError(detail)
        if status_code == 403:
            raise AuthorizationError(detail)
        if status_code == 404:
            raise NotFoundError(detail)
        if status_code == 409:
            raise ConflictError(detail)
        if status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitError(
                detail,
                retry_after=int(retry_after) if retry_after else None,
            )
        if status_code >= 500:
            raise APIError(detail, status_code=status_code, response_data=error_data)
        raise APIError(detail, status_code=status_code, response_data=error_data)

    async def close(self) -> None:
        """Close the HTTP client and release resources."""
        await self._http_client.aclose()

    async def __aenter__(self) -> ChronoGuard:
        """Enter async context manager."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit async context manager."""
        await self.close()


class ChronoGuardSync:
    """Synchronous ChronoGuard SDK client.

    Main client for interacting with the ChronoGuard API using synchronous calls.

    Example:
        with ChronoGuardSync(api_url="http://localhost:8000") as client:
            agents = client.agents.list()
    """

    def __init__(
        self,
        api_url: str,
        tenant_id: str | None = None,
        user_id: str | None = None,
        timeout: float = 30.0,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Initialize ChronoGuard sync client.

        Args:
            api_url: Base URL for ChronoGuard API
            tenant_id: Optional default tenant ID (can be set via X-Tenant-ID header)
            user_id: Optional default user ID (can be set via X-User-ID header)
            timeout: Request timeout in seconds (default: 30.0)
            headers: Optional additional headers to include in all requests
        """
        self._api_url = api_url.rstrip("/")
        self._tenant_id = tenant_id
        self._user_id = user_id
        self._timeout = timeout

        # Build default headers
        default_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        if tenant_id:
            default_headers["X-Tenant-ID"] = tenant_id
        if user_id:
            default_headers["X-User-ID"] = user_id

        if headers:
            default_headers.update(headers)

        # Create HTTP client with event hooks for error handling
        self._http_client = httpx.Client(
            timeout=timeout,
            headers=default_headers,
            event_hooks={"response": [self._handle_response_errors]},
        )

        # Initialize API modules
        self.agents = AgentsSyncAPI(self._http_client, self._api_url, tenant_id)
        self.policies = PoliciesSyncAPI(self._http_client, self._api_url, tenant_id, user_id)
        self.audit = AuditSyncAPI(self._http_client, self._api_url)
        self.analytics = AnalyticsSyncAPI(self._http_client, self._api_url)

    def _handle_response_errors(self, response: httpx.Response) -> None:
        """Handle HTTP response errors.

        Args:
            response: HTTP response object

        Raises:
            Various SDK exceptions based on status code
        """
        if response.is_success:
            return

        # Read response content first
        response.read()

        try:
            error_data = response.json()
        except Exception:
            error_data = {}

        status_code = response.status_code
        detail = error_data.get("detail", response.text or "Unknown error")

        if status_code == 400:
            raise ValidationError(detail, error_data.get("field_errors"))
        if status_code == 401:
            raise AuthenticationError(detail)
        if status_code == 403:
            raise AuthorizationError(detail)
        if status_code == 404:
            raise NotFoundError(detail)
        if status_code == 409:
            raise ConflictError(detail)
        if status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitError(
                detail,
                retry_after=int(retry_after) if retry_after else None,
            )
        if status_code >= 500:
            raise APIError(detail, status_code=status_code, response_data=error_data)
        raise APIError(detail, status_code=status_code, response_data=error_data)

    def close(self) -> None:
        """Close the HTTP client and release resources."""
        self._http_client.close()

    def __enter__(self) -> ChronoGuardSync:
        """Enter context manager."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit context manager."""
        self.close()
