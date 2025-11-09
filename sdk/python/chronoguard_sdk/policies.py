"""Policy management API for ChronoGuard SDK.

This module provides methods for managing policies through the ChronoGuard API.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from chronoguard_sdk.models import (
    CreatePolicyRequest,
    Policy,
    PolicyListResponse,
    UpdatePolicyRequest,
)

if TYPE_CHECKING:
    from httpx import AsyncClient, Client


class PoliciesAPI:
    """Policy management API interface.

    Provides methods for creating, reading, updating, deleting, and listing policies.
    """

    def __init__(
        self,
        client: AsyncClient,
        base_url: str,
        tenant_id: str | None = None,
        user_id: str | None = None,
    ) -> None:
        """Initialize policies API.

        Args:
            client: HTTP client instance
            base_url: Base URL for API endpoints
            tenant_id: Optional default tenant ID
            user_id: Optional default user ID
        """
        self._client = client
        self._base_url = base_url
        self._tenant_id = tenant_id
        self._user_id = user_id

    async def list(
        self,
        page: int = 1,
        page_size: int = 50,
        status_filter: str | None = None,
    ) -> PolicyListResponse:
        """List all policies for the tenant.

        Args:
            page: Page number (default: 1)
            page_size: Items per page (default: 50, max: 1000)
            status_filter: Optional status filter (e.g., "active", "inactive")

        Returns:
            Paginated list of policies

        Raises:
            ValidationError: If pagination parameters are invalid
            APIError: If the API request fails
        """
        params: dict[str, int | str] = {"page": page, "page_size": page_size}
        if status_filter:
            params["status_filter"] = status_filter

        response = await self._client.get(f"{self._base_url}/api/v1/policies/", params=params)
        response.raise_for_status()
        return PolicyListResponse(**response.json())

    async def get(self, policy_id: str) -> Policy:
        """Retrieve a policy by ID.

        Args:
            policy_id: Policy identifier

        Returns:
            Policy details

        Raises:
            NotFoundError: If policy not found
            APIError: If the API request fails
        """
        response = await self._client.get(f"{self._base_url}/api/v1/policies/{policy_id}")
        response.raise_for_status()
        return Policy(**response.json())

    async def create(
        self,
        name: str,
        description: str,
        priority: int = 500,
        allowed_domains: list[str] | None = None,
        blocked_domains: list[str] | None = None,
        metadata: dict[str, str] | None = None,
    ) -> Policy:
        """Create a new policy.

        Args:
            name: Policy name (3-100 characters)
            description: Policy description (1-500 characters)
            priority: Priority value (1-1000, default: 500)
            allowed_domains: Optional list of allowed domains
            blocked_domains: Optional list of blocked domains
            metadata: Optional metadata dictionary

        Returns:
            Created policy details

        Raises:
            ValidationError: If validation fails
            ConflictError: If duplicate policy exists
            APIError: If the API request fails
        """
        request = CreatePolicyRequest(
            name=name,
            description=description,
            priority=priority,
            allowed_domains=allowed_domains or [],
            blocked_domains=blocked_domains or [],
            metadata=metadata or {},
        )

        response = await self._client.post(
            f"{self._base_url}/api/v1/policies/",
            json=request.model_dump(mode="json"),
        )
        response.raise_for_status()
        return Policy(**response.json())

    async def update(
        self,
        policy_id: str,
        name: str | None = None,
        description: str | None = None,
        priority: int | None = None,
        allowed_domains: list[str] | None = None,
        blocked_domains: list[str] | None = None,
        metadata: dict[str, str] | None = None,
    ) -> Policy:
        """Update an existing policy.

        Args:
            policy_id: Policy identifier
            name: Optional new policy name (3-100 characters)
            description: Optional new description (1-500 characters)
            priority: Optional new priority value (1-1000)
            allowed_domains: Optional new list of allowed domains
            blocked_domains: Optional new list of blocked domains
            metadata: Optional new metadata dictionary

        Returns:
            Updated policy details

        Raises:
            NotFoundError: If policy not found
            ValidationError: If validation fails
            APIError: If the API request fails
        """
        request = UpdatePolicyRequest(
            name=name,
            description=description,
            priority=priority,
            allowed_domains=allowed_domains,
            blocked_domains=blocked_domains,
            metadata=metadata,
        )

        request_data = request.model_dump(mode="json", exclude_none=True)

        response = await self._client.put(
            f"{self._base_url}/api/v1/policies/{policy_id}",
            json=request_data,
        )
        response.raise_for_status()
        return Policy(**response.json())

    async def delete(self, policy_id: str) -> bool:
        """Delete a policy.

        Args:
            policy_id: Policy identifier

        Returns:
            True if deletion was successful

        Raises:
            NotFoundError: If policy not found
            APIError: If the API request fails
        """
        response = await self._client.delete(f"{self._base_url}/api/v1/policies/{policy_id}")
        response.raise_for_status()
        return response.status_code == 204


class PoliciesSyncAPI:
    """Synchronous policy management API interface.

    Provides synchronous methods for creating, reading, updating, deleting, and listing policies.
    """

    def __init__(
        self,
        client: Client,
        base_url: str,
        tenant_id: str | None = None,
        user_id: str | None = None,
    ) -> None:
        """Initialize policies API.

        Args:
            client: HTTP client instance
            base_url: Base URL for API endpoints
            tenant_id: Optional default tenant ID
            user_id: Optional default user ID
        """
        self._client = client
        self._base_url = base_url
        self._tenant_id = tenant_id
        self._user_id = user_id

    def list(
        self,
        page: int = 1,
        page_size: int = 50,
        status_filter: str | None = None,
    ) -> PolicyListResponse:
        """List all policies for the tenant.

        Args:
            page: Page number (default: 1)
            page_size: Items per page (default: 50, max: 1000)
            status_filter: Optional status filter (e.g., "active", "inactive")

        Returns:
            Paginated list of policies

        Raises:
            ValidationError: If pagination parameters are invalid
            APIError: If the API request fails
        """
        params: dict[str, int | str] = {"page": page, "page_size": page_size}
        if status_filter:
            params["status_filter"] = status_filter

        response = self._client.get(f"{self._base_url}/api/v1/policies/", params=params)
        response.raise_for_status()
        return PolicyListResponse(**response.json())

    def get(self, policy_id: str) -> Policy:
        """Retrieve a policy by ID.

        Args:
            policy_id: Policy identifier

        Returns:
            Policy details

        Raises:
            NotFoundError: If policy not found
            APIError: If the API request fails
        """
        response = self._client.get(f"{self._base_url}/api/v1/policies/{policy_id}")
        response.raise_for_status()
        return Policy(**response.json())

    def create(
        self,
        name: str,
        description: str,
        priority: int = 500,
        allowed_domains: list[str] | None = None,
        blocked_domains: list[str] | None = None,
        metadata: dict[str, str] | None = None,
    ) -> Policy:
        """Create a new policy.

        Args:
            name: Policy name (3-100 characters)
            description: Policy description (1-500 characters)
            priority: Priority value (1-1000, default: 500)
            allowed_domains: Optional list of allowed domains
            blocked_domains: Optional list of blocked domains
            metadata: Optional metadata dictionary

        Returns:
            Created policy details

        Raises:
            ValidationError: If validation fails
            ConflictError: If duplicate policy exists
            APIError: If the API request fails
        """
        request = CreatePolicyRequest(
            name=name,
            description=description,
            priority=priority,
            allowed_domains=allowed_domains or [],
            blocked_domains=blocked_domains or [],
            metadata=metadata or {},
        )

        response = self._client.post(
            f"{self._base_url}/api/v1/policies/",
            json=request.model_dump(mode="json"),
        )
        response.raise_for_status()
        return Policy(**response.json())

    def update(
        self,
        policy_id: str,
        name: str | None = None,
        description: str | None = None,
        priority: int | None = None,
        allowed_domains: list[str] | None = None,
        blocked_domains: list[str] | None = None,
        metadata: dict[str, str] | None = None,
    ) -> Policy:
        """Update an existing policy.

        Args:
            policy_id: Policy identifier
            name: Optional new policy name (3-100 characters)
            description: Optional new description (1-500 characters)
            priority: Optional new priority value (1-1000)
            allowed_domains: Optional new list of allowed domains
            blocked_domains: Optional new list of blocked domains
            metadata: Optional new metadata dictionary

        Returns:
            Updated policy details

        Raises:
            NotFoundError: If policy not found
            ValidationError: If validation fails
            APIError: If the API request fails
        """
        request = UpdatePolicyRequest(
            name=name,
            description=description,
            priority=priority,
            allowed_domains=allowed_domains,
            blocked_domains=blocked_domains,
            metadata=metadata,
        )

        request_data = request.model_dump(mode="json", exclude_none=True)

        response = self._client.put(
            f"{self._base_url}/api/v1/policies/{policy_id}",
            json=request_data,
        )
        response.raise_for_status()
        return Policy(**response.json())

    def delete(self, policy_id: str) -> bool:
        """Delete a policy.

        Args:
            policy_id: Policy identifier

        Returns:
            True if deletion was successful

        Raises:
            NotFoundError: If policy not found
            APIError: If the API request fails
        """
        response = self._client.delete(f"{self._base_url}/api/v1/policies/{policy_id}")
        response.raise_for_status()
        return response.status_code == 204
