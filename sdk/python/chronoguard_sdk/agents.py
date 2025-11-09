"""Agent management API for ChronoGuard SDK.

This module provides methods for managing agents through the ChronoGuard API.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from chronoguard_sdk.models import Agent, AgentListResponse, CreateAgentRequest, UpdateAgentRequest

if TYPE_CHECKING:
    from httpx import AsyncClient, Client


class AgentsAPI:
    """Agent management API interface.

    Provides methods for creating, reading, updating, and listing agents.
    """

    def __init__(self, client: AsyncClient, base_url: str, tenant_id: str | None = None) -> None:
        """Initialize agents API.

        Args:
            client: HTTP client instance
            base_url: Base URL for API endpoints
            tenant_id: Optional default tenant ID
        """
        self._client = client
        self._base_url = base_url
        self._tenant_id = tenant_id

    async def list(
        self,
        page: int = 1,
        page_size: int = 50,
        status_filter: str | None = None,
    ) -> AgentListResponse:
        """List all agents for the tenant.

        Args:
            page: Page number (default: 1)
            page_size: Items per page (default: 50, max: 1000)
            status_filter: Optional status filter (e.g., "active", "inactive")

        Returns:
            Paginated list of agents

        Raises:
            ValidationError: If pagination parameters are invalid
            APIError: If the API request fails
        """
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        if status_filter:
            params["status_filter"] = status_filter

        response = await self._client.get(f"{self._base_url}/api/v1/agents/", params=params)
        response.raise_for_status()
        return AgentListResponse(**response.json())

    async def get(self, agent_id: str) -> Agent:
        """Retrieve an agent by ID.

        Args:
            agent_id: Agent identifier

        Returns:
            Agent details

        Raises:
            NotFoundError: If agent not found
            APIError: If the API request fails
        """
        response = await self._client.get(f"{self._base_url}/api/v1/agents/{agent_id}")
        response.raise_for_status()
        return Agent(**response.json())

    async def create(
        self,
        name: str,
        certificate_pem: str,
        metadata: dict[str, Any] | None = None,
    ) -> Agent:
        """Create a new agent.

        Args:
            name: Agent name (3-100 characters)
            certificate_pem: X.509 certificate in PEM format
            metadata: Optional metadata dictionary

        Returns:
            Created agent details

        Raises:
            ValidationError: If validation fails
            ConflictError: If duplicate agent exists
            APIError: If the API request fails
        """
        request = CreateAgentRequest(
            name=name,
            certificate_pem=certificate_pem,
            metadata=metadata or {},
        )

        response = await self._client.post(
            f"{self._base_url}/api/v1/agents/",
            json=request.model_dump(mode="json"),
        )
        response.raise_for_status()
        return Agent(**response.json())

    async def update(
        self,
        agent_id: str,
        name: str | None = None,
        certificate_pem: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Agent:
        """Update an existing agent.

        Args:
            agent_id: Agent identifier
            name: Optional new agent name (3-100 characters)
            certificate_pem: Optional new X.509 certificate in PEM format
            metadata: Optional new metadata dictionary

        Returns:
            Updated agent details

        Raises:
            NotFoundError: If agent not found
            ValidationError: If validation fails
            APIError: If the API request fails
        """
        request = UpdateAgentRequest(
            name=name,
            certificate_pem=certificate_pem,
            metadata=metadata,
        )

        # Only include fields that are set
        request_data = request.model_dump(mode="json", exclude_none=True)

        response = await self._client.put(
            f"{self._base_url}/api/v1/agents/{agent_id}",
            json=request_data,
        )
        response.raise_for_status()
        return Agent(**response.json())


class AgentsSyncAPI:
    """Synchronous agent management API interface.

    Provides synchronous methods for creating, reading, updating, and listing agents.
    """

    def __init__(self, client: Client, base_url: str, tenant_id: str | None = None) -> None:
        """Initialize agents API.

        Args:
            client: HTTP client instance
            base_url: Base URL for API endpoints
            tenant_id: Optional default tenant ID
        """
        self._client = client
        self._base_url = base_url
        self._tenant_id = tenant_id

    def list(
        self,
        page: int = 1,
        page_size: int = 50,
        status_filter: str | None = None,
    ) -> AgentListResponse:
        """List all agents for the tenant.

        Args:
            page: Page number (default: 1)
            page_size: Items per page (default: 50, max: 1000)
            status_filter: Optional status filter (e.g., "active", "inactive")

        Returns:
            Paginated list of agents

        Raises:
            ValidationError: If pagination parameters are invalid
            APIError: If the API request fails
        """
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        if status_filter:
            params["status_filter"] = status_filter

        response = self._client.get(f"{self._base_url}/api/v1/agents/", params=params)
        response.raise_for_status()
        return AgentListResponse(**response.json())

    def get(self, agent_id: str) -> Agent:
        """Retrieve an agent by ID.

        Args:
            agent_id: Agent identifier

        Returns:
            Agent details

        Raises:
            NotFoundError: If agent not found
            APIError: If the API request fails
        """
        response = self._client.get(f"{self._base_url}/api/v1/agents/{agent_id}")
        response.raise_for_status()
        return Agent(**response.json())

    def create(
        self,
        name: str,
        certificate_pem: str,
        metadata: dict[str, Any] | None = None,
    ) -> Agent:
        """Create a new agent.

        Args:
            name: Agent name (3-100 characters)
            certificate_pem: X.509 certificate in PEM format
            metadata: Optional metadata dictionary

        Returns:
            Created agent details

        Raises:
            ValidationError: If validation fails
            ConflictError: If duplicate agent exists
            APIError: If the API request fails
        """
        request = CreateAgentRequest(
            name=name,
            certificate_pem=certificate_pem,
            metadata=metadata or {},
        )

        response = self._client.post(
            f"{self._base_url}/api/v1/agents/",
            json=request.model_dump(mode="json"),
        )
        response.raise_for_status()
        return Agent(**response.json())

    def update(
        self,
        agent_id: str,
        name: str | None = None,
        certificate_pem: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Agent:
        """Update an existing agent.

        Args:
            agent_id: Agent identifier
            name: Optional new agent name (3-100 characters)
            certificate_pem: Optional new X.509 certificate in PEM format
            metadata: Optional new metadata dictionary

        Returns:
            Updated agent details

        Raises:
            NotFoundError: If agent not found
            ValidationError: If validation fails
            APIError: If the API request fails
        """
        request = UpdateAgentRequest(
            name=name,
            certificate_pem=certificate_pem,
            metadata=metadata,
        )

        request_data = request.model_dump(mode="json", exclude_none=True)

        response = self._client.put(
            f"{self._base_url}/api/v1/agents/{agent_id}",
            json=request_data,
        )
        response.raise_for_status()
        return Agent(**response.json())
