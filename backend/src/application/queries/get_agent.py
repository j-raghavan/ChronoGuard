"""Agent query handlers for read operations.

This module implements query handlers for agent retrieval, following CQRS principles
and Clean Architecture.
"""

from __future__ import annotations

from uuid import UUID

from domain.agent.entity import AgentStatus
from domain.agent.repository import AgentRepository

from ..dto import AgentDTO, AgentListResponse, AgentMapper


class GetAgentQuery:
    """Query handler for retrieving individual agents."""

    def __init__(self, agent_repository: AgentRepository) -> None:
        """Initialize get agent query.

        Args:
            agent_repository: Repository for agent persistence
        """
        self._repository = agent_repository

    async def execute(self, agent_id: UUID, tenant_id: UUID) -> AgentDTO | None:
        """Retrieve an agent by ID.

        Args:
            agent_id: Agent identifier
            tenant_id: Tenant ID for authorization

        Returns:
            AgentDTO if found and belongs to tenant, None otherwise
        """
        agent = await self._repository.find_by_id(agent_id)

        # Verify tenant ownership
        if agent is None or agent.tenant_id != tenant_id:
            return None

        return AgentMapper.to_dto(agent)


class ListAgentsQuery:
    """Query handler for listing agents with pagination and filtering."""

    def __init__(self, agent_repository: AgentRepository) -> None:
        """Initialize list agents query.

        Args:
            agent_repository: Repository for agent persistence
        """
        self._repository = agent_repository

    async def execute(
        self,
        tenant_id: UUID,
        page: int = 1,
        page_size: int = 50,
        status_filter: AgentStatus | None = None,
    ) -> AgentListResponse:
        """List agents for a tenant with pagination.

        Args:
            tenant_id: Tenant ID to list agents for
            page: Page number (1-indexed)
            page_size: Number of agents per page
            status_filter: Optional status filter

        Returns:
            Paginated list of agents

        Raises:
            ValueError: If pagination parameters are invalid
        """
        if page < 1:
            raise ValueError(f"Page must be >= 1, got {page}")
        if page_size < 1 or page_size > 1000:
            raise ValueError(f"Page size must be between 1 and 1000, got {page_size}")

        # Calculate offset
        offset = (page - 1) * page_size

        # Retrieve agents
        agents = await self._repository.find_paginated(
            tenant_id=tenant_id, offset=offset, limit=page_size, status_filter=status_filter
        )

        # Get total count (respect status filters)
        if status_filter:
            total_count = await self._repository.count_by_status(tenant_id, status_filter)
        else:
            total_count = await self._repository.count_by_tenant(tenant_id)

        # Convert to DTOs
        agent_dtos = [AgentMapper.to_dto(agent) for agent in agents]

        return AgentListResponse(
            agents=agent_dtos, total_count=total_count, page=page, page_size=page_size
        )
