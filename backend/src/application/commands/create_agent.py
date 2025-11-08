"""Create Agent command handler.

This module implements the command pattern for agent creation, following CQRS principles
and Clean Architecture by coordinating between domain services and DTOs.
"""

from __future__ import annotations

from uuid import UUID

from domain.agent.service import AgentService

from ..dto import AgentDTO, AgentMapper, CreateAgentRequest


class CreateAgentCommand:
    """Command handler for creating new agents.

    This command encapsulates the agent creation use case, coordinating between
    the presentation layer (DTOs) and domain layer (entities and services).
    """

    def __init__(self, agent_service: AgentService) -> None:
        """Initialize create agent command.

        Args:
            agent_service: Domain service for agent operations
        """
        self._agent_service = agent_service

    async def execute(self, request: CreateAgentRequest, tenant_id: UUID) -> AgentDTO:
        """Execute agent creation command.

        Args:
            request: Validated agent creation request
            tenant_id: Tenant ID for the new agent

        Returns:
            Created agent as DTO

        Raises:
            DuplicateEntityError: If agent name or certificate already exists
            BusinessRuleViolationError: If business rules are violated
            ValidationError: If certificate is invalid
        """
        # Convert DTO to domain entity
        agent = AgentMapper.from_create_request(request, tenant_id)

        # Execute domain operation
        created_agent = await self._agent_service.create_agent(
            tenant_id=agent.tenant_id, name=agent.name, certificate=agent.certificate
        )

        # Convert domain entity back to DTO
        return AgentMapper.to_dto(created_agent)
