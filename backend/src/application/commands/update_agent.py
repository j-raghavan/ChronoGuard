"""Update Agent command handler.

This module implements the command pattern for agent updates, following CQRS principles
and Clean Architecture.
"""

from __future__ import annotations

from uuid import UUID

from domain.agent.repository import AgentRepository
from domain.common.exceptions import EntityNotFoundError
from domain.common.value_objects import X509Certificate

from ..dto import AgentDTO, AgentMapper, UpdateAgentRequest


class UpdateAgentCommand:
    """Command handler for updating existing agents.

    This command encapsulates the agent update use case, supporting partial updates
    where only provided fields are modified.
    """

    def __init__(self, agent_repository: AgentRepository) -> None:
        """Initialize update agent command.

        Args:
            agent_repository: Repository for agent persistence
        """
        self._repository = agent_repository

    async def execute(
        self, agent_id: UUID, tenant_id: UUID, request: UpdateAgentRequest
    ) -> AgentDTO:
        """Execute agent update command.

        Args:
            agent_id: ID of agent to update
            tenant_id: Tenant ID for authorization
            request: Update request with optional fields

        Returns:
            Updated agent as DTO

        Raises:
            EntityNotFoundError: If agent doesn't exist
            ValidationError: If certificate is invalid
        """
        # Retrieve existing agent
        agent = await self._repository.find_by_id(agent_id)
        if agent is None or agent.tenant_id != tenant_id:
            raise EntityNotFoundError("Agent", str(agent_id))

        # Build update dict with only provided fields
        update_data: dict[str, object] = {}

        if request.name is not None:
            update_data["name"] = request.name

        if request.certificate_pem is not None:
            certificate = X509Certificate(pem_data=request.certificate_pem)
            update_data["certificate"] = certificate

        if request.metadata is not None:
            update_data["metadata"] = request.metadata

        # Create updated agent using Pydantic's model_copy
        if update_data:
            updated_agent = agent.model_copy(update=update_data)
            await self._repository.save(updated_agent)
        else:
            updated_agent = agent

        # Convert to DTO
        return AgentMapper.to_dto(updated_agent)
