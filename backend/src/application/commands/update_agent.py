"""Update Agent command handler.

This module implements the command pattern for agent updates, following CQRS principles
and Clean Architecture.
"""

from __future__ import annotations

from uuid import UUID

from loguru import logger

from domain.agent.repository import AgentRepository
from domain.audit.entity import AccessDecision
from domain.audit.service import AccessRequest, AuditService
from domain.common.exceptions import EntityNotFoundError
from domain.common.value_objects import X509Certificate

from ..dto import AgentDTO, AgentMapper, UpdateAgentRequest


class UpdateAgentCommand:
    """Command handler for updating existing agents.

    This command encapsulates the agent update use case, supporting partial updates
    where only provided fields are modified.
    """

    def __init__(
        self, agent_repository: AgentRepository, audit_service: AuditService | None = None
    ) -> None:
        """Initialize update agent command.

        Args:
            agent_repository: Repository for agent persistence
            audit_service: Optional audit service for side effects
        """
        self._repository = agent_repository
        self._audit_service = audit_service

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

        # Record audit entry as side effect
        if self._audit_service:
            try:
                # Collect changes for metadata
                changes = list(update_data.keys()) if update_data else []
                audit_request = AccessRequest(
                    tenant_id=updated_agent.tenant_id,
                    agent_id=updated_agent.agent_id,
                    domain="system",
                    decision=AccessDecision.ALLOW,
                    reason=f"Agent updated: {updated_agent.name}",
                    request_method="SYSTEM",
                    request_path="/agents/update",
                    metadata={
                        "operation": "update_agent",
                        "agent_name": updated_agent.name,
                        "changes": ",".join(changes),
                    },
                )
                await self._audit_service.record_access(audit_request)
            except Exception as e:
                # Log warning but don't fail the command
                logger.warning(
                    "Failed to record audit entry for agent update",
                    agent_id=str(updated_agent.agent_id),
                    error=str(e),
                )

        # Convert to DTO
        return AgentMapper.to_dto(updated_agent)
