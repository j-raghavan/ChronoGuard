"""Create Agent command handler.

This module implements the command pattern for agent creation, following CQRS principles
and Clean Architecture by coordinating between domain services and DTOs.
"""

from __future__ import annotations

from uuid import UUID

from loguru import logger

from domain.agent.service import AgentService
from domain.audit.entity import AccessDecision
from domain.audit.service import AccessRequest, AuditService

from ..dto import AgentDTO, AgentMapper, CreateAgentRequest


class CreateAgentCommand:
    """Command handler for creating new agents.

    This command encapsulates the agent creation use case, coordinating between
    the presentation layer (DTOs) and domain layer (entities and services).
    """

    def __init__(
        self, agent_service: AgentService, audit_service: AuditService | None = None
    ) -> None:
        """Initialize create agent command.

        Args:
            agent_service: Domain service for agent operations
            audit_service: Optional audit service for side effects
        """
        self._agent_service = agent_service
        self._audit_service = audit_service

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

        # Record audit entry as side effect
        if self._audit_service:
            try:
                audit_request = AccessRequest(
                    tenant_id=created_agent.tenant_id,
                    agent_id=created_agent.agent_id,
                    domain="system",
                    decision=AccessDecision.ALLOW,
                    reason=f"Agent created: {created_agent.name}",
                    request_method="SYSTEM",
                    request_path="/agents/create",
                    metadata={
                        "operation": "create_agent",
                        "agent_name": created_agent.name,
                        "agent_status": str(
                            created_agent.status.value
                            if hasattr(created_agent.status, "value")
                            else created_agent.status
                        ),
                    },
                )
                await self._audit_service.record_access(audit_request)
            except Exception as e:
                # Log warning but don't fail the command
                logger.warning(
                    "Failed to record audit entry for agent creation",
                    agent_id=str(created_agent.agent_id),
                    error=str(e),
                )

        # Convert domain entity back to DTO
        return AgentMapper.to_dto(created_agent)
