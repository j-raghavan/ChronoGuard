"""Create Policy command handler.

This module implements the command pattern for policy creation, following CQRS principles
and Clean Architecture.
"""

from __future__ import annotations

from uuid import UUID

from domain.policy.service import PolicyService

from ..dto import CreatePolicyRequest, PolicyDTO, PolicyMapper


class CreatePolicyCommand:
    """Command handler for creating new policies.

    This command encapsulates the policy creation use case, coordinating between
    the presentation layer (DTOs) and domain layer (entities and services).
    """

    def __init__(self, policy_service: PolicyService) -> None:
        """Initialize create policy command.

        Args:
            policy_service: Domain service for policy operations
        """
        self._policy_service = policy_service

    async def execute(
        self, request: CreatePolicyRequest, tenant_id: UUID, created_by: UUID
    ) -> PolicyDTO:
        """Execute policy creation command.

        Args:
            request: Validated policy creation request
            tenant_id: Tenant ID for the new policy
            created_by: User ID creating the policy

        Returns:
            Created policy as DTO

        Raises:
            DuplicateEntityError: If policy name already exists
            BusinessRuleViolationError: If business rules are violated
            ValidationError: If policy validation fails
        """
        # Execute domain operation
        created_policy = await self._policy_service.create_policy(
            tenant_id=tenant_id,
            name=request.name,
            description=request.description,
            created_by=created_by,
            priority=request.priority,
        )

        # Apply additional settings using domain entity methods
        if request.allowed_domains:
            created_policy = created_policy.model_copy(
                update={"allowed_domains": set(request.allowed_domains)}
            )

        if request.blocked_domains:
            created_policy = created_policy.model_copy(
                update={"blocked_domains": set(request.blocked_domains)}
            )

        if request.metadata:
            created_policy = created_policy.model_copy(update={"metadata": request.metadata})

        # Convert domain entity to DTO
        return PolicyMapper.to_dto(created_policy)
