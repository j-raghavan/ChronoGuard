"""Update Policy command handler.

This module implements the command pattern for policy updates, following CQRS principles
and Clean Architecture.
"""

from __future__ import annotations

from uuid import UUID

from domain.common.exceptions import EntityNotFoundError
from domain.policy.repository import PolicyRepository

from ..dto import PolicyDTO, PolicyMapper, UpdatePolicyRequest


class UpdatePolicyCommand:
    """Command handler for updating existing policies.

    This command encapsulates the policy update use case, supporting partial updates
    where only provided fields are modified.
    """

    def __init__(self, policy_repository: PolicyRepository) -> None:
        """Initialize update policy command.

        Args:
            policy_repository: Repository for policy persistence
        """
        self._repository = policy_repository

    async def execute(
        self, policy_id: UUID, tenant_id: UUID, request: UpdatePolicyRequest
    ) -> PolicyDTO:
        """Execute policy update command.

        Args:
            policy_id: ID of policy to update
            tenant_id: Tenant ID for authorization
            request: Update request with optional fields

        Returns:
            Updated policy as DTO

        Raises:
            EntityNotFoundError: If policy doesn't exist
        """
        # Retrieve existing policy
        policy = await self._repository.find_by_id(policy_id)
        if policy is None or policy.tenant_id != tenant_id:
            raise EntityNotFoundError("Policy", str(policy_id))

        # Build update dict with only provided fields
        update_data: dict[str, object] = {}

        if request.name is not None:
            update_data["name"] = request.name

        if request.description is not None:
            update_data["description"] = request.description

        if request.priority is not None:
            update_data["priority"] = request.priority

        if request.allowed_domains is not None:
            update_data["allowed_domains"] = set(request.allowed_domains)

        if request.blocked_domains is not None:
            update_data["blocked_domains"] = set(request.blocked_domains)

        if request.metadata is not None:
            update_data["metadata"] = request.metadata

        # Create updated policy using Pydantic's model_copy
        if update_data:
            updated_policy = policy.model_copy(update=update_data)
            await self._repository.save(updated_policy)
        else:
            updated_policy = policy

        # Convert to DTO
        return PolicyMapper.to_dto(updated_policy)
