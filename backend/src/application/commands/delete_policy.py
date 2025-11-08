"""Delete Policy command handler.

This module implements the command pattern for policy deletion, following CQRS principles
and Clean Architecture.
"""

from __future__ import annotations

from uuid import UUID

from domain.policy.repository import PolicyRepository


class DeletePolicyCommand:
    """Command handler for deleting policies.

    This command encapsulates the policy deletion use case, ensuring proper
    validation and cascading operations.
    """

    def __init__(self, policy_repository: PolicyRepository) -> None:
        """Initialize delete policy command.

        Args:
            policy_repository: Repository for policy persistence
        """
        self._repository = policy_repository

    async def execute(self, policy_id: UUID, tenant_id: UUID) -> bool:
        """Execute policy deletion command.

        Args:
            policy_id: ID of policy to delete
            tenant_id: Tenant ID for authorization

        Returns:
            True if policy was deleted successfully

        Raises:
            EntityNotFoundError: If policy doesn't exist or doesn't belong to tenant
        """
        # Verify policy exists and belongs to tenant
        policy = await self._repository.find_by_id(policy_id)
        if policy is None or policy.tenant_id != tenant_id:
            from domain.common.exceptions import EntityNotFoundError

            raise EntityNotFoundError("Policy", str(policy_id))

        # Delete the policy
        return await self._repository.delete(policy_id)
