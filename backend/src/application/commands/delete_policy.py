"""Delete Policy command handler.

This module implements the command pattern for policy deletion, following CQRS principles
and Clean Architecture.
"""

from __future__ import annotations

from uuid import UUID

from domain.audit.entity import AccessDecision
from domain.audit.service import AccessRequest, AuditService
from domain.policy.repository import PolicyRepository
from infrastructure.opa.client import OPAClient
from loguru import logger

# System agent ID for policy operations
SYSTEM_AGENT_ID = UUID("00000000-0000-0000-0000-000000000000")


class DeletePolicyCommand:
    """Command handler for deleting policies.

    This command encapsulates the policy deletion use case, ensuring proper
    validation and cascading operations.
    """

    def __init__(
        self,
        policy_repository: PolicyRepository,
        opa_client: OPAClient | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        """Initialize delete policy command.

        Args:
            policy_repository: Repository for policy persistence
            opa_client: Optional OPA client for policy removal
            audit_service: Optional audit service for side effects
        """
        self._repository = policy_repository
        self._opa_client = opa_client
        self._audit_service = audit_service

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

        # Store policy info before deletion
        policy_name = policy.name
        policy_tenant_id = policy.tenant_id

        # Delete the policy from database
        deletion_success = await self._repository.delete(policy_id)

        # Remove from OPA if OPA integration is available
        if deletion_success and self._opa_client:
            try:
                policy_name_opa = f"policy_{policy_id}"
                await self._opa_client.delete_policy(policy_name_opa)

                logger.info(
                    "Successfully removed policy from OPA",
                    policy_id=str(policy_id),
                    policy_name=policy_name,
                )
            except Exception as e:
                # Log deletion error but don't fail the command
                # Policy is already deleted from database
                logger.error(
                    "Failed to remove policy from OPA",
                    policy_id=str(policy_id),
                    policy_name=policy_name,
                    error=str(e),
                )

        # Record audit entry as side effect
        if deletion_success and self._audit_service:
            try:
                audit_request = AccessRequest(
                    tenant_id=policy_tenant_id,
                    agent_id=SYSTEM_AGENT_ID,
                    domain="system",
                    decision=AccessDecision.ALLOW,
                    reason=f"Policy deleted: {policy_name}",
                    request_method="SYSTEM",
                    request_path="/policies/delete",
                    metadata={
                        "operation": "delete_policy",
                        "policy_name": policy_name,
                    },
                )
                await self._audit_service.record_access(audit_request)
            except Exception as e:
                # Log warning but don't fail the command
                logger.warning(
                    "Failed to record audit entry for policy deletion",
                    policy_id=str(policy_id),
                    error=str(e),
                )

        return deletion_success
