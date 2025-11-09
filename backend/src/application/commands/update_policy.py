"""Update Policy command handler.

This module implements the command pattern for policy updates, following CQRS principles
and Clean Architecture.
"""

from __future__ import annotations

from uuid import UUID

from domain.audit.entity import AccessDecision
from domain.audit.service import AccessRequest, AuditService
from domain.common.exceptions import EntityNotFoundError
from domain.policy.entity import PolicyStatus
from domain.policy.repository import PolicyRepository
from infrastructure.opa.client import OPAClient
from infrastructure.opa.policy_compiler import PolicyCompiler
from loguru import logger

from ..dto import PolicyDTO, PolicyMapper, UpdatePolicyRequest

# System agent ID for policy operations
SYSTEM_AGENT_ID = UUID("00000000-0000-0000-0000-000000000000")


class UpdatePolicyCommand:
    """Command handler for updating existing policies.

    This command encapsulates the policy update use case, supporting partial updates
    where only provided fields are modified.
    """

    def __init__(
        self,
        policy_repository: PolicyRepository,
        opa_client: OPAClient | None = None,
        policy_compiler: PolicyCompiler | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        """Initialize update policy command.

        Args:
            policy_repository: Repository for policy persistence
            opa_client: Optional OPA client for policy deployment
            policy_compiler: Optional policy compiler for Rego generation
            audit_service: Optional audit service for side effects
        """
        self._repository = policy_repository
        self._opa_client = opa_client
        self._policy_compiler = policy_compiler
        self._audit_service = audit_service

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

        # Track if changes were made
        has_changes = False

        # Update simple fields using model_copy (for immutable Pydantic fields)
        update_data: dict[str, object] = {}

        if request.name is not None:
            update_data["name"] = request.name
            has_changes = True

        if request.description is not None:
            update_data["description"] = request.description
            has_changes = True

        if request.priority is not None:
            update_data["priority"] = request.priority
            has_changes = True

        # Apply simple field updates if any
        if update_data:
            policy = policy.model_copy(update=update_data)

        # Update domains using domain entity methods (ensures validation and metadata)
        if request.allowed_domains is not None:
            # Clear existing and add new domains via domain methods
            policy.allowed_domains.clear()
            for domain in request.allowed_domains:
                policy.add_allowed_domain(domain)
            has_changes = True

        if request.blocked_domains is not None:
            # Clear existing and add new domains via domain methods
            policy.blocked_domains.clear()
            for domain in request.blocked_domains:
                policy.add_blocked_domain(domain)
            has_changes = True

        # Update custom metadata dict directly (no dedicated domain method exists)
        if request.metadata is not None:
            policy.metadata.clear()
            policy.metadata.update(request.metadata)
            policy._update_metadata()  # Ensure version/timestamp updated
            has_changes = True

        # Save the updated policy if changes were made
        if has_changes:
            await self._repository.save(policy)

        updated_policy = policy

        # Redeploy to OPA if policy is ACTIVE and OPA integration is available
        if (
            updated_policy.status == PolicyStatus.ACTIVE
            and self._opa_client
            and self._policy_compiler
        ):
            try:
                # Compile policy to Rego
                rego_code = await self._policy_compiler.compile_policy(updated_policy)

                # Deploy to OPA
                policy_name = f"policy_{updated_policy.policy_id}"
                await self._opa_client.update_policy(policy_name, rego_code)

                logger.info(
                    "Successfully redeployed updated policy to OPA",
                    policy_id=str(updated_policy.policy_id),
                    policy_name=updated_policy.name,
                )
            except Exception as e:
                # Log deployment error but don't fail the command
                # Policy is still updated in database
                logger.error(
                    "Failed to redeploy updated policy to OPA",
                    policy_id=str(updated_policy.policy_id),
                    policy_name=updated_policy.name,
                    error=str(e),
                )

        # Record audit entry as side effect
        if self._audit_service:
            try:
                # Collect changes for metadata
                changes = list(update_data.keys()) if update_data else []
                audit_request = AccessRequest(
                    tenant_id=updated_policy.tenant_id,
                    agent_id=SYSTEM_AGENT_ID,
                    domain="system",
                    decision=AccessDecision.ALLOW,
                    reason=f"Policy updated: {updated_policy.name}",
                    request_method="SYSTEM",
                    request_path="/policies/update",
                    metadata={
                        "operation": "update_policy",
                        "policy_name": updated_policy.name,
                        "changes": ",".join(changes),
                    },
                )
                await self._audit_service.record_access(audit_request)
            except Exception as e:
                # Log warning but don't fail the command
                logger.warning(
                    "Failed to record audit entry for policy update",
                    policy_id=str(updated_policy.policy_id),
                    error=str(e),
                )

        # Convert to DTO
        return PolicyMapper.to_dto(updated_policy)
