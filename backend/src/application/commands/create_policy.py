"""Create Policy command handler.

This module implements the command pattern for policy creation, following CQRS principles
and Clean Architecture.
"""

from __future__ import annotations

from uuid import UUID

from domain.audit.entity import AccessDecision
from domain.audit.service import AccessRequest, AuditService
from domain.policy.entity import PolicyStatus
from domain.policy.service import PolicyService
from infrastructure.opa.client import OPAClient
from infrastructure.opa.policy_compiler import PolicyCompiler
from loguru import logger

from ..dto import CreatePolicyRequest, PolicyDTO, PolicyMapper

# System agent ID for policy operations
SYSTEM_AGENT_ID = UUID("00000000-0000-0000-0000-000000000000")


class CreatePolicyCommand:
    """Command handler for creating new policies.

    This command encapsulates the policy creation use case, coordinating between
    the presentation layer (DTOs) and domain layer (entities and services).
    """

    def __init__(
        self,
        policy_service: PolicyService,
        opa_client: OPAClient | None = None,
        policy_compiler: PolicyCompiler | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        """Initialize create policy command.

        Args:
            policy_service: Domain service for policy operations
            opa_client: Optional OPA client for policy deployment
            policy_compiler: Optional policy compiler for Rego generation
            audit_service: Optional audit service for side effects
        """
        self._policy_service = policy_service
        self._opa_client = opa_client
        self._policy_compiler = policy_compiler
        self._audit_service = audit_service

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
        # This ensures validation and metadata updates via _update_metadata()
        for domain in request.allowed_domains:
            created_policy.add_allowed_domain(domain)

        for domain in request.blocked_domains:
            created_policy.add_blocked_domain(domain)

        # Update custom metadata dict directly (no dedicated domain method exists)
        if request.metadata:
            created_policy.metadata.update(request.metadata)
            created_policy._update_metadata()  # Ensure version/timestamp updated

        # Save the updated policy
        await self._policy_service._policy_repository.save(created_policy)

        # Deploy to OPA if policy is ACTIVE and OPA integration is available
        if (
            created_policy.status == PolicyStatus.ACTIVE
            and self._opa_client
            and self._policy_compiler
        ):
            try:
                # Compile policy to Rego
                rego_code = await self._policy_compiler.compile_policy(created_policy)

                # Deploy to OPA
                policy_name = f"policy_{created_policy.policy_id}"
                await self._opa_client.update_policy(policy_name, rego_code)

                logger.info(
                    "Successfully deployed policy to OPA",
                    policy_id=str(created_policy.policy_id),
                    policy_name=created_policy.name,
                )
            except Exception as e:
                # Log deployment error but don't fail the command
                # Policy is still created in database
                logger.error(
                    "Failed to deploy policy to OPA",
                    policy_id=str(created_policy.policy_id),
                    policy_name=created_policy.name,
                    error=str(e),
                )

        # Record audit entry as side effect
        if self._audit_service:
            try:
                audit_request = AccessRequest(
                    tenant_id=created_policy.tenant_id,
                    agent_id=SYSTEM_AGENT_ID,
                    domain="system",
                    decision=AccessDecision.ALLOW,
                    reason=f"Policy created: {created_policy.name}",
                    request_method="SYSTEM",
                    request_path="/policies/create",
                    metadata={
                        "operation": "create_policy",
                        "policy_name": created_policy.name,
                        "policy_status": created_policy.status.value,
                    },
                )
                await self._audit_service.record_access(audit_request)
            except Exception as e:
                # Log warning but don't fail the command
                logger.warning(
                    "Failed to record audit entry for policy creation",
                    policy_id=str(created_policy.policy_id),
                    error=str(e),
                )

        # Convert domain entity to DTO
        return PolicyMapper.to_dto(created_policy)
