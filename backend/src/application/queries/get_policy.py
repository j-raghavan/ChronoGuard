"""Policy query handlers for read operations.

This module implements query handlers for policy retrieval, following CQRS principles
and Clean Architecture.
"""

from __future__ import annotations

from uuid import UUID

from domain.policy.entity import PolicyStatus
from domain.policy.repository import PolicyRepository

from ..dto import PolicyDTO, PolicyListResponse, PolicyMapper


class GetPolicyQuery:
    """Query handler for retrieving individual policies."""

    def __init__(self, policy_repository: PolicyRepository) -> None:
        """Initialize get policy query.

        Args:
            policy_repository: Repository for policy persistence
        """
        self._repository = policy_repository

    async def execute(self, policy_id: UUID, tenant_id: UUID) -> PolicyDTO | None:
        """Retrieve a policy by ID.

        Args:
            policy_id: Policy identifier
            tenant_id: Tenant ID for authorization

        Returns:
            PolicyDTO if found and belongs to tenant, None otherwise
        """
        policy = await self._repository.find_by_id(policy_id)

        # Verify tenant ownership
        if policy is None or policy.tenant_id != tenant_id:
            return None

        return PolicyMapper.to_dto(policy)


class ListPoliciesQuery:
    """Query handler for listing policies with pagination and filtering."""

    def __init__(self, policy_repository: PolicyRepository) -> None:
        """Initialize list policies query.

        Args:
            policy_repository: Repository for policy persistence
        """
        self._repository = policy_repository

    async def execute(
        self,
        tenant_id: UUID,
        page: int = 1,
        page_size: int = 50,
        status_filter: PolicyStatus | None = None,
    ) -> PolicyListResponse:
        """List policies for a tenant with pagination.

        Args:
            tenant_id: Tenant ID to list policies for
            page: Page number (1-indexed)
            page_size: Number of policies per page
            status_filter: Optional status filter

        Returns:
            Paginated list of policies

        Raises:
            ValueError: If pagination parameters are invalid
        """
        if page < 1:
            raise ValueError(f"Page must be >= 1, got {page}")
        if page_size < 1 or page_size > 1000:
            raise ValueError(f"Page size must be between 1 and 1000, got {page_size}")

        # Calculate offset
        offset = (page - 1) * page_size

        # Retrieve policies
        policies = await self._repository.find_paginated(
            tenant_id=tenant_id, offset=offset, limit=page_size, status_filter=status_filter
        )

        # Get total count (respect status filters)
        if status_filter:
            total_count = await self._repository.count_by_status(tenant_id, status_filter)
        else:
            total_count = await self._repository.count_by_tenant(tenant_id)

        # Convert to DTOs
        policy_dtos = [PolicyMapper.to_dto(policy) for policy in policies]

        return PolicyListResponse(
            policies=policy_dtos, total_count=total_count, page=page, page_size=page_size
        )
