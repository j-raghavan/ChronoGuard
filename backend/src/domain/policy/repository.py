"""Repository interface for policy persistence following DDD principles."""

from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID

from domain.policy.entity import Policy, PolicyStatus


class PolicyRepository(ABC):
    """Repository interface for policy persistence operations."""

    @abstractmethod
    async def find_by_id(self, policy_id: UUID) -> Policy | None:
        """Retrieve a policy by its unique identifier.

        Args:
            policy_id: The unique identifier of the policy

        Returns:
            Policy if found, None otherwise

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def find_by_tenant_id(self, tenant_id: UUID) -> list[Policy]:
        """Retrieve all policies for a tenant.

        Args:
            tenant_id: The tenant's unique identifier

        Returns:
            List of policies belonging to the tenant

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def find_by_name(self, tenant_id: UUID, name: str) -> Policy | None:
        """Find policy by name within a tenant.

        Args:
            tenant_id: The tenant's unique identifier
            name: The policy name to search for

        Returns:
            Policy if found, None otherwise

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def find_by_status(self, tenant_id: UUID, status: PolicyStatus) -> list[Policy]:
        """Find policies by status within a tenant.

        Args:
            tenant_id: The tenant's unique identifier
            status: The policy status to filter by

        Returns:
            List of policies with the specified status

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def find_active_policies(self, tenant_id: UUID) -> list[Policy]:
        """Find all active policies for a tenant.

        Args:
            tenant_id: The tenant's unique identifier

        Returns:
            List of active policies

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def find_policies_by_priority_range(
        self, tenant_id: UUID, min_priority: int, max_priority: int
    ) -> list[Policy]:
        """Find policies within a priority range.

        Args:
            tenant_id: The tenant's unique identifier
            min_priority: Minimum priority value (inclusive)
            max_priority: Maximum priority value (inclusive)

        Returns:
            List of policies within the priority range

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def find_policies_with_domain(self, tenant_id: UUID, domain: str) -> list[Policy]:
        """Find policies that reference a specific domain.

        Args:
            tenant_id: The tenant's unique identifier
            domain: The domain to search for in policy rules

        Returns:
            List of policies that reference the domain

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def find_policies_created_by(self, tenant_id: UUID, created_by: UUID) -> list[Policy]:
        """Find policies created by a specific user.

        Args:
            tenant_id: The tenant's unique identifier
            created_by: The user ID who created the policies

        Returns:
            List of policies created by the user

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def find_policies_updated_since(
        self, tenant_id: UUID, since_date: datetime
    ) -> list[Policy]:
        """Find policies updated since a specific date.

        Args:
            tenant_id: The tenant's unique identifier
            since_date: The date to filter by

        Returns:
            List of policies updated since the date

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def save(self, policy: Policy) -> None:
        """Persist a policy (insert or update).

        Args:
            policy: The policy entity to persist

        Raises:
            RepositoryError: If persistence operation fails
            ConcurrencyError: If version conflict occurs during update
        """
        pass

    @abstractmethod
    async def delete(self, policy_id: UUID) -> bool:
        """Remove a policy from persistence.

        Args:
            policy_id: The unique identifier of the policy to delete

        Returns:
            True if deleted, False if not found

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def exists_by_name(self, tenant_id: UUID, name: str) -> bool:
        """Check if a policy with given name exists for a tenant.

        Args:
            tenant_id: The tenant's unique identifier
            name: The policy name to check

        Returns:
            True if exists, False otherwise

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def count_by_tenant(self, tenant_id: UUID) -> int:
        """Count total number of policies for a tenant.

        Args:
            tenant_id: The tenant's unique identifier

        Returns:
            Number of policies for the tenant

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def count_by_status(self, tenant_id: UUID, status: PolicyStatus) -> int:
        """Count policies by status for a tenant.

        Args:
            tenant_id: The tenant's unique identifier
            status: The policy status to count

        Returns:
            Number of policies with the specified status

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def find_policies_for_evaluation(self, tenant_id: UUID, domain: str) -> list[Policy]:
        """Find active policies that should be evaluated for a domain request.

        Args:
            tenant_id: The tenant's unique identifier
            domain: The domain being accessed

        Returns:
            List of policies that should be evaluated, sorted by priority

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def bulk_update_status(self, policy_ids: list[UUID], new_status: PolicyStatus) -> int:
        """Bulk update status for multiple policies.

        Args:
            policy_ids: List of policy IDs to update
            new_status: New status to set

        Returns:
            Number of policies updated

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def find_paginated(
        self,
        tenant_id: UUID,
        offset: int = 0,
        limit: int = 100,
        status_filter: PolicyStatus | None = None,
    ) -> list[Policy]:
        """Find policies with pagination support.

        Args:
            tenant_id: The tenant's unique identifier
            offset: Number of records to skip
            limit: Maximum number of records to return
            status_filter: Optional status filter

        Returns:
            List of policies matching criteria

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def find_duplicate_priority(
        self, tenant_id: UUID, priority: int, exclude_policy_id: UUID | None = None
    ) -> list[Policy]:
        """Find policies with the same priority (for conflict detection).

        Args:
            tenant_id: The tenant's unique identifier
            priority: The priority value to check
            exclude_policy_id: Optional policy ID to exclude from search

        Returns:
            List of policies with the same priority

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def search_policies(
        self,
        tenant_id: UUID,
        search_term: str,
        status_filter: PolicyStatus | None = None,
        limit: int = 50,
    ) -> list[Policy]:
        """Search policies by name, description, or rules.

        Args:
            tenant_id: The tenant's unique identifier
            search_term: The search term to match against
            status_filter: Optional status filter
            limit: Maximum number of results to return

        Returns:
            List of policies matching the search criteria

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass
