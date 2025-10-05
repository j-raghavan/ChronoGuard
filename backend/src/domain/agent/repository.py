"""Repository interface for agent persistence following DDD principles."""

from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID

from domain.agent.entity import Agent, AgentStatus


class AgentRepository(ABC):
    """Repository interface for agent persistence operations."""

    @abstractmethod
    async def find_by_id(self, agent_id: UUID) -> Agent | None:
        """Retrieve an agent by its unique identifier.

        Args:
            agent_id: The unique identifier of the agent

        Returns:
            Agent if found, None otherwise

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def find_by_tenant_id(self, tenant_id: UUID) -> list[Agent]:
        """Retrieve all agents for a tenant.

        Args:
            tenant_id: The tenant's unique identifier

        Returns:
            List of agents belonging to the tenant

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def find_by_name(self, tenant_id: UUID, name: str) -> Agent | None:
        """Find agent by name within a tenant.

        Args:
            tenant_id: The tenant's unique identifier
            name: The agent name to search for

        Returns:
            Agent if found, None otherwise

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def find_by_status(self, tenant_id: UUID, status: AgentStatus) -> list[Agent]:
        """Find agents by status within a tenant.

        Args:
            tenant_id: The tenant's unique identifier
            status: The agent status to filter by

        Returns:
            List of agents with the specified status

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def find_expired_certificates(self, before_date: datetime) -> list[Agent]:
        """Find agents with certificates expiring before specified date.

        Args:
            before_date: Date to check certificate expiry against

        Returns:
            List of agents with expiring certificates

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def find_inactive_agents(self, since_date: datetime) -> list[Agent]:
        """Find agents that haven't been seen since specified date.

        Args:
            since_date: Date to check last seen against

        Returns:
            List of inactive agents

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def save(self, agent: Agent) -> None:
        """Persist an agent (insert or update).

        Args:
            agent: The agent entity to persist

        Raises:
            RepositoryError: If persistence operation fails
            ConcurrencyError: If version conflict occurs during update
        """
        pass

    @abstractmethod
    async def delete(self, agent_id: UUID) -> bool:
        """Remove an agent from persistence.

        Args:
            agent_id: The unique identifier of the agent to delete

        Returns:
            True if deleted, False if not found

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def exists_by_name(self, tenant_id: UUID, name: str) -> bool:
        """Check if an agent with given name exists for a tenant.

        Args:
            tenant_id: The tenant's unique identifier
            name: The agent name to check

        Returns:
            True if exists, False otherwise

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def exists_by_certificate_fingerprint(self, fingerprint: str) -> bool:
        """Check if an agent with given certificate fingerprint exists.

        Args:
            fingerprint: SHA256 fingerprint of the certificate

        Returns:
            True if exists, False otherwise

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def count_by_tenant(self, tenant_id: UUID) -> int:
        """Count total number of agents for a tenant.

        Args:
            tenant_id: The tenant's unique identifier

        Returns:
            Number of agents for the tenant

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def count_by_status(self, tenant_id: UUID, status: AgentStatus) -> int:
        """Count agents by status for a tenant.

        Args:
            tenant_id: The tenant's unique identifier
            status: The agent status to count

        Returns:
            Number of agents with the specified status

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def find_with_policy(self, tenant_id: UUID, policy_id: UUID) -> list[Agent]:
        """Find agents that have a specific policy assigned.

        Args:
            tenant_id: The tenant's unique identifier
            policy_id: The policy ID to search for

        Returns:
            List of agents with the specified policy

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass

    @abstractmethod
    async def bulk_update_status(self, agent_ids: list[UUID], new_status: AgentStatus) -> int:
        """Bulk update status for multiple agents.

        Args:
            agent_ids: List of agent IDs to update
            new_status: New status to set

        Returns:
            Number of agents updated

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
        status_filter: AgentStatus | None = None,
    ) -> list[Agent]:
        """Find agents with pagination support.

        Args:
            tenant_id: The tenant's unique identifier
            offset: Number of records to skip
            limit: Maximum number of records to return
            status_filter: Optional status filter

        Returns:
            List of agents matching criteria

        Raises:
            RepositoryError: If persistence operation fails
        """
        pass
