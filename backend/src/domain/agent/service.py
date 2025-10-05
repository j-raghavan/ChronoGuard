"""Agent domain service for business operations."""

from datetime import UTC, datetime
from uuid import UUID

from domain.agent.entity import Agent, AgentStatus
from domain.agent.repository import AgentRepository
from domain.common.exceptions import (
    BusinessRuleViolationError,
    DuplicateEntityError,
    EntityNotFoundError,
)
from domain.common.value_objects import X509Certificate


class AgentService:
    """Domain service for agent business operations."""

    def __init__(self, agent_repository: AgentRepository) -> None:
        """Initialize agent service.

        Args:
            agent_repository: Repository for agent persistence
        """
        self._repository = agent_repository

    async def create_agent(
        self,
        tenant_id: UUID,
        name: str,
        certificate: X509Certificate,
    ) -> Agent:
        """Create a new agent with validation.

        Args:
            tenant_id: Tenant identifier
            name: Agent name
            certificate: Agent's X.509 certificate

        Returns:
            Created agent entity

        Raises:
            DuplicateEntityError: If agent name already exists for tenant
            BusinessRuleViolationError: If business rules are violated
        """
        # Check for duplicate name
        if await self._repository.exists_by_name(tenant_id, name):
            raise DuplicateEntityError("Agent", "name", name)

        # Check for duplicate certificate
        fingerprint = certificate.fingerprint_sha256
        if await self._repository.exists_by_certificate_fingerprint(fingerprint):
            raise DuplicateEntityError("Agent", "certificate_fingerprint", fingerprint)

        # Validate certificate is not expired
        if not certificate.is_valid_now:
            raise BusinessRuleViolationError(
                "Cannot create agent with expired certificate",
                rule_name="certificate_must_be_valid",
                context={
                    "certificate_expiry": certificate.not_valid_after.isoformat(),
                    "certificate_fingerprint": fingerprint,
                },
            )

        # Check tenant agent limits (business rule)
        agent_count = await self._repository.count_by_tenant(tenant_id)
        if agent_count >= 1000:  # Configurable limit
            raise BusinessRuleViolationError(
                f"Tenant has reached maximum agent limit: {agent_count}",
                rule_name="max_agents_per_tenant",
                context={"tenant_id": str(tenant_id), "current_count": agent_count},
            )

        # Create agent
        agent = Agent(
            tenant_id=tenant_id,
            name=name,
            certificate=certificate,
            status=AgentStatus.PENDING,
        )

        await self._repository.save(agent)
        return agent

    async def activate_agent(self, agent_id: UUID) -> Agent:
        """Activate an agent after validation.

        Args:
            agent_id: Agent identifier

        Returns:
            Activated agent entity

        Raises:
            EntityNotFoundError: If agent doesn't exist
            BusinessRuleViolationError: If activation rules are violated
        """
        agent = await self._get_agent_or_raise(agent_id)

        # Additional business rule: cannot activate if certificate expired
        if agent.is_certificate_expired():
            raise BusinessRuleViolationError(
                "Cannot activate agent with expired certificate",
                rule_name="certificate_must_be_valid_for_activation",
                context={
                    "agent_id": str(agent_id),
                    "certificate_expiry": agent.certificate.not_valid_after.isoformat(),
                },
            )

        agent.activate()
        await self._repository.save(agent)
        return agent

    async def suspend_agent(self, agent_id: UUID, reason: str | None = None) -> Agent:
        """Suspend an agent.

        Args:
            agent_id: Agent identifier
            reason: Optional suspension reason

        Returns:
            Suspended agent entity

        Raises:
            EntityNotFoundError: If agent doesn't exist
        """
        agent = await self._get_agent_or_raise(agent_id)
        agent.suspend(reason)
        await self._repository.save(agent)
        return agent

    async def deactivate_agent(self, agent_id: UUID, reason: str | None = None) -> Agent:
        """Deactivate an agent permanently.

        Args:
            agent_id: Agent identifier
            reason: Optional deactivation reason

        Returns:
            Deactivated agent entity

        Raises:
            EntityNotFoundError: If agent doesn't exist
        """
        agent = await self._get_agent_or_raise(agent_id)
        agent.deactivate(reason)
        await self._repository.save(agent)
        return agent

    async def update_agent_certificate(
        self, agent_id: UUID, new_certificate: X509Certificate
    ) -> Agent:
        """Update an agent's certificate.

        Args:
            agent_id: Agent identifier
            new_certificate: New certificate to assign

        Returns:
            Updated agent entity

        Raises:
            EntityNotFoundError: If agent doesn't exist
            BusinessRuleViolationError: If certificate update violates rules
            DuplicateEntityError: If certificate is already in use
        """
        agent = await self._get_agent_or_raise(agent_id)

        # Check for duplicate certificate (excluding current agent)
        fingerprint = new_certificate.fingerprint_sha256
        current_fingerprint = agent.certificate.fingerprint_sha256

        if (
            fingerprint != current_fingerprint
            and await self._repository.exists_by_certificate_fingerprint(fingerprint)
        ):
            raise DuplicateEntityError("Agent", "certificate_fingerprint", fingerprint)

        agent.update_certificate(new_certificate)
        await self._repository.save(agent)
        return agent

    async def assign_policy_to_agent(self, agent_id: UUID, policy_id: UUID) -> Agent:
        """Assign a policy to an agent.

        Args:
            agent_id: Agent identifier
            policy_id: Policy identifier

        Returns:
            Updated agent entity

        Raises:
            EntityNotFoundError: If agent doesn't exist
            BusinessRuleViolationError: If policy assignment violates rules
        """
        agent = await self._get_agent_or_raise(agent_id)
        agent.assign_policy(policy_id)
        await self._repository.save(agent)
        return agent

    async def remove_policy_from_agent(self, agent_id: UUID, policy_id: UUID) -> Agent:
        """Remove a policy from an agent.

        Args:
            agent_id: Agent identifier
            policy_id: Policy identifier

        Returns:
            Updated agent entity

        Raises:
            EntityNotFoundError: If agent doesn't exist
            BusinessRuleViolationError: If policy removal violates rules
        """
        agent = await self._get_agent_or_raise(agent_id)
        agent.remove_policy(policy_id)
        await self._repository.save(agent)
        return agent

    async def update_agent_last_seen(self, agent_id: UUID) -> Agent:
        """Update agent's last seen timestamp.

        Args:
            agent_id: Agent identifier

        Returns:
            Updated agent entity

        Raises:
            EntityNotFoundError: If agent doesn't exist
        """
        agent = await self._get_agent_or_raise(agent_id)
        agent.update_last_seen()
        await self._repository.save(agent)
        return agent

    async def check_and_expire_certificates(self) -> list[Agent]:
        """Check for expired certificates and mark agents as expired.

        Returns:
            List of agents that were marked as expired

        Note:
            This should be called periodically by a background process
        """
        now = datetime.now(UTC)
        agents_with_expired_certs = await self._repository.find_expired_certificates(now)

        expired_agents = []
        for agent in agents_with_expired_certs:
            if agent.status in {AgentStatus.ACTIVE, AgentStatus.SUSPENDED}:
                agent.mark_expired()
                await self._repository.save(agent)
                expired_agents.append(agent)

        return expired_agents

    async def find_agents_for_policy_removal(self, policy_id: UUID) -> list[Agent]:
        """Find all agents that have a specific policy assigned.

        Args:
            policy_id: Policy identifier

        Returns:
            List of agents with the specified policy

        Note:
            Used when a policy is being deleted
        """
        # This requires a cross-tenant search, so we need to implement
        # a different repository method or accept tenant_id parameter
        # For now, this is a placeholder that would need tenant context
        raise NotImplementedError("Requires tenant context or cross-tenant capability")

    async def get_tenant_agent_statistics(self, tenant_id: UUID) -> dict[str, int]:
        """Get agent statistics for a tenant.

        Args:
            tenant_id: Tenant identifier

        Returns:
            Dictionary with agent statistics
        """
        total_agents = await self._repository.count_by_tenant(tenant_id)
        active_agents = await self._repository.count_by_status(tenant_id, AgentStatus.ACTIVE)
        pending_agents = await self._repository.count_by_status(tenant_id, AgentStatus.PENDING)
        suspended_agents = await self._repository.count_by_status(tenant_id, AgentStatus.SUSPENDED)
        deactivated_agents = await self._repository.count_by_status(
            tenant_id, AgentStatus.DEACTIVATED
        )
        expired_agents = await self._repository.count_by_status(tenant_id, AgentStatus.EXPIRED)

        return {
            "total": total_agents,
            "active": active_agents,
            "pending": pending_agents,
            "suspended": suspended_agents,
            "deactivated": deactivated_agents,
            "expired": expired_agents,
        }

    async def find_inactive_agents_for_cleanup(self, inactive_days: int = 30) -> list[Agent]:
        """Find agents that have been inactive for cleanup.

        Args:
            inactive_days: Number of days of inactivity to consider

        Returns:
            List of inactive agents
        """
        from datetime import timedelta

        cutoff_date = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        cutoff_date = cutoff_date - timedelta(days=inactive_days)

        return await self._repository.find_inactive_agents(cutoff_date)

    async def bulk_deactivate_agents(self, agent_ids: list[UUID], reason: str) -> int:
        """Bulk deactivate multiple agents.

        Args:
            agent_ids: List of agent IDs to deactivate
            reason: Reason for deactivation

        Returns:
            Number of agents successfully deactivated
        """
        # For bulk operations, we might want to handle this differently
        # depending on the persistence layer capabilities
        return await self._repository.bulk_update_status(agent_ids, AgentStatus.DEACTIVATED)

    async def _get_agent_or_raise(self, agent_id: UUID) -> Agent:
        """Get agent by ID or raise EntityNotFoundError.

        Args:
            agent_id: Agent identifier

        Returns:
            Agent entity

        Raises:
            EntityNotFoundError: If agent doesn't exist
        """
        agent = await self._repository.find_by_id(agent_id)
        if not agent:
            raise EntityNotFoundError("Agent", agent_id)
        return agent
