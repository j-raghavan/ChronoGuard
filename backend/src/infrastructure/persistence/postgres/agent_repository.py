"""PostgreSQL implementation of AgentRepository with production-grade features.

This implementation is tested via integration tests with real PostgreSQL.
See tests/integration/test_agent_repository_integration.py
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from domain.agent.entity import Agent, AgentStatus
from domain.agent.repository import AgentRepository
from domain.common.exceptions import ConcurrencyError
from domain.common.value_objects import X509Certificate
from infrastructure.persistence.models import AgentModel


class RepositoryError(Exception):
    """Raised when repository operations fail."""

    def __init__(self, message: str, original_error: Exception | None = None) -> None:
        """Initialize repository error.

        Args:
            message: Error description
            original_error: Original exception that caused the error
        """
        super().__init__(message)
        self.message = message
        self.original_error = original_error


class PostgresAgentRepository(AgentRepository):
    """PostgreSQL implementation of agent repository with production features."""

    def __init__(self, database_url: str) -> None:
        """Initialize PostgreSQL agent repository.

        Args:
            database_url: PostgreSQL connection URL
        """
        if database_url.startswith("postgresql://"):
            database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)

        self._engine = create_async_engine(database_url, echo=False, pool_pre_ping=True)
        self._session_factory = async_sessionmaker(
            self._engine, class_=AsyncSession, expire_on_commit=False
        )

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        """Expose session factory for orchestration scripts."""

        return self._session_factory

    async def find_by_id(self, agent_id: UUID) -> Agent | None:
        """Retrieve an agent by its unique identifier.

        Args:
            agent_id: The unique identifier of the agent

        Returns:
            Agent if found, None otherwise

        Raises:
            RepositoryError: If persistence operation fails
        """
        try:
            async with self._session_factory() as session:
                stmt = select(AgentModel).where(AgentModel.agent_id == agent_id)
                result = await session.execute(stmt)
                model = result.scalar_one_or_none()
                return self._to_entity(model) if model else None
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to find agent by ID {agent_id}: {str(e)}", original_error=e
            ) from e

    async def find_by_tenant_id(self, tenant_id: UUID) -> list[Agent]:
        """Retrieve all agents for a tenant.

        Args:
            tenant_id: The tenant's unique identifier

        Returns:
            List of agents belonging to the tenant

        Raises:
            RepositoryError: If persistence operation fails
        """
        try:
            async with self._session_factory() as session:
                stmt = (
                    select(AgentModel)
                    .where(AgentModel.tenant_id == tenant_id)
                    .order_by(AgentModel.created_at.desc())
                )
                result = await session.execute(stmt)
                return [self._to_entity(m) for m in result.scalars().all()]
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to find agents for tenant {tenant_id}: {str(e)}", original_error=e
            ) from e

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
        try:
            async with self._session_factory() as session:
                stmt = select(AgentModel).where(
                    and_(AgentModel.tenant_id == tenant_id, AgentModel.name == name)
                )
                result = await session.execute(stmt)
                model = result.scalar_one_or_none()
                return self._to_entity(model) if model else None
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to find agent by name '{name}' for tenant {tenant_id}: {str(e)}",
                original_error=e,
            ) from e

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
        try:
            async with self._session_factory() as session:
                stmt = (
                    select(AgentModel)
                    .where(and_(AgentModel.tenant_id == tenant_id, AgentModel.status == status))
                    .order_by(AgentModel.updated_at.desc())
                )
                result = await session.execute(stmt)
                return [self._to_entity(m) for m in result.scalars().all()]
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to find agents by status {status} for tenant {tenant_id}: {str(e)}",
                original_error=e,
            ) from e

    async def find_expired_certificates(self, before_date: datetime) -> list[Agent]:
        """Find agents with certificates expiring before specified date.

        Args:
            before_date: Date to check certificate expiry against

        Returns:
            List of agents with expiring certificates

        Raises:
            RepositoryError: If persistence operation fails
        """
        try:
            async with self._session_factory() as session:
                stmt = select(AgentModel).where(
                    or_(
                        AgentModel.status == AgentStatus.ACTIVE,
                        AgentModel.status == AgentStatus.SUSPENDED,
                    )
                )
                result = await session.execute(stmt)
                models = result.scalars().all()

                # Filter by certificate expiry in application layer
                agents = []
                for model in models:
                    agent = self._to_entity(model)
                    if agent.certificate.not_valid_after <= before_date:
                        agents.append(agent)

                return agents
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to find expired certificates before {before_date}: {str(e)}",
                original_error=e,
            ) from e

    async def find_inactive_agents(self, since_date: datetime) -> list[Agent]:
        """Find agents that haven't been seen since specified date.

        Args:
            since_date: Date to check last seen against

        Returns:
            List of inactive agents

        Raises:
            RepositoryError: If persistence operation fails
        """
        try:
            async with self._session_factory() as session:
                stmt = (
                    select(AgentModel)
                    .where(
                        or_(
                            AgentModel.last_seen_at < since_date,
                            AgentModel.last_seen_at.is_(None),
                        )
                    )
                    .order_by(AgentModel.last_seen_at.desc())
                )
                result = await session.execute(stmt)
                return [self._to_entity(m) for m in result.scalars().all()]
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to find inactive agents since {since_date}: {str(e)}",
                original_error=e,
            ) from e

    async def save(self, agent: Agent) -> None:
        """Persist an agent (insert or update).

        Args:
            agent: The agent entity to persist

        Raises:
            RepositoryError: If persistence operation fails
            ConcurrencyError: If version conflict occurs during update
        """
        try:
            async with self._session_factory() as session:
                # Check if agent exists
                existing_stmt = select(AgentModel).where(AgentModel.agent_id == agent.agent_id)
                result = await session.execute(existing_stmt)
                existing = result.scalar_one_or_none()

                if existing:
                    # Update existing agent
                    if existing.version != agent.version - 1:
                        raise ConcurrencyError(
                            entity_type="Agent",
                            entity_id=agent.agent_id,
                            expected_version=agent.version - 1,
                            actual_version=existing.version,
                        )

                    # Update fields
                    existing.name = agent.name
                    existing.certificate_pem = agent.certificate.pem_data
                    existing.status = agent.status
                    existing.policy_ids = agent.policy_ids
                    existing.updated_at = agent.updated_at
                    existing.last_seen_at = agent.last_seen_at
                    existing.agent_metadata = agent.metadata
                    existing.version = agent.version
                else:
                    # Insert new agent
                    model = AgentModel(
                        agent_id=agent.agent_id,
                        tenant_id=agent.tenant_id,
                        name=agent.name,
                        certificate_pem=agent.certificate.pem_data,
                        status=agent.status,
                        policy_ids=agent.policy_ids,
                        created_at=agent.created_at,
                        updated_at=agent.updated_at,
                        last_seen_at=agent.last_seen_at,
                        agent_metadata=agent.metadata,
                        version=agent.version,
                    )
                    session.add(model)

                await session.commit()

        except ConcurrencyError:
            # Re-raise concurrency errors as-is
            raise
        except IntegrityError as e:
            raise RepositoryError(
                f"Integrity constraint violated while saving agent {agent.agent_id}: {str(e)}",
                original_error=e,
            ) from e
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to save agent {agent.agent_id}: {str(e)}", original_error=e
            ) from e

    async def delete(self, agent_id: UUID) -> bool:
        """Remove an agent from persistence.

        Args:
            agent_id: The unique identifier of the agent to delete

        Returns:
            True if deleted, False if not found

        Raises:
            RepositoryError: If persistence operation fails
        """
        try:
            async with self._session_factory() as session:
                stmt = delete(AgentModel).where(AgentModel.agent_id == agent_id)
                result = await session.execute(stmt)
                await session.commit()
                return result.rowcount > 0
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to delete agent {agent_id}: {str(e)}", original_error=e
            ) from e

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
        try:
            async with self._session_factory() as session:
                stmt = select(func.count(AgentModel.agent_id)).where(
                    and_(AgentModel.tenant_id == tenant_id, AgentModel.name == name)
                )
                result = await session.execute(stmt)
                count = result.scalar_one()
                return count > 0
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to check agent existence by name '{name}' "
                f"for tenant {tenant_id}: {str(e)}",
                original_error=e,
            ) from e

    async def exists_by_certificate_fingerprint(self, fingerprint: str) -> bool:
        """Check if an agent with given certificate fingerprint exists.

        Args:
            fingerprint: SHA256 fingerprint of the certificate

        Returns:
            True if exists, False otherwise

        Raises:
            RepositoryError: If persistence operation fails
        """
        try:
            async with self._session_factory() as session:
                # We need to load all agents and check fingerprints in application layer
                # since fingerprint is computed from certificate
                stmt = select(AgentModel)
                result = await session.execute(stmt)
                models = result.scalars().all()

                for model in models:
                    agent = self._to_entity(model)
                    if agent.certificate.fingerprint_sha256 == fingerprint:
                        return True

                return False
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to check agent existence by certificate fingerprint: {str(e)}",
                original_error=e,
            ) from e

    async def count_by_tenant(self, tenant_id: UUID) -> int:
        """Count total number of agents for a tenant.

        Args:
            tenant_id: The tenant's unique identifier

        Returns:
            Number of agents for the tenant

        Raises:
            RepositoryError: If persistence operation fails
        """
        try:
            async with self._session_factory() as session:
                stmt = select(func.count(AgentModel.agent_id)).where(
                    AgentModel.tenant_id == tenant_id
                )
                result = await session.execute(stmt)
                return result.scalar_one()
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to count agents for tenant {tenant_id}: {str(e)}", original_error=e
            ) from e

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
        try:
            async with self._session_factory() as session:
                stmt = select(func.count(AgentModel.agent_id)).where(
                    and_(AgentModel.tenant_id == tenant_id, AgentModel.status == status)
                )
                result = await session.execute(stmt)
                return result.scalar_one()
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to count agents by status {status} for tenant {tenant_id}: {str(e)}",
                original_error=e,
            ) from e

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
        try:
            async with self._session_factory() as session:
                # Use PostgreSQL's array contains operator
                stmt = (
                    select(AgentModel)
                    .where(
                        and_(
                            AgentModel.tenant_id == tenant_id,
                            AgentModel.policy_ids.contains([policy_id]),
                        )
                    )
                    .order_by(AgentModel.updated_at.desc())
                )
                result = await session.execute(stmt)
                return [self._to_entity(m) for m in result.scalars().all()]
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to find agents with policy {policy_id} for tenant {tenant_id}: {str(e)}",
                original_error=e,
            ) from e

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
        if not agent_ids:
            return 0

        try:
            async with self._session_factory() as session:
                stmt = (
                    update(AgentModel)
                    .where(AgentModel.agent_id.in_(agent_ids))
                    .values(status=new_status)
                )
                result = await session.execute(stmt)
                await session.commit()
                return result.rowcount
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to bulk update status to {new_status} "
                f"for {len(agent_ids)} agents: {str(e)}",
                original_error=e,
            ) from e

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
        try:
            async with self._session_factory() as session:
                stmt = select(AgentModel).where(AgentModel.tenant_id == tenant_id)

                if status_filter:
                    stmt = stmt.where(AgentModel.status == status_filter)

                stmt = stmt.order_by(AgentModel.created_at.desc()).offset(offset).limit(limit)

                result = await session.execute(stmt)
                return [self._to_entity(m) for m in result.scalars().all()]
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to find paginated agents for tenant {tenant_id}: {str(e)}",
                original_error=e,
            ) from e

    def _to_entity(self, model: AgentModel) -> Agent:
        """Convert SQLAlchemy model to domain entity.

        Args:
            model: AgentModel instance

        Returns:
            Agent domain entity
        """
        return Agent(
            agent_id=model.agent_id,
            tenant_id=model.tenant_id,
            name=model.name,
            certificate=X509Certificate(pem_data=model.certificate_pem),
            status=model.status,
            policy_ids=model.policy_ids or [],
            created_at=model.created_at,
            updated_at=model.updated_at,
            last_seen_at=model.last_seen_at,
            metadata=model.agent_metadata or {},
            version=model.version,
        )

    def _to_model(self, agent: Agent) -> dict[str, Any]:
        """Convert domain entity to model dictionary.

        Args:
            agent: Agent domain entity

        Returns:
            Dictionary of model attributes
        """
        return {
            "agent_id": agent.agent_id,
            "tenant_id": agent.tenant_id,
            "name": agent.name,
            "certificate_pem": agent.certificate.pem_data,
            "status": agent.status,
            "policy_ids": agent.policy_ids,
            "created_at": agent.created_at,
            "updated_at": agent.updated_at,
            "last_seen_at": agent.last_seen_at,
            "agent_metadata": agent.metadata,
            "version": agent.version,
        }
