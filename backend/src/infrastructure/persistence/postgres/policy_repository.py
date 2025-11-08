"""PostgreSQL implementation of PolicyRepository following DDD principles.

This implementation provides full persistence capabilities for policy entities
using SQLAlchemy and PostgreSQL with proper error handling and type safety.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from domain.common.exceptions import ConcurrencyError
from domain.common.value_objects.time_range import TimeRange
from domain.policy.entity import (
    Policy,
    PolicyRule,
    PolicyStatus,
    RateLimit,
    RuleCondition,
    TimeRestriction,
)
from domain.policy.repository import PolicyRepository
from infrastructure.persistence.models import PolicyModel
from sqlalchemy import and_, delete, desc, func, or_, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


class RepositoryError(Exception):
    """Exception raised for repository operation failures."""

    def __init__(self, message: str, original_error: Exception | None = None) -> None:
        """Initialize repository error.

        Args:
            message: Error description
            original_error: Original exception that caused this error
        """
        super().__init__(message)
        self.original_error = original_error


class PostgresPolicyRepository(PolicyRepository):
    """PostgreSQL implementation of policy repository with comprehensive query support.

    This repository handles all persistence operations for policy entities,
    including complex queries, JSON serialization, and proper error handling.
    Tested via integration tests in tests/integration/test_policy_repository_integration.py
    """

    def __init__(self, database_url: str) -> None:
        """Initialize PostgreSQL policy repository.

        Args:
            database_url: PostgreSQL connection URL
        """
        if database_url.startswith("postgresql://"):
            database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)

        self._engine = create_async_engine(database_url, echo=False, pool_pre_ping=True)
        self._session_factory = async_sessionmaker(
            self._engine, class_=AsyncSession, expire_on_commit=False
        )

    async def find_by_id(self, policy_id: UUID) -> Policy | None:
        """Retrieve a policy by its unique identifier.

        Args:
            policy_id: The unique identifier of the policy

        Returns:
            Policy if found, None otherwise

        Raises:
            RepositoryError: If persistence operation fails
        """
        try:
            async with self._session_factory() as session:
                stmt = select(PolicyModel).where(PolicyModel.policy_id == policy_id)
                result = await session.execute(stmt)
                model = result.scalar_one_or_none()
                return self._to_entity(model) if model else None
        except SQLAlchemyError as e:
            raise RepositoryError(f"Failed to find policy by ID {policy_id}", e) from e

    async def find_by_tenant_id(self, tenant_id: UUID) -> list[Policy]:
        """Retrieve all policies for a tenant.

        Args:
            tenant_id: The tenant's unique identifier

        Returns:
            List of policies belonging to the tenant

        Raises:
            RepositoryError: If persistence operation fails
        """
        try:
            async with self._session_factory() as session:
                stmt = (
                    select(PolicyModel)
                    .where(PolicyModel.tenant_id == tenant_id)
                    .order_by(desc(PolicyModel.priority))
                )
                result = await session.execute(stmt)
                return [self._to_entity(m) for m in result.scalars().all()]
        except SQLAlchemyError as e:
            raise RepositoryError(f"Failed to find policies for tenant {tenant_id}", e) from e

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
        try:
            async with self._session_factory() as session:
                stmt = select(PolicyModel).where(
                    and_(PolicyModel.tenant_id == tenant_id, PolicyModel.name == name)
                )
                result = await session.execute(stmt)
                model = result.scalar_one_or_none()
                return self._to_entity(model) if model else None
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to find policy by name '{name}' for tenant {tenant_id}", e
            ) from e

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
        try:
            async with self._session_factory() as session:
                stmt = (
                    select(PolicyModel)
                    .where(
                        and_(
                            PolicyModel.tenant_id == tenant_id,
                            PolicyModel.status == status,
                        )
                    )
                    .order_by(desc(PolicyModel.priority))
                )
                result = await session.execute(stmt)
                return [self._to_entity(m) for m in result.scalars().all()]
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to find policies by status {status} for tenant {tenant_id}", e
            ) from e

    async def find_active_policies(self, tenant_id: UUID) -> list[Policy]:
        """Find all active policies for a tenant.

        Args:
            tenant_id: The tenant's unique identifier

        Returns:
            List of active policies

        Raises:
            RepositoryError: If persistence operation fails
        """
        return await self.find_by_status(tenant_id, PolicyStatus.ACTIVE)

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
        try:
            async with self._session_factory() as session:
                stmt = (
                    select(PolicyModel)
                    .where(
                        and_(
                            PolicyModel.tenant_id == tenant_id,
                            PolicyModel.priority >= min_priority,
                            PolicyModel.priority <= max_priority,
                        )
                    )
                    .order_by(desc(PolicyModel.priority))
                )
                result = await session.execute(stmt)
                return [self._to_entity(m) for m in result.scalars().all()]
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to find policies by priority range [{min_priority}, {max_priority}]", e
            ) from e

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
        try:
            async with self._session_factory() as session:
                stmt = (
                    select(PolicyModel)
                    .where(
                        and_(
                            PolicyModel.tenant_id == tenant_id,
                            or_(
                                PolicyModel.allowed_domains.any(domain),
                                PolicyModel.blocked_domains.any(domain),
                            ),
                        )
                    )
                    .order_by(desc(PolicyModel.priority))
                )
                result = await session.execute(stmt)
                return [self._to_entity(m) for m in result.scalars().all()]
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to find policies with domain '{domain}' for tenant {tenant_id}", e
            ) from e

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
        try:
            async with self._session_factory() as session:
                stmt = (
                    select(PolicyModel)
                    .where(
                        and_(
                            PolicyModel.tenant_id == tenant_id,
                            PolicyModel.created_by == created_by,
                        )
                    )
                    .order_by(desc(PolicyModel.created_at))
                )
                result = await session.execute(stmt)
                return [self._to_entity(m) for m in result.scalars().all()]
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to find policies created by {created_by} for tenant {tenant_id}", e
            ) from e

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
        try:
            async with self._session_factory() as session:
                stmt = (
                    select(PolicyModel)
                    .where(
                        and_(
                            PolicyModel.tenant_id == tenant_id,
                            PolicyModel.updated_at >= since_date,
                        )
                    )
                    .order_by(desc(PolicyModel.updated_at))
                )
                result = await session.execute(stmt)
                return [self._to_entity(m) for m in result.scalars().all()]
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to find policies updated since {since_date} for tenant {tenant_id}", e
            ) from e

    async def save(self, policy: Policy) -> None:
        """Persist a policy (insert or update).

        Args:
            policy: The policy entity to persist

        Raises:
            RepositoryError: If persistence operation fails
            ConcurrencyError: If version conflict occurs during update
        """
        try:
            async with self._session_factory() as session:
                stmt = select(PolicyModel).where(PolicyModel.policy_id == policy.policy_id)
                result = await session.execute(stmt)
                existing = result.scalar_one_or_none()

                if existing:
                    if existing.version != policy.version - 1:
                        raise ConcurrencyError(
                            f"Version conflict for policy {policy.policy_id}: "
                            f"expected {existing.version}, got {policy.version - 1}"
                        )

                    existing.tenant_id = policy.tenant_id
                    existing.name = policy.name
                    existing.description = policy.description
                    existing.rules = self._serialize_rules(policy.rules)
                    existing.time_restrictions = self._serialize_time_restrictions(
                        policy.time_restrictions
                    )
                    existing.rate_limits = self._serialize_rate_limits(policy.rate_limits)
                    existing.priority = policy.priority
                    existing.status = policy.status
                    existing.allowed_domains = list(policy.allowed_domains)
                    existing.blocked_domains = list(policy.blocked_domains)
                    existing.updated_at = policy.updated_at
                    existing.created_by = policy.created_by
                    existing.version = policy.version
                    existing.policy_metadata = policy.metadata
                else:
                    model = PolicyModel(
                        policy_id=policy.policy_id,
                        tenant_id=policy.tenant_id,
                        name=policy.name,
                        description=policy.description,
                        rules=self._serialize_rules(policy.rules),
                        time_restrictions=self._serialize_time_restrictions(
                            policy.time_restrictions
                        ),
                        rate_limits=self._serialize_rate_limits(policy.rate_limits),
                        priority=policy.priority,
                        status=policy.status,
                        allowed_domains=list(policy.allowed_domains),
                        blocked_domains=list(policy.blocked_domains),
                        created_at=policy.created_at,
                        updated_at=policy.updated_at,
                        created_by=policy.created_by,
                        version=policy.version,
                        policy_metadata=policy.metadata,
                    )
                    session.add(model)

                await session.commit()
        except ConcurrencyError:
            raise
        except IntegrityError as e:
            raise RepositoryError(
                f"Integrity constraint violated while saving policy {policy.policy_id}", e
            ) from e
        except SQLAlchemyError as e:
            raise RepositoryError(f"Failed to save policy {policy.policy_id}", e) from e

    async def delete(self, policy_id: UUID) -> bool:
        """Remove a policy from persistence.

        Args:
            policy_id: The unique identifier of the policy to delete

        Returns:
            True if deleted, False if not found

        Raises:
            RepositoryError: If persistence operation fails
        """
        try:
            async with self._session_factory() as session:
                stmt = delete(PolicyModel).where(PolicyModel.policy_id == policy_id)
                result = await session.execute(stmt)
                await session.commit()
                return result.rowcount > 0
        except SQLAlchemyError as e:
            raise RepositoryError(f"Failed to delete policy {policy_id}", e) from e

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
        try:
            async with self._session_factory() as session:
                stmt = select(func.count(PolicyModel.policy_id)).where(
                    and_(PolicyModel.tenant_id == tenant_id, PolicyModel.name == name)
                )
                result = await session.execute(stmt)
                count = result.scalar_one()
                return count > 0
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to check existence of policy '{name}' for tenant {tenant_id}", e
            ) from e

    async def count_by_tenant(self, tenant_id: UUID) -> int:
        """Count total number of policies for a tenant.

        Args:
            tenant_id: The tenant's unique identifier

        Returns:
            Number of policies for the tenant

        Raises:
            RepositoryError: If persistence operation fails
        """
        try:
            async with self._session_factory() as session:
                stmt = select(func.count(PolicyModel.policy_id)).where(
                    PolicyModel.tenant_id == tenant_id
                )
                result = await session.execute(stmt)
                return result.scalar_one()
        except SQLAlchemyError as e:
            raise RepositoryError(f"Failed to count policies for tenant {tenant_id}", e) from e

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
        try:
            async with self._session_factory() as session:
                stmt = select(func.count(PolicyModel.policy_id)).where(
                    and_(PolicyModel.tenant_id == tenant_id, PolicyModel.status == status)
                )
                result = await session.execute(stmt)
                return result.scalar_one()
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to count policies by status {status} for tenant {tenant_id}", e
            ) from e

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
        try:
            async with self._session_factory() as session:
                stmt = (
                    select(PolicyModel)
                    .where(
                        and_(
                            PolicyModel.tenant_id == tenant_id,
                            PolicyModel.status == PolicyStatus.ACTIVE,
                        )
                    )
                    .order_by(desc(PolicyModel.priority))
                )
                result = await session.execute(stmt)
                all_active_policies = [self._to_entity(m) for m in result.scalars().all()]

                relevant_policies = []
                for policy in all_active_policies:
                    if (
                        domain in policy.allowed_domains
                        or domain in policy.blocked_domains
                        or (not policy.allowed_domains and not policy.blocked_domains)
                    ):
                        relevant_policies.append(policy)

                return relevant_policies
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to find policies for evaluation of domain '{domain}'", e
            ) from e

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
        try:
            async with self._session_factory() as session:
                stmt = (
                    update(PolicyModel)
                    .where(PolicyModel.policy_id.in_(policy_ids))
                    .values(status=new_status)
                )
                result = await session.execute(stmt)
                await session.commit()
                return result.rowcount
        except SQLAlchemyError as e:
            raise RepositoryError(f"Failed to bulk update status to {new_status}", e) from e

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
        try:
            async with self._session_factory() as session:
                stmt = select(PolicyModel).where(PolicyModel.tenant_id == tenant_id)

                if status_filter:
                    stmt = stmt.where(PolicyModel.status == status_filter)

                stmt = stmt.order_by(desc(PolicyModel.priority)).offset(offset).limit(limit)

                result = await session.execute(stmt)
                return [self._to_entity(m) for m in result.scalars().all()]
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to find paginated policies for tenant {tenant_id}", e
            ) from e

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
        try:
            async with self._session_factory() as session:
                stmt = select(PolicyModel).where(
                    and_(PolicyModel.tenant_id == tenant_id, PolicyModel.priority == priority)
                )

                if exclude_policy_id:
                    stmt = stmt.where(PolicyModel.policy_id != exclude_policy_id)

                result = await session.execute(stmt)
                return [self._to_entity(m) for m in result.scalars().all()]
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to find duplicate priority {priority} for tenant {tenant_id}", e
            ) from e

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
        try:
            async with self._session_factory() as session:
                search_pattern = f"%{search_term}%"

                stmt = select(PolicyModel).where(
                    and_(
                        PolicyModel.tenant_id == tenant_id,
                        or_(
                            PolicyModel.name.ilike(search_pattern),
                            PolicyModel.description.ilike(search_pattern),
                        ),
                    )
                )

                if status_filter:
                    stmt = stmt.where(PolicyModel.status == status_filter)

                stmt = stmt.order_by(desc(PolicyModel.priority)).limit(limit)

                result = await session.execute(stmt)
                return [self._to_entity(m) for m in result.scalars().all()]
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"Failed to search policies for term '{search_term}' in tenant {tenant_id}", e
            ) from e

    def _to_entity(self, model: PolicyModel) -> Policy:
        """Convert SQLAlchemy model to domain entity.

        Args:
            model: PolicyModel instance

        Returns:
            Policy domain entity
        """
        return Policy(
            policy_id=model.policy_id,
            tenant_id=model.tenant_id,
            name=model.name,
            description=model.description,
            rules=self._deserialize_rules(model.rules),
            time_restrictions=self._deserialize_time_restrictions(model.time_restrictions),
            rate_limits=self._deserialize_rate_limits(model.rate_limits),
            priority=model.priority,
            status=model.status,
            allowed_domains=set(model.allowed_domains or []),
            blocked_domains=set(model.blocked_domains or []),
            created_at=model.created_at,
            updated_at=model.updated_at,
            created_by=model.created_by,
            version=model.version,
            metadata=model.policy_metadata or {},
        )

    def _serialize_rules(self, rules: list[PolicyRule]) -> list[dict[str, Any]]:
        """Serialize policy rules to JSON-compatible format.

        Args:
            rules: List of PolicyRule domain objects

        Returns:
            List of dictionaries representing rules
        """
        return [
            {
                "rule_id": str(rule.rule_id),
                "name": rule.name,
                "description": rule.description,
                "conditions": [
                    {"field": c.field, "operator": c.operator, "value": c.value}
                    for c in rule.conditions
                ],
                "action": rule.action.value,
                "priority": rule.priority,
                "enabled": rule.enabled,
                "metadata": rule.metadata,
            }
            for rule in rules
        ]

    def _deserialize_rules(self, rules_data: list[dict[str, Any]]) -> list[PolicyRule]:
        """Deserialize policy rules from JSON format.

        Args:
            rules_data: List of dictionaries representing rules

        Returns:
            List of PolicyRule domain objects
        """
        if not rules_data:
            return []

        return [
            PolicyRule(
                rule_id=UUID(rule["rule_id"]),
                name=rule["name"],
                description=rule["description"],
                conditions=[
                    RuleCondition(field=c["field"], operator=c["operator"], value=c["value"])
                    for c in rule["conditions"]
                ],
                action=rule["action"],
                priority=rule["priority"],
                enabled=rule["enabled"],
                metadata=rule.get("metadata", {}),
            )
            for rule in rules_data
        ]

    def _serialize_time_restrictions(
        self, time_restrictions: TimeRestriction | None
    ) -> dict[str, Any] | None:
        """Serialize time restrictions to JSON format.

        Args:
            time_restrictions: TimeRestriction object or None

        Returns:
            Dictionary representation or None
        """
        if not time_restrictions:
            return None

        return {
            "allowed_time_ranges": [
                {
                    "start_hour": tr.start_hour,
                    "start_minute": tr.start_minute,
                    "end_hour": tr.end_hour,
                    "end_minute": tr.end_minute,
                    "timezone_name": tr.timezone_name,
                }
                for tr in time_restrictions.allowed_time_ranges
            ],
            "allowed_days_of_week": list(time_restrictions.allowed_days_of_week),
            "timezone": time_restrictions.timezone,
            "enabled": time_restrictions.enabled,
        }

    def _deserialize_time_restrictions(self, data: dict[str, Any] | None) -> TimeRestriction | None:
        """Deserialize time restrictions from JSON format.

        Args:
            data: Dictionary representation or None

        Returns:
            TimeRestriction object or None
        """
        if not data:
            return None

        return TimeRestriction(
            allowed_time_ranges=[
                TimeRange(
                    start_hour=tr["start_hour"],
                    start_minute=tr["start_minute"],
                    end_hour=tr["end_hour"],
                    end_minute=tr["end_minute"],
                    timezone_name=tr.get("timezone_name", "UTC"),
                )
                for tr in data["allowed_time_ranges"]
            ],
            allowed_days_of_week=set(data["allowed_days_of_week"]),
            timezone=data["timezone"],
            enabled=data["enabled"],
        )

    def _serialize_rate_limits(self, rate_limits: RateLimit | None) -> dict[str, Any] | None:
        """Serialize rate limits to JSON format.

        Args:
            rate_limits: RateLimit object or None

        Returns:
            Dictionary representation or None
        """
        if not rate_limits:
            return None

        return {
            "requests_per_minute": rate_limits.requests_per_minute,
            "requests_per_hour": rate_limits.requests_per_hour,
            "requests_per_day": rate_limits.requests_per_day,
            "burst_limit": rate_limits.burst_limit,
            "enabled": rate_limits.enabled,
        }

    def _deserialize_rate_limits(self, data: dict[str, Any] | None) -> RateLimit | None:
        """Deserialize rate limits from JSON format.

        Args:
            data: Dictionary representation or None

        Returns:
            RateLimit object or None
        """
        if not data:
            return None

        return RateLimit(
            requests_per_minute=data["requests_per_minute"],
            requests_per_hour=data["requests_per_hour"],
            requests_per_day=data["requests_per_day"],
            burst_limit=data["burst_limit"],
            enabled=data["enabled"],
        )
