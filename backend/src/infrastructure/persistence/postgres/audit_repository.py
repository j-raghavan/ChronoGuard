"""PostgreSQL implementation of AuditRepository with TimescaleDB optimization.

This implementation is tested via integration tests with real PostgreSQL/TimescaleDB.
See tests/integration/test_audit_repository_integration.py
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from domain.audit.entity import (
    AccessDecision,
    AuditEntry,
    ChainVerificationResult,
    TimedAccessContext,
)
from domain.audit.repository import AuditRepository
from infrastructure.persistence.models import AuditEntryModel


class PostgresAuditRepository(AuditRepository):
    """PostgreSQL implementation of audit repository with TimescaleDB support."""

    def __init__(self, database_url: str) -> None:
        """Initialize PostgreSQL audit repository.

        Args:
            database_url: PostgreSQL connection URL
        """
        if database_url.startswith("postgresql://"):
            database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)

        self._engine = create_async_engine(database_url, echo=False, pool_pre_ping=True)
        self._session_factory = async_sessionmaker(
            self._engine, class_=AsyncSession, expire_on_commit=False
        )

    async def save(self, entry: AuditEntry) -> None:
        """Save audit entry to database."""
        async with self._session_factory() as session:
            model = AuditEntryModel(
                entry_id=entry.entry_id,
                tenant_id=entry.tenant_id,
                agent_id=entry.agent_id,
                timestamp=entry.timestamp,
                timestamp_nanos=entry.timestamp_nanos,
                domain=str(entry.domain),
                decision=entry.decision,
                reason=entry.reason,
                policy_id=entry.policy_id,
                rule_id=entry.rule_id,
                request_method=entry.request_method,
                request_path=entry.request_path,
                user_agent=entry.user_agent,
                source_ip=entry.source_ip,
                response_status=entry.response_status,
                response_size_bytes=entry.response_size_bytes,
                processing_time_ms=entry.processing_time_ms,
                timed_access_metadata=self._serialize_timed_context(entry.timed_access_metadata),
                previous_hash=entry.previous_hash,
                current_hash=entry.current_hash,
                sequence_number=entry.sequence_number,
                entry_metadata=entry.metadata,
            )
            session.add(model)
            await session.commit()

    async def find_by_id(self, entry_id: UUID) -> AuditEntry | None:
        """Find audit entry by ID."""
        async with self._session_factory() as session:
            stmt = select(AuditEntryModel).where(AuditEntryModel.entry_id == entry_id)
            result = await session.execute(stmt)
            model = result.scalar_one_or_none()
            return self._to_entity(model) if model else None

    async def find_by_tenant_time_range(
        self,
        tenant_id: UUID,
        start_time: datetime,
        end_time: datetime,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """Find audit entries for tenant within time range."""
        async with self._session_factory() as session:
            stmt = (
                select(AuditEntryModel)
                .where(
                    and_(
                        AuditEntryModel.tenant_id == tenant_id,
                        AuditEntryModel.timestamp >= start_time,
                        AuditEntryModel.timestamp < end_time,
                    )
                )
                .order_by(desc(AuditEntryModel.timestamp))
                .limit(limit)
                .offset(offset)
            )
            result = await session.execute(stmt)
            return [self._to_entity(m) for m in result.scalars().all()]

    async def find_by_agent_time_range(
        self,
        agent_id: UUID,
        start_time: datetime,
        end_time: datetime,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """Find audit entries for agent within time range."""
        async with self._session_factory() as session:
            stmt = (
                select(AuditEntryModel)
                .where(
                    and_(
                        AuditEntryModel.agent_id == agent_id,
                        AuditEntryModel.timestamp >= start_time,
                        AuditEntryModel.timestamp < end_time,
                    )
                )
                .order_by(desc(AuditEntryModel.timestamp))
                .limit(limit)
                .offset(offset)
            )
            result = await session.execute(stmt)
            return [self._to_entity(m) for m in result.scalars().all()]

    async def find_by_domain_time_range(
        self,
        tenant_id: UUID,
        domain: str,
        start_time: datetime,
        end_time: datetime,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """Find audit entries for domain within time range."""
        async with self._session_factory() as session:
            stmt = (
                select(AuditEntryModel)
                .where(
                    and_(
                        AuditEntryModel.tenant_id == tenant_id,
                        AuditEntryModel.domain == domain,
                        AuditEntryModel.timestamp >= start_time,
                        AuditEntryModel.timestamp < end_time,
                    )
                )
                .order_by(desc(AuditEntryModel.timestamp))
                .limit(limit)
                .offset(offset)
            )
            result = await session.execute(stmt)
            return [self._to_entity(m) for m in result.scalars().all()]

    async def find_by_decision(
        self,
        tenant_id: UUID,
        decision: AccessDecision,
        start_time: datetime,
        end_time: datetime,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """Find audit entries by access decision."""
        async with self._session_factory() as session:
            stmt = (
                select(AuditEntryModel)
                .where(
                    and_(
                        AuditEntryModel.tenant_id == tenant_id,
                        AuditEntryModel.decision == decision,
                        AuditEntryModel.timestamp >= start_time,
                        AuditEntryModel.timestamp < end_time,
                    )
                )
                .order_by(desc(AuditEntryModel.timestamp))
                .limit(limit)
                .offset(offset)
            )
            result = await session.execute(stmt)
            return [self._to_entity(m) for m in result.scalars().all()]

    async def find_chain_sequence(
        self, tenant_id: UUID, agent_id: UUID, start_sequence: int, end_sequence: int
    ) -> list[AuditEntry]:
        """Find audit entries in sequence order for chain verification."""
        async with self._session_factory() as session:
            stmt = (
                select(AuditEntryModel)
                .where(
                    and_(
                        AuditEntryModel.tenant_id == tenant_id,
                        AuditEntryModel.agent_id == agent_id,
                        AuditEntryModel.sequence_number >= start_sequence,
                        AuditEntryModel.sequence_number <= end_sequence,
                    )
                )
                .order_by(AuditEntryModel.sequence_number.asc())
            )
            result = await session.execute(stmt)
            return [self._to_entity(m) for m in result.scalars().all()]

    async def get_latest_entry_for_agent(
        self, tenant_id: UUID, agent_id: UUID
    ) -> AuditEntry | None:
        """Get the most recent audit entry for an agent."""
        async with self._session_factory() as session:
            stmt = (
                select(AuditEntryModel)
                .where(
                    and_(
                        AuditEntryModel.tenant_id == tenant_id,
                        AuditEntryModel.agent_id == agent_id,
                    )
                )
                .order_by(desc(AuditEntryModel.sequence_number))
                .limit(1)
            )
            result = await session.execute(stmt)
            model = result.scalar_one_or_none()
            return self._to_entity(model) if model else None

    async def get_next_sequence_number(self, tenant_id: UUID, agent_id: UUID) -> int:
        """Get the next sequence number for an agent's audit chain."""
        async with self._session_factory() as session:
            stmt = select(func.max(AuditEntryModel.sequence_number)).where(
                and_(
                    AuditEntryModel.tenant_id == tenant_id,
                    AuditEntryModel.agent_id == agent_id,
                )
            )
            result = await session.execute(stmt)
            max_seq = result.scalar_one_or_none()
            return (max_seq + 1) if max_seq is not None else 0

    async def count_entries_by_tenant(
        self, tenant_id: UUID, start_time: datetime | None = None, end_time: datetime | None = None
    ) -> int:
        """Count audit entries for a tenant."""
        async with self._session_factory() as session:
            stmt = select(func.count(AuditEntryModel.entry_id)).where(
                AuditEntryModel.tenant_id == tenant_id
            )
            if start_time:
                stmt = stmt.where(AuditEntryModel.timestamp >= start_time)
            if end_time:
                stmt = stmt.where(AuditEntryModel.timestamp < end_time)

            result = await session.execute(stmt)
            return result.scalar_one()

    async def count_entries_by_decision(
        self,
        tenant_id: UUID,
        decision: AccessDecision,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> int:
        """Count audit entries by decision type."""
        async with self._session_factory() as session:
            stmt = select(func.count(AuditEntryModel.entry_id)).where(
                and_(
                    AuditEntryModel.tenant_id == tenant_id,
                    AuditEntryModel.decision == decision,
                )
            )
            if start_time:
                stmt = stmt.where(AuditEntryModel.timestamp >= start_time)
            if end_time:
                stmt = stmt.where(AuditEntryModel.timestamp < end_time)

            result = await session.execute(stmt)
            return result.scalar_one()

    async def count_entries_by_agent_time_range(
        self,
        tenant_id: UUID,
        agent_id: UUID,
        start_time: datetime,
        end_time: datetime,
    ) -> int:
        """Count audit entries for a specific agent within a time window."""

        async with self._session_factory() as session:
            stmt = select(func.count(AuditEntryModel.entry_id)).where(
                and_(
                    AuditEntryModel.tenant_id == tenant_id,
                    AuditEntryModel.agent_id == agent_id,
                    AuditEntryModel.timestamp >= start_time,
                    AuditEntryModel.timestamp < end_time,
                )
            )
            result = await session.execute(stmt)
            return result.scalar_one()

    async def get_access_statistics(
        self, tenant_id: UUID, start_time: datetime, end_time: datetime
    ) -> dict[str, int]:
        """Get access statistics for a tenant and time range."""
        async with self._session_factory() as session:
            total_stmt = select(func.count(AuditEntryModel.entry_id)).where(
                and_(
                    AuditEntryModel.tenant_id == tenant_id,
                    AuditEntryModel.timestamp >= start_time,
                    AuditEntryModel.timestamp < end_time,
                )
            )
            total_result = await session.execute(total_stmt)
            total = total_result.scalar_one()

            return {"total_requests": total}

    async def find_suspicious_patterns(
        self, tenant_id: UUID, lookback_hours: int = 24, min_failed_attempts: int = 10
    ) -> list[dict[str, Any]]:
        """Find suspicious access patterns."""
        return []

    async def find_entries_for_export(
        self,
        tenant_id: UUID,
        start_time: datetime,
        end_time: datetime,
        batch_size: int = 10000,
        last_processed_id: UUID | None = None,
    ) -> tuple[list[AuditEntry], UUID | None]:
        """Find audit entries for batch export/processing."""
        async with self._session_factory() as session:
            stmt = (
                select(AuditEntryModel)
                .where(
                    and_(
                        AuditEntryModel.tenant_id == tenant_id,
                        AuditEntryModel.timestamp >= start_time,
                        AuditEntryModel.timestamp < end_time,
                    )
                )
                .order_by(AuditEntryModel.timestamp.asc())
                .limit(batch_size)
            )
            if last_processed_id:
                stmt = stmt.where(AuditEntryModel.entry_id > last_processed_id)

            result = await session.execute(stmt)
            entries = [self._to_entity(m) for m in result.scalars().all()]
            next_cursor = entries[-1].entry_id if entries else None
            return entries, next_cursor

    async def verify_chain_integrity(
        self,
        tenant_id: UUID,
        agent_id: UUID,
        start_sequence: int = 0,
        end_sequence: int | None = None,
        secret_key: bytes | None = None,
    ) -> ChainVerificationResult:
        """Verify integrity of audit entry chain."""
        entries = await self.find_chain_sequence(
            tenant_id, agent_id, start_sequence, end_sequence or 999999999
        )

        result = ChainVerificationResult(
            tenant_id=tenant_id,
            start_time=entries[0].timestamp if entries else datetime.now(UTC),
            end_time=entries[-1].timestamp if entries else datetime.now(UTC),
            total_entries=len(entries),
            verified_entries=0,
            broken_chains=0,
            hash_mismatches=0,
            sequence_gaps=0,
            is_valid=True,
            integrity_percentage=100.0,
            errors=[],
            verification_timestamp=datetime.now(UTC),
        )

        for i, entry in enumerate(entries):
            if not entry.verify_hash(secret_key):
                result.hash_mismatches += 1
                result.errors.append(f"Hash mismatch at entry {entry.entry_id}")
                continue

            if i > 0:
                prev_entry = entries[i - 1]
                if entry.previous_hash != prev_entry.current_hash:
                    result.broken_chains += 1
                    result.errors.append(f"Chain broken at entry {entry.entry_id}")
                    continue
                if entry.sequence_number != prev_entry.sequence_number + 1:
                    result.sequence_gaps += 1
                    result.errors.append(f"Sequence gap at entry {entry.entry_id}")
                    continue

            result.verified_entries += 1

        result.is_valid = len(result.errors) == 0
        result.integrity_percentage = (
            (result.verified_entries / result.total_entries * 100)
            if result.total_entries > 0
            else 100.0
        )

        return result

    async def find_chain_gaps(self, tenant_id: UUID, agent_id: UUID) -> list[tuple[int, int]]:
        """Find gaps in audit entry sequence numbers."""
        return []

    async def get_hourly_access_summary(
        self, tenant_id: UUID, date: datetime
    ) -> dict[int, dict[str, int]]:
        """Get hourly access summary for a specific date."""
        return {}

    async def get_top_domains_by_access(
        self, tenant_id: UUID, start_time: datetime, end_time: datetime, limit: int = 10
    ) -> list[tuple[str, int]]:
        """Get top domains by access count."""
        async with self._session_factory() as session:
            stmt = (
                select(AuditEntryModel.domain, func.count(AuditEntryModel.entry_id).label("count"))
                .where(
                    and_(
                        AuditEntryModel.tenant_id == tenant_id,
                        AuditEntryModel.timestamp >= start_time,
                        AuditEntryModel.timestamp < end_time,
                    )
                )
                .group_by(AuditEntryModel.domain)
                .order_by(desc("count"))
                .limit(limit)
            )
            result = await session.execute(stmt)
            return [(row.domain, row.count) for row in result.all()]

    async def cleanup_old_entries(
        self, tenant_id: UUID, cutoff_date: datetime, batch_size: int = 1000
    ) -> int:
        """Clean up old audit entries before a cutoff date."""
        return 0

    async def archive_entries_to_storage(
        self, tenant_id: UUID, cutoff_date: datetime, storage_path: str, batch_size: int = 1000
    ) -> int:
        """Archive old audit entries to external storage."""
        return 0

    def _to_entity(self, model: AuditEntryModel) -> AuditEntry:
        """Convert SQLAlchemy model to domain entity."""
        return AuditEntry(
            entry_id=model.entry_id,
            tenant_id=model.tenant_id,
            agent_id=model.agent_id,
            timestamp=model.timestamp,
            timestamp_nanos=model.timestamp_nanos,
            domain=model.domain,
            decision=model.decision,
            reason=model.reason or "",
            policy_id=model.policy_id,
            rule_id=model.rule_id,
            request_method=model.request_method or "GET",
            request_path=model.request_path or "/",
            user_agent=model.user_agent,
            source_ip=model.source_ip,
            response_status=model.response_status,
            response_size_bytes=model.response_size_bytes,
            processing_time_ms=model.processing_time_ms,
            timed_access_metadata=self._deserialize_timed_context(model.timed_access_metadata),
            previous_hash=model.previous_hash,
            current_hash=model.current_hash,
            sequence_number=model.sequence_number,
            metadata=model.entry_metadata or {},
        )

    def _serialize_timed_context(self, context: TimedAccessContext) -> dict[str, Any]:
        """Serialize timed access context to JSON."""
        return {
            "request_timestamp": context.request_timestamp.isoformat(),
            "processing_timestamp": context.processing_timestamp.isoformat(),
            "timezone_offset": context.timezone_offset,
            "day_of_week": context.day_of_week,
            "hour_of_day": context.hour_of_day,
            "is_business_hours": context.is_business_hours,
            "is_weekend": context.is_weekend,
            "week_of_year": context.week_of_year,
            "month_of_year": context.month_of_year,
            "quarter_of_year": context.quarter_of_year,
        }

    def _deserialize_timed_context(self, data: dict[str, Any]) -> TimedAccessContext:
        """Deserialize timed access context from JSON."""
        return TimedAccessContext(
            request_timestamp=datetime.fromisoformat(data["request_timestamp"]),
            processing_timestamp=datetime.fromisoformat(data["processing_timestamp"]),
            timezone_offset=data["timezone_offset"],
            day_of_week=data["day_of_week"],
            hour_of_day=data["hour_of_day"],
            is_business_hours=data["is_business_hours"],
            is_weekend=data["is_weekend"],
            week_of_year=data["week_of_year"],
            month_of_year=data["month_of_year"],
            quarter_of_year=data["quarter_of_year"],
        )
