"""Integration tests for audit repository with real PostgreSQL/TimescaleDB."""

import time
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from domain.audit.entity import AccessDecision, AuditEntry, TimedAccessContext
from domain.common.value_objects import DomainName
from infrastructure.persistence.postgres.audit_repository import PostgresAuditRepository


@pytest.mark.asyncio
class TestAuditRepositoryIntegration:
    """Integration tests for PostgreSQL audit repository."""

    async def test_save_and_retrieve_audit_entry(
        self, database_url: str, clean_database: None, test_tenant_id: UUID, test_agent_id: UUID
    ) -> None:
        """Test saving and retrieving audit entries with real database."""
        repository = PostgresAuditRepository(database_url)

        now = datetime.now(UTC)
        timed_context = TimedAccessContext.create_from_timestamp(now)

        entry = AuditEntry(
            tenant_id=test_tenant_id,
            agent_id=test_agent_id,
            timestamp=now,
            domain=DomainName(value="example.com"),
            decision=AccessDecision.ALLOW,
            reason="Policy match",
            request_method="GET",
            request_path="/api/data",
            timed_access_metadata=timed_context,
            sequence_number=1,
        )

        entry_with_hash = entry.with_hash("", None)

        await repository.save(entry_with_hash)

        retrieved = await repository.find_by_id(entry_with_hash.entry_id)

        assert retrieved is not None
        assert retrieved.entry_id == entry_with_hash.entry_id
        assert retrieved.tenant_id == test_tenant_id
        assert str(retrieved.domain) == "example.com"
        assert retrieved.decision == AccessDecision.ALLOW

    async def test_hash_chain_integrity(
        self, database_url: str, clean_database: None, test_tenant_id: UUID, test_agent_id: UUID
    ) -> None:
        """Test hash chain integrity with multiple entries."""
        repository = PostgresAuditRepository(database_url)

        entries = []
        previous_hash = ""

        for i in range(10):
            now = datetime.now(UTC) + timedelta(microseconds=i * 1000)
            timed_context = TimedAccessContext.create_from_timestamp(now)

            entry = AuditEntry(
                tenant_id=test_tenant_id,
                agent_id=test_agent_id,
                timestamp=now,
                timestamp_nanos=time.time_ns() + i * 1000,
                domain=DomainName(value=f"example{i}.com"),
                decision=AccessDecision.ALLOW if i % 2 == 0 else AccessDecision.DENY,
                reason=f"Test entry {i}",
                request_method="GET",
                request_path=f"/path/{i}",
                timed_access_metadata=timed_context,
                sequence_number=i,
            )

            entry_with_hash = entry.with_hash(previous_hash, None)
            await repository.save(entry_with_hash)

            entries.append(entry_with_hash)
            previous_hash = entry_with_hash.current_hash

        retrieved_entries = await repository.find_by_tenant_time_range(
            test_tenant_id,
            entries[0].timestamp - timedelta(seconds=1),
            entries[-1].timestamp + timedelta(seconds=1),
            limit=100,
        )

        assert len(retrieved_entries) == 10

        for i in range(len(retrieved_entries)):
            if i > 0:
                assert retrieved_entries[i].previous_hash == retrieved_entries[i - 1].current_hash

    async def test_find_by_decision(
        self, database_url: str, clean_database: None, test_tenant_id: UUID, test_agent_id: UUID
    ) -> None:
        """Test filtering entries by decision type."""
        repository = PostgresAuditRepository(database_url)

        base_time = datetime.now(UTC)

        for i in range(20):
            timed_context = TimedAccessContext.create_from_timestamp(
                base_time + timedelta(seconds=i)
            )

            entry = AuditEntry(
                tenant_id=test_tenant_id,
                agent_id=test_agent_id,
                timestamp=base_time + timedelta(seconds=i),
                domain=DomainName(value=f"test{i}.com"),
                decision=AccessDecision.DENY if i % 3 == 0 else AccessDecision.ALLOW,
                reason=f"Entry {i}",
                request_method="GET",
                request_path=f"/path/{i}",
                timed_access_metadata=timed_context,
                sequence_number=i,
            )

            entry_with_hash = entry.with_hash("", None)
            await repository.save(entry_with_hash)

        denied_entries = await repository.find_by_decision(
            test_tenant_id,
            AccessDecision.DENY,
            base_time,
            base_time + timedelta(seconds=25),
            limit=100,
        )

        assert len(denied_entries) == 7
        assert all(e.decision == AccessDecision.DENY for e in denied_entries)

    async def test_get_next_sequence_number(
        self, database_url: str, clean_database: None, test_tenant_id: UUID, test_agent_id: UUID
    ) -> None:
        """Test getting next sequence number."""
        repository = PostgresAuditRepository(database_url)

        next_seq = await repository.get_next_sequence_number(test_tenant_id, test_agent_id)
        assert next_seq == 0

        timed_context = TimedAccessContext.create_from_timestamp(datetime.now(UTC))
        entry = AuditEntry(
            tenant_id=test_tenant_id,
            agent_id=test_agent_id,
            timestamp=datetime.now(UTC),
            domain=DomainName(value="test.com"),
            decision=AccessDecision.ALLOW,
            reason="Test",
            request_method="GET",
            request_path="/test",
            timed_access_metadata=timed_context,
            sequence_number=0,
        )

        await repository.save(entry.with_hash("", None))

        next_seq = await repository.get_next_sequence_number(test_tenant_id, test_agent_id)
        assert next_seq == 1
