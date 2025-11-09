"""Repository interface for audit log persistence and retrieval."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import UUID

from domain.audit.entity import AccessDecision, AuditEntry, ChainVerificationResult


class AuditRepository(ABC):
    """Repository interface for audit log operations."""

    @abstractmethod
    async def save(self, entry: AuditEntry) -> None:
        """Save an audit entry to persistent storage.

        Args:
            entry: Audit entry to save

        Raises:
            RepositoryError: If save operation fails
        """
        pass

    @abstractmethod
    async def find_by_id(self, entry_id: UUID) -> AuditEntry | None:
        """Find audit entry by ID.

        Args:
            entry_id: Entry ID to search for

        Returns:
            Audit entry if found, None otherwise

        Raises:
            RepositoryError: If search operation fails
        """
        pass

    @abstractmethod
    async def find_by_tenant_time_range(
        self,
        tenant_id: UUID,
        start_time: datetime,
        end_time: datetime,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """Find audit entries for a tenant within a time range.

        Args:
            tenant_id: Tenant ID to filter by
            start_time: Start of time range (inclusive)
            end_time: End of time range (inclusive)
            limit: Maximum number of entries to return
            offset: Number of entries to skip

        Returns:
            List of audit entries sorted by timestamp descending

        Raises:
            RepositoryError: If search operation fails
        """
        pass

    @abstractmethod
    async def find_by_agent_time_range(
        self,
        agent_id: UUID,
        start_time: datetime,
        end_time: datetime,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """Find audit entries for an agent within a time range.

        Args:
            agent_id: Agent ID to filter by
            start_time: Start of time range (inclusive)
            end_time: End of time range (inclusive)
            limit: Maximum number of entries to return
            offset: Number of entries to skip

        Returns:
            List of audit entries sorted by timestamp descending

        Raises:
            RepositoryError: If search operation fails
        """
        pass

    @abstractmethod
    async def find_by_domain_time_range(
        self,
        tenant_id: UUID,
        domain: str,
        start_time: datetime,
        end_time: datetime,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """Find audit entries for a domain within a time range.

        Args:
            tenant_id: Tenant ID to filter by
            domain: Domain to filter by
            start_time: Start of time range (inclusive)
            end_time: End of time range (inclusive)
            limit: Maximum number of entries to return
            offset: Number of entries to skip

        Returns:
            List of audit entries sorted by timestamp descending

        Raises:
            RepositoryError: If search operation fails
        """
        pass

    @abstractmethod
    async def find_by_decision(
        self,
        tenant_id: UUID,
        decision: AccessDecision,
        start_time: datetime,
        end_time: datetime,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """Find audit entries by access decision.

        Args:
            tenant_id: Tenant ID to filter by
            decision: Access decision to filter by
            start_time: Start of time range (inclusive)
            end_time: End of time range (inclusive)
            limit: Maximum number of entries to return
            offset: Number of entries to skip

        Returns:
            List of audit entries sorted by timestamp descending

        Raises:
            RepositoryError: If search operation fails
        """
        pass

    @abstractmethod
    async def find_chain_sequence(
        self,
        tenant_id: UUID,
        agent_id: UUID,
        start_sequence: int,
        end_sequence: int,
    ) -> list[AuditEntry]:
        """Find audit entries in sequence order for chain verification.

        Args:
            tenant_id: Tenant ID to filter by
            agent_id: Agent ID to filter by
            start_sequence: Starting sequence number (inclusive)
            end_sequence: Ending sequence number (inclusive)

        Returns:
            List of audit entries sorted by sequence number ascending

        Raises:
            RepositoryError: If search operation fails
        """
        pass

    @abstractmethod
    async def get_latest_entry_for_agent(
        self, tenant_id: UUID, agent_id: UUID
    ) -> AuditEntry | None:
        """Get the most recent audit entry for an agent.

        Args:
            tenant_id: Tenant ID to filter by
            agent_id: Agent ID to search for

        Returns:
            Latest audit entry if found, None otherwise

        Raises:
            RepositoryError: If search operation fails
        """
        pass

    @abstractmethod
    async def get_next_sequence_number(self, tenant_id: UUID, agent_id: UUID) -> int:
        """Get the next sequence number for an agent's audit chain.

        Args:
            tenant_id: Tenant ID
            agent_id: Agent ID

        Returns:
            Next sequence number to use

        Raises:
            RepositoryError: If operation fails
        """
        pass

    @abstractmethod
    async def count_entries_by_tenant(
        self,
        tenant_id: UUID,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> int:
        """Count audit entries for a tenant.

        Args:
            tenant_id: Tenant ID to count for
            start_time: Optional start time filter
            end_time: Optional end time filter

        Returns:
            Number of audit entries

        Raises:
            RepositoryError: If count operation fails
        """
        pass

    @abstractmethod
    async def count_entries_by_decision(
        self,
        tenant_id: UUID,
        decision: AccessDecision,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> int:
        """Count audit entries by decision type.

        Args:
            tenant_id: Tenant ID to count for
            decision: Access decision to count
            start_time: Optional start time filter
            end_time: Optional end time filter

        Returns:
            Number of audit entries with the specified decision

        Raises:
            RepositoryError: If count operation fails
        """
        pass

    @abstractmethod
    async def count_entries_by_agent_time_range(
        self,
        tenant_id: UUID,
        agent_id: UUID,
        start_time: datetime,
        end_time: datetime,
    ) -> int:
        """Count audit entries for an agent within a time range."""

        pass

    @abstractmethod
    async def get_access_statistics(
        self,
        tenant_id: UUID,
        start_time: datetime,
        end_time: datetime,
    ) -> dict[str, int]:
        """Get access statistics for a tenant and time range.

        Args:
            tenant_id: Tenant ID to analyze
            start_time: Start time for analysis
            end_time: End time for analysis

        Returns:
            Dictionary with access statistics

        Raises:
            RepositoryError: If analysis fails
        """
        pass

    @abstractmethod
    async def find_suspicious_patterns(
        self,
        tenant_id: UUID,
        lookback_hours: int = 24,
        min_failed_attempts: int = 10,
    ) -> list[dict[str, Any]]:
        """Find suspicious access patterns.

        Args:
            tenant_id: Tenant ID to analyze
            lookback_hours: Hours to look back for patterns
            min_failed_attempts: Minimum failed attempts to flag as suspicious

        Returns:
            List of suspicious pattern summaries

        Raises:
            RepositoryError: If analysis fails
        """
        pass

    @abstractmethod
    async def find_entries_for_export(
        self,
        tenant_id: UUID,
        start_time: datetime,
        end_time: datetime,
        batch_size: int = 10000,
        last_processed_id: UUID | None = None,
    ) -> tuple[list[AuditEntry], UUID | None]:
        """Find audit entries for batch export/processing.

        Args:
            tenant_id: Tenant ID to export for
            start_time: Start time for export
            end_time: End time for export
            batch_size: Number of entries per batch
            last_processed_id: ID of last processed entry for pagination

        Returns:
            Tuple of (audit entries, next cursor ID)

        Raises:
            RepositoryError: If export operation fails
        """
        pass

    @abstractmethod
    async def verify_chain_integrity(
        self,
        tenant_id: UUID,
        agent_id: UUID,
        start_sequence: int = 0,
        end_sequence: int | None = None,
        secret_key: bytes | None = None,
    ) -> ChainVerificationResult:
        """Verify integrity of audit entry chain.

        Args:
            tenant_id: Tenant ID to verify
            agent_id: Agent ID to verify
            start_sequence: Starting sequence number
            end_sequence: Ending sequence number (None for latest)
            secret_key: Secret key for hash verification

        Returns:
            Chain verification result

        Raises:
            RepositoryError: If verification fails
        """
        pass

    @abstractmethod
    async def find_chain_gaps(self, tenant_id: UUID, agent_id: UUID) -> list[tuple[int, int]]:
        """Find gaps in audit entry sequence numbers.

        Args:
            tenant_id: Tenant ID to check
            agent_id: Agent ID to check

        Returns:
            List of (start_gap, end_gap) tuples indicating missing sequences

        Raises:
            RepositoryError: If gap detection fails
        """
        pass

    @abstractmethod
    async def get_hourly_access_summary(
        self,
        tenant_id: UUID,
        date: datetime,
    ) -> dict[int, dict[str, int]]:
        """Get hourly access summary for a specific date.

        Args:
            tenant_id: Tenant ID to summarize
            date: Date to summarize (time component ignored)

        Returns:
            Dictionary mapping hour (0-23) to decision counts

        Raises:
            RepositoryError: If summary generation fails
        """
        pass

    @abstractmethod
    async def get_top_domains_by_access(
        self,
        tenant_id: UUID,
        start_time: datetime,
        end_time: datetime,
        limit: int = 10,
    ) -> list[tuple[str, int]]:
        """Get top domains by access count.

        Args:
            tenant_id: Tenant ID to analyze
            start_time: Start time for analysis
            end_time: End time for analysis
            limit: Maximum number of domains to return

        Returns:
            List of (domain, access_count) tuples sorted by count descending

        Raises:
            RepositoryError: If analysis fails
        """
        pass

    @abstractmethod
    async def cleanup_old_entries(
        self,
        tenant_id: UUID,
        cutoff_date: datetime,
        batch_size: int = 1000,
    ) -> int:
        """Clean up old audit entries before a cutoff date.

        Args:
            tenant_id: Tenant ID to clean up
            cutoff_date: Date before which entries should be deleted
            batch_size: Number of entries to delete per batch

        Returns:
            Number of entries deleted

        Raises:
            RepositoryError: If cleanup fails
        """
        pass

    @abstractmethod
    async def archive_entries_to_storage(
        self,
        tenant_id: UUID,
        cutoff_date: datetime,
        storage_path: str,
        batch_size: int = 1000,
    ) -> int:
        """Archive old audit entries to external storage.

        Args:
            tenant_id: Tenant ID to archive
            cutoff_date: Date before which entries should be archived
            storage_path: Path to external storage (S3, filesystem, etc.)
            batch_size: Number of entries to process per batch

        Returns:
            Number of entries archived

        Raises:
            RepositoryError: If archival fails
        """
        pass
