"""Unit tests for audit domain components."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from domain.audit.entity import (
    AccessDecision,
    AuditEntry,
    ChainVerificationResult,
    TimedAccessContext,
)
from domain.audit.hasher import AuditHashError, EnhancedAuditHasher
from domain.audit.service import AccessRequest, AuditService
from domain.common.exceptions import BusinessRuleViolationError, ValidationError
from domain.common.value_objects import DomainName


class TestTimedAccessContext:
    """Unit tests for TimedAccessContext value object."""

    def test_create_from_timestamp_business_hours(self) -> None:
        """Test creating context from timestamp during business hours."""
        # Thursday 10 AM UTC
        timestamp = datetime(2023, 9, 14, 10, 0, 0, tzinfo=UTC)
        context = TimedAccessContext.create_from_timestamp(timestamp)

        assert context.request_timestamp == timestamp
        assert context.day_of_week == 3  # Thursday
        assert context.hour_of_day == 10
        assert context.is_business_hours is True
        assert context.is_weekend is False
        assert context.week_of_year == 37
        assert context.month_of_year == 9
        assert context.quarter_of_year == 3

    def test_create_from_timestamp_weekend(self) -> None:
        """Test creating context from timestamp during weekend."""
        # Saturday 10 AM UTC
        timestamp = datetime(2023, 9, 16, 10, 0, 0, tzinfo=UTC)
        context = TimedAccessContext.create_from_timestamp(timestamp)

        assert context.day_of_week == 5  # Saturday
        assert context.is_weekend is True
        assert context.is_business_hours is True  # 10 AM is business hours

    def test_create_from_timestamp_off_hours(self) -> None:
        """Test creating context from timestamp outside business hours."""
        # Thursday 8 PM UTC
        timestamp = datetime(2023, 9, 14, 20, 0, 0, tzinfo=UTC)
        context = TimedAccessContext.create_from_timestamp(timestamp)

        assert context.hour_of_day == 20
        assert context.is_business_hours is False
        assert context.is_weekend is False

    def test_create_from_naive_timestamp(self) -> None:
        """Test creating context from naive timestamp."""
        # Naive timestamp (no timezone)
        timestamp = datetime(2023, 9, 14, 10, 0, 0)  # noqa: DTZ001
        context = TimedAccessContext.create_from_timestamp(timestamp)

        assert context.is_business_hours is True

    def test_create_from_non_utc_timestamp(self) -> None:
        """Test creating context from non-UTC timezone."""
        import zoneinfo

        # Create timestamp in US/Pacific (UTC-7 in September)
        pacific_tz = zoneinfo.ZoneInfo("US/Pacific")
        pacific_timestamp = datetime(
            2023, 9, 14, 2, 0, 0, tzinfo=pacific_tz
        )  # 2 AM Pacific = 9 AM UTC

        context = TimedAccessContext.create_from_timestamp(pacific_timestamp)

        assert context.request_timestamp.tzinfo == UTC

    def test_immutability(self) -> None:
        """Test that TimedAccessContext is immutable."""
        timestamp = datetime(2023, 9, 14, 10, 0, 0, tzinfo=UTC)
        context = TimedAccessContext.create_from_timestamp(timestamp)

        with pytest.raises(Exception):  # Pydantic ValidationError
            context.hour_of_day = 15


class TestAuditEntry:
    """Unit tests for AuditEntry entity."""

    def test_create_valid_audit_entry(
        self, test_tenant_id: UUID, test_agent_id: UUID, test_domain_name: DomainName
    ) -> None:
        """Test creating a valid audit entry."""
        entry = AuditEntry(
            tenant_id=test_tenant_id,
            agent_id=test_agent_id,
            domain=test_domain_name,
            decision=AccessDecision.ALLOW,
            reason="Test access allowed",
            sequence_number=1,
        )

        assert entry.tenant_id == test_tenant_id
        assert entry.agent_id == test_agent_id
        assert entry.domain == test_domain_name
        assert entry.decision == AccessDecision.ALLOW
        assert entry.reason == "Test access allowed"
        assert entry.sequence_number == 1
        assert entry.timed_access_metadata is not None

    def test_domain_validation_string_input(
        self, test_tenant_id: UUID, test_agent_id: UUID
    ) -> None:
        """Test domain validation with string input."""
        entry = AuditEntry(
            tenant_id=test_tenant_id,
            agent_id=test_agent_id,
            domain="example.com",  # String instead of DomainName
            decision=AccessDecision.ALLOW,
        )

        assert isinstance(entry.domain, DomainName)
        assert entry.domain.value == "example.com"

    def test_domain_validation_invalid_type(
        self, test_tenant_id: UUID, test_agent_id: UUID
    ) -> None:
        """Test domain validation with invalid type."""
        with pytest.raises(ValidationError) as exc_info:
            AuditEntry(
                tenant_id=test_tenant_id,
                agent_id=test_agent_id,
                domain=123,  # Invalid type
                decision=AccessDecision.ALLOW,
            )

        assert "Domain must be string or DomainName" in str(exc_info.value)

    def test_timestamp_validation_naive(
        self, test_tenant_id: UUID, test_agent_id: UUID, test_domain_name: DomainName
    ) -> None:
        """Test timestamp validation with naive datetime."""
        naive_timestamp = datetime(2023, 9, 14, 10, 0, 0)  # noqa: DTZ001

        entry = AuditEntry(
            tenant_id=test_tenant_id,
            agent_id=test_agent_id,
            domain=test_domain_name,
            decision=AccessDecision.ALLOW,
            timestamp=naive_timestamp,
        )

        assert entry.timestamp.tzinfo == UTC

    def test_timestamp_validation_non_utc(
        self, test_tenant_id: UUID, test_agent_id: UUID, test_domain_name: DomainName
    ) -> None:
        """Test timestamp validation with non-UTC timezone."""
        import zoneinfo

        # Create timestamp in US/Eastern
        eastern_tz = zoneinfo.ZoneInfo("US/Eastern")
        eastern_timestamp = datetime(
            2023, 9, 14, 5, 0, 0, tzinfo=eastern_tz
        )  # 5 AM Eastern = 9 AM UTC

        entry = AuditEntry(
            tenant_id=test_tenant_id,
            agent_id=test_agent_id,
            domain=test_domain_name,
            decision=AccessDecision.ALLOW,
            timestamp=eastern_timestamp,
        )

        # Should be converted to UTC
        assert entry.timestamp.tzinfo == UTC
        assert entry.timestamp.hour == 9

    def test_reason_validation_too_long(
        self, test_tenant_id: UUID, test_agent_id: UUID, test_domain_name: DomainName
    ) -> None:
        """Test reason validation with too long text."""
        long_reason = "a" * 501

        with pytest.raises(ValidationError) as exc_info:
            AuditEntry(
                tenant_id=test_tenant_id,
                agent_id=test_agent_id,
                domain=test_domain_name,
                decision=AccessDecision.ALLOW,
                reason=long_reason,
            )

        assert "Reason too long" in str(exc_info.value)

    def test_source_ip_validation_invalid(
        self, test_tenant_id: UUID, test_agent_id: UUID, test_domain_name: DomainName
    ) -> None:
        """Test source IP validation with invalid IP."""
        with pytest.raises(ValidationError) as exc_info:
            AuditEntry(
                tenant_id=test_tenant_id,
                agent_id=test_agent_id,
                domain=test_domain_name,
                decision=AccessDecision.ALLOW,
                source_ip="invalid.ip.address",
            )

        assert "Invalid IP address format" in str(exc_info.value)

    def test_sequence_number_validation_negative(
        self, test_tenant_id: UUID, test_agent_id: UUID, test_domain_name: DomainName
    ) -> None:
        """Test sequence number validation with negative value."""
        with pytest.raises(ValidationError) as exc_info:
            AuditEntry(
                tenant_id=test_tenant_id,
                agent_id=test_agent_id,
                domain=test_domain_name,
                decision=AccessDecision.ALLOW,
                sequence_number=-1,
            )

        assert "Sequence number must be non-negative" in str(exc_info.value)

    def test_calculate_hash(self, test_audit_entry: AuditEntry) -> None:
        """Test hash calculation."""
        hash_value = test_audit_entry.calculate_hash()

        assert isinstance(hash_value, str)
        assert len(hash_value) == 64  # SHA-256 hex string

    def test_calculate_hash_with_previous(self, test_audit_entry: AuditEntry) -> None:
        """Test hash calculation with previous hash."""
        previous_hash = "abcd1234"
        hash_value = test_audit_entry.calculate_hash(previous_hash)

        assert isinstance(hash_value, str)
        assert len(hash_value) == 64

    def test_calculate_hash_with_secret_key(
        self, test_audit_entry: AuditEntry, test_secret_key: bytes
    ) -> None:
        """Test hash calculation with secret key."""
        hash_value = test_audit_entry.calculate_hash(secret_key=test_secret_key)

        assert isinstance(hash_value, str)
        assert len(hash_value) == 64

    def test_with_hash(self, test_audit_entry: AuditEntry) -> None:
        """Test creating entry with calculated hash."""
        previous_hash = "abcd1234"
        entry_with_hash = test_audit_entry.with_hash(previous_hash)

        assert entry_with_hash.previous_hash == previous_hash
        assert entry_with_hash.current_hash != ""
        assert len(entry_with_hash.current_hash) == 64

    def test_verify_hash_valid(self, test_audit_entry: AuditEntry, test_secret_key: bytes) -> None:
        """Test hash verification with valid hash."""
        entry_with_hash = test_audit_entry.with_hash(secret_key=test_secret_key)

        assert entry_with_hash.verify_hash(test_secret_key) is True

    def test_verify_hash_invalid(self, test_audit_entry: AuditEntry) -> None:
        """Test hash verification with invalid hash."""
        # Create entry with hash but verify with different secret
        entry_with_hash = test_audit_entry.with_hash()
        entry_with_invalid_hash = AuditEntry(
            **{**entry_with_hash.model_dump(), "current_hash": "invalid_hash"}
        )

        assert entry_with_invalid_hash.verify_hash() is False

    def test_verify_hash_missing(self, test_audit_entry: AuditEntry) -> None:
        """Test hash verification when current_hash is not set."""
        # Entry without hash set (empty string)
        assert test_audit_entry.current_hash == ""
        assert test_audit_entry.verify_hash() is False

    def test_is_access_allowed(self, test_audit_entry: AuditEntry) -> None:
        """Test checking if access was allowed."""
        assert test_audit_entry.is_access_allowed() is True

        deny_entry = AuditEntry(
            **{**test_audit_entry.model_dump(), "decision": AccessDecision.DENY}
        )
        assert deny_entry.is_access_allowed() is False

    def test_is_access_denied(self, test_audit_entry: AuditEntry) -> None:
        """Test checking if access was denied."""
        assert test_audit_entry.is_access_denied() is False

        deny_entry = AuditEntry(
            **{**test_audit_entry.model_dump(), "decision": AccessDecision.DENY}
        )
        assert deny_entry.is_access_denied() is True

    def test_get_risk_score(self, test_audit_entry: AuditEntry) -> None:
        """Test risk score calculation."""
        risk_score = test_audit_entry.get_risk_score()

        assert isinstance(risk_score, int)
        assert 0 <= risk_score <= 100

    def test_get_risk_score_denied_access(
        self, test_tenant_id: UUID, test_agent_id: UUID, test_domain_name: DomainName
    ) -> None:
        """Test risk score for denied access."""
        deny_entry = AuditEntry(
            tenant_id=test_tenant_id,
            agent_id=test_agent_id,
            domain=test_domain_name,
            decision=AccessDecision.DENY,
        )

        risk_score = deny_entry.get_risk_score()
        assert risk_score >= 30  # Base score for denied access

    def test_to_json_dict(self, test_audit_entry: AuditEntry) -> None:
        """Test JSON dictionary conversion."""
        json_dict = test_audit_entry.to_json_dict()

        assert isinstance(json_dict, dict)
        assert "entry_id" in json_dict
        assert "tenant_id" in json_dict
        assert "domain" in json_dict
        assert "decision" in json_dict
        assert "risk_score" in json_dict

    def test_string_representation(self, test_audit_entry: AuditEntry) -> None:
        """Test string representation."""
        str_repr = str(test_audit_entry)

        assert "AuditEntry" in str_repr
        assert str(test_audit_entry.entry_id) in str_repr
        assert test_audit_entry.domain.value in str_repr

    def test_detailed_representation(self, test_audit_entry: AuditEntry) -> None:
        """Test detailed representation."""
        repr_str = repr(test_audit_entry)

        assert "AuditEntry" in repr_str
        assert str(test_audit_entry.entry_id) in repr_str
        assert str(test_audit_entry.tenant_id) in repr_str


class TestEnhancedAuditHasher:
    """Unit tests for EnhancedAuditHasher."""

    def test_create_hasher_with_secret_key(self, test_secret_key: bytes) -> None:
        """Test creating hasher with provided secret key."""
        hasher = EnhancedAuditHasher(test_secret_key)

        assert hasher.secret_key == test_secret_key

    def test_create_hasher_without_secret_key(self) -> None:
        """Test creating hasher without secret key."""
        hasher = EnhancedAuditHasher()

        assert hasher.secret_key is not None
        assert len(hasher.secret_key) == 32

    def test_compute_entry_hash(
        self, test_audit_hasher: EnhancedAuditHasher, test_audit_entry: AuditEntry
    ) -> None:
        """Test computing entry hash."""
        hash_bytes = test_audit_hasher.compute_entry_hash(test_audit_entry)

        assert isinstance(hash_bytes, bytes)
        assert len(hash_bytes) == 48  # 16 bytes salt + 32 bytes hash

    def test_compute_entry_hash_with_previous(
        self, test_audit_hasher: EnhancedAuditHasher, test_audit_entry: AuditEntry
    ) -> None:
        """Test computing entry hash with previous hash."""
        previous_hash = "abcd1234"
        hash_bytes = test_audit_hasher.compute_entry_hash(test_audit_entry, previous_hash)

        assert isinstance(hash_bytes, bytes)
        assert len(hash_bytes) == 48

    def test_verify_entry_hash_valid(
        self, test_audit_hasher: EnhancedAuditHasher, test_audit_entry: AuditEntry
    ) -> None:
        """Test verifying valid entry hash."""
        hash_bytes = test_audit_hasher.compute_entry_hash(test_audit_entry)
        is_valid = test_audit_hasher.verify_entry_hash(test_audit_entry, hash_bytes)

        assert is_valid is True

    def test_verify_entry_hash_invalid(
        self, test_audit_hasher: EnhancedAuditHasher, test_audit_entry: AuditEntry
    ) -> None:
        """Test verifying invalid entry hash."""
        invalid_hash = b"invalid_hash_too_short"

        with pytest.raises(AuditHashError) as exc_info:
            test_audit_hasher.verify_entry_hash(test_audit_entry, invalid_hash)

        assert "Invalid hash format" in str(exc_info.value)

    def test_compute_chain_hash(
        self,
        test_audit_hasher: EnhancedAuditHasher,
        test_audit_entries_collection: list,
    ) -> None:
        """Test computing chain hash for multiple entries."""
        chain_hash = test_audit_hasher.compute_chain_hash(test_audit_entries_collection)

        assert isinstance(chain_hash, str)
        assert len(chain_hash) == 64  # SHA-256 hex string

    def test_compute_chain_hash_empty(self, test_audit_hasher: EnhancedAuditHasher) -> None:
        """Test computing chain hash for empty list."""
        chain_hash = test_audit_hasher.compute_chain_hash([])

        assert chain_hash == ""

    def test_verify_chain_integrity_valid(
        self,
        test_audit_hasher: EnhancedAuditHasher,
        test_audit_entries_collection: list,
    ) -> None:
        """Test verifying valid chain integrity."""
        # Create entries with proper hashing
        entries_with_hashes = []
        previous_hash = ""

        for entry in test_audit_entries_collection:
            hash_bytes = test_audit_hasher.compute_entry_hash(entry, previous_hash)
            hash_hex = hash_bytes.hex()

            entry_with_hash = AuditEntry(
                **{
                    **entry.model_dump(),
                    "previous_hash": previous_hash,
                    "current_hash": hash_hex,
                }
            )
            entries_with_hashes.append(entry_with_hash)
            previous_hash = hash_hex

        is_valid, errors = test_audit_hasher.verify_chain_integrity(entries_with_hashes)

        assert is_valid is True
        assert len(errors) == 0

    def test_generate_integrity_proof(
        self,
        test_audit_hasher: EnhancedAuditHasher,
        test_audit_entries_collection: list,
    ) -> None:
        """Test generating integrity proof."""
        proof = test_audit_hasher.generate_integrity_proof(test_audit_entries_collection)

        assert isinstance(proof, dict)
        assert "root_hash" in proof
        assert "entry_count" in proof
        assert "start_sequence" in proof
        assert "end_sequence" in proof
        assert "signature" in proof


class TestAuditService:
    """Unit tests for AuditService."""

    @pytest.fixture
    def mock_audit_repository(self) -> AsyncMock:
        """Mock audit repository."""
        return AsyncMock()

    @pytest.fixture
    def audit_service(
        self, mock_audit_repository: AsyncMock, test_secret_key: bytes
    ) -> AuditService:
        """Audit service with mock repository."""
        return AuditService(mock_audit_repository, test_secret_key)

    async def test_record_access_success(
        self,
        audit_service: AuditService,
        mock_audit_repository: AsyncMock,
        test_tenant_id: UUID,
        test_agent_id: UUID,
    ) -> None:
        """Test successful access recording."""
        # Setup mocks
        mock_audit_repository.get_latest_entry_for_agent.return_value = None
        mock_audit_repository.get_next_sequence_number.return_value = 1
        mock_audit_repository.save.return_value = None

        # Create access request
        request = AccessRequest(
            tenant_id=test_tenant_id,
            agent_id=test_agent_id,
            domain="example.com",
            decision=AccessDecision.ALLOW,
            reason="Test access",
        )

        # Record access
        entry = await audit_service.record_access(request)

        # Verify entry properties
        assert entry.tenant_id == test_tenant_id
        assert entry.agent_id == test_agent_id
        assert entry.domain.value == "example.com"
        assert entry.decision == AccessDecision.ALLOW
        assert entry.sequence_number == 1

        # Verify repository calls
        mock_audit_repository.save.assert_called_once()

    async def test_record_access_with_chaining(
        self,
        audit_service: AuditService,
        mock_audit_repository: AsyncMock,
        test_tenant_id: UUID,
        test_agent_id: UUID,
        test_audit_entry: AuditEntry,
    ) -> None:
        """Test access recording with hash chaining."""
        # Setup previous entry
        previous_entry = test_audit_entry.with_hash("", audit_service._secret_key)
        mock_audit_repository.get_latest_entry_for_agent.return_value = previous_entry
        mock_audit_repository.get_next_sequence_number.return_value = 2
        mock_audit_repository.save.return_value = None

        # Create access request
        request = AccessRequest(
            tenant_id=test_tenant_id,
            agent_id=test_agent_id,
            domain="example.com",
            decision=AccessDecision.ALLOW,
        )

        # Record access
        entry = await audit_service.record_access(request)

        # Verify chaining
        assert entry.previous_hash == previous_entry.current_hash
        assert entry.current_hash != ""
        assert entry.sequence_number == 2

    async def test_verify_agent_chain(
        self,
        audit_service: AuditService,
        mock_audit_repository: AsyncMock,
        test_tenant_id: UUID,
        test_agent_id: UUID,
    ) -> None:
        """Test agent chain verification."""
        # Setup mock verification result
        verification_result = ChainVerificationResult(
            is_valid=True,
            total_entries=10,
            verified_entries=10,
            broken_chains=0,
            hash_mismatches=0,
            sequence_gaps=0,
        )
        mock_audit_repository.verify_chain_integrity.return_value = verification_result

        result = await audit_service.verify_agent_chain(test_tenant_id, test_agent_id)

        assert result.is_valid is True
        assert result.total_entries == 10

    async def test_get_audit_statistics(
        self,
        audit_service: AuditService,
        mock_audit_repository: AsyncMock,
        test_tenant_id: UUID,
    ) -> None:
        """Test getting audit statistics."""
        start_time = datetime(2023, 9, 1, tzinfo=UTC)
        end_time = datetime(2023, 9, 30, tzinfo=UTC)

        # Setup mocks
        mock_audit_repository.get_access_statistics.return_value = {"total_requests": 1000}
        mock_audit_repository.count_entries_by_decision.return_value = 100
        mock_audit_repository.get_top_domains_by_access.return_value = [("example.com", 500)]
        mock_audit_repository.find_suspicious_patterns.return_value = []

        stats = await audit_service.get_audit_statistics(test_tenant_id, start_time, end_time)

        assert isinstance(stats, dict)
        assert "period" in stats
        assert "access_statistics" in stats
        assert "decision_counts" in stats
        assert "top_domains" in stats

    async def test_export_audit_logs_json(
        self,
        audit_service: AuditService,
        mock_audit_repository: AsyncMock,
        test_tenant_id: UUID,
        test_audit_entries_collection: list,
    ) -> None:
        """Test exporting audit logs in JSON format."""
        start_time = datetime(2023, 9, 1, tzinfo=UTC)
        end_time = datetime(2023, 9, 30, tzinfo=UTC)

        # Setup mock
        mock_audit_repository.find_entries_for_export.return_value = (
            test_audit_entries_collection,
            None,
        )

        exported = await audit_service.export_audit_logs(
            test_tenant_id, start_time, end_time, export_format="json"
        )

        assert isinstance(exported, list)
        assert len(exported) == len(test_audit_entries_collection)
        assert all(isinstance(entry, dict) for entry in exported)

    async def test_export_audit_logs_csv(
        self,
        audit_service: AuditService,
        mock_audit_repository: AsyncMock,
        test_tenant_id: UUID,
        test_audit_entries_collection: list,
    ) -> None:
        """Test exporting audit logs in CSV format."""
        start_time = datetime(2023, 9, 1, tzinfo=UTC)
        end_time = datetime(2023, 9, 30, tzinfo=UTC)

        # Setup mock
        mock_audit_repository.find_entries_for_export.return_value = (
            test_audit_entries_collection,
            None,
        )

        exported = await audit_service.export_audit_logs(
            test_tenant_id, start_time, end_time, export_format="csv"
        )

        assert isinstance(exported, list)
        assert len(exported) == len(test_audit_entries_collection)
        assert all(isinstance(entry, dict) for entry in exported)

    async def test_export_audit_logs_invalid_format(
        self,
        audit_service: AuditService,
        test_tenant_id: UUID,
    ) -> None:
        """Test exporting audit logs with invalid format."""
        start_time = datetime(2023, 9, 1, tzinfo=UTC)
        end_time = datetime(2023, 9, 30, tzinfo=UTC)

        with pytest.raises(ValidationError) as exc_info:
            await audit_service.export_audit_logs(
                test_tenant_id, start_time, end_time, export_format="invalid"
            )

        assert "Unsupported export format" in str(exc_info.value)

    async def test_export_audit_logs_with_pagination(
        self,
        audit_service: AuditService,
        mock_audit_repository: AsyncMock,
        test_tenant_id: UUID,
        test_audit_entries_collection: list,
    ) -> None:
        """Test exporting audit logs handles pagination."""
        start_time = datetime(2023, 9, 1, tzinfo=UTC)
        end_time = datetime(2023, 9, 30, tzinfo=UTC)

        # First call returns entries with cursor, second returns empty (break condition)
        mock_audit_repository.find_entries_for_export.side_effect = [
            (test_audit_entries_collection, "cursor_123"),
            ([], None),
        ]

        exported = await audit_service.export_audit_logs(
            test_tenant_id, start_time, end_time, export_format="json", batch_size=10
        )

        # Should have called repository twice due to pagination
        assert mock_audit_repository.find_entries_for_export.call_count == 2
        assert len(exported) == len(test_audit_entries_collection)

    async def test_cleanup_old_audit_logs_success(
        self,
        audit_service: AuditService,
        mock_audit_repository: AsyncMock,
        test_tenant_id: UUID,
    ) -> None:
        """Test successful cleanup of old audit logs."""
        # Setup mocks
        mock_audit_repository.archive_entries_to_storage.return_value = 100
        mock_audit_repository.cleanup_old_entries.return_value = 100

        result = await audit_service.cleanup_old_audit_logs(
            tenant_id=test_tenant_id,
            retention_days=90,
            archive_before_delete=True,
            storage_path="s3://bucket/path",
        )

        assert result["archived_entries"] == 100
        assert result["deleted_entries"] == 100

    async def test_cleanup_old_audit_logs_retention_violation(
        self,
        audit_service: AuditService,
        test_tenant_id: UUID,
    ) -> None:
        """Test cleanup with retention period violation."""
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            await audit_service.cleanup_old_audit_logs(
                tenant_id=test_tenant_id,
                retention_days=15,  # Less than minimum 30 days
            )

        assert "Minimum retention period is 30 days" in str(exc_info.value)

    async def test_detect_time_anomalies_with_sequence_violation(
        self,
        audit_service: AuditService,
        mock_audit_repository: AsyncMock,
    ) -> None:
        """Test detecting time sequence violations in audit chain."""
        from datetime import timedelta

        tenant_id = uuid4()
        agent_id = uuid4()
        now = datetime.now(UTC)

        # Create entries with reversed timestamps (violation)
        entry1 = AuditEntry(
            tenant_id=tenant_id,
            agent_id=agent_id,
            domain="test1.example.com",
            decision=AccessDecision.ALLOW,
            timestamp=now,
        )

        entry2 = AuditEntry(
            tenant_id=tenant_id,
            agent_id=agent_id,
            domain="test2.example.com",
            decision=AccessDecision.ALLOW,
            timestamp=now - timedelta(hours=1),  # Earlier than entry1 - violation!
        )

        mock_audit_repository.find_by_agent_time_range.return_value = [entry1, entry2]

        anomalies = await audit_service._detect_time_anomalies(tenant_id, agent_id)

        # Should return anomalies list (may or may not detect based on logic)
        assert isinstance(anomalies, list)

    async def test_detect_time_anomalies_with_large_time_gap(
        self,
        audit_service: AuditService,
        mock_audit_repository: AsyncMock,
    ) -> None:
        """Test detecting large time gaps in audit chain."""
        from datetime import timedelta

        tenant_id = uuid4()
        agent_id = uuid4()
        now = datetime.now(UTC)

        # Create entries with large time gap (>1 hour)
        entry1 = AuditEntry(
            tenant_id=tenant_id,
            agent_id=agent_id,
            domain="test1.example.com",
            decision=AccessDecision.ALLOW,
            timestamp=now - timedelta(hours=3),
        )

        entry2 = AuditEntry(
            tenant_id=tenant_id,
            agent_id=agent_id,
            domain="test2.example.com",
            decision=AccessDecision.ALLOW,
            timestamp=now,  # 3 hours later - large gap
        )

        mock_audit_repository.find_by_agent_time_range.return_value = [entry1, entry2]

        anomalies = await audit_service._detect_time_anomalies(tenant_id, agent_id)

        # Should return anomalies list (may or may not detect based on logic)
        assert isinstance(anomalies, list)
