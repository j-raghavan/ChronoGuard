"""Comprehensive tests for audit domain exceptions."""

from uuid import uuid4

from domain.audit.exceptions import (
    AuditAccessDeniedError,
    AuditChainIntegrityError,
    AuditConfigurationError,
    AuditEntryNotFoundError,
    AuditError,
    AuditExportError,
    AuditHashMismatchError,
    AuditRetentionViolationError,
    AuditSequenceGapError,
    AuditStorageError,
    AuditTimestampAnomalyError,
)


class TestAuditError:
    """Test base AuditError class."""

    def test_audit_error_is_base_class(self):
        """Test that AuditError can be instantiated."""
        error = AuditError("Test audit error")
        assert str(error) == "Test audit error"


class TestAuditEntryNotFoundError:
    """Test AuditEntryNotFoundError exception."""

    def test_audit_entry_not_found_error_creation(self):
        """Test creation of AuditEntryNotFoundError."""
        entry_id = uuid4()
        error = AuditEntryNotFoundError(entry_id)

        assert str(entry_id) in str(error)
        assert "not found" in str(error).lower()
        assert error.entry_id == entry_id
        assert error.error_code == "AUDIT_ENTRY_NOT_FOUND"

    def test_audit_entry_not_found_error_attributes(self):
        """Test AuditEntryNotFoundError has correct attributes."""
        entry_id = uuid4()
        error = AuditEntryNotFoundError(entry_id)

        assert hasattr(error, "entry_id")
        assert hasattr(error, "error_code")
        assert error.entry_id == entry_id


class TestAuditChainIntegrityError:
    """Test AuditChainIntegrityError exception."""

    def test_audit_chain_integrity_error_creation(self):
        """Test creation of AuditChainIntegrityError."""
        agent_id = uuid4()
        error_details = "Hash mismatch detected"
        error = AuditChainIntegrityError(agent_id, error_details)

        assert str(agent_id) in str(error)
        assert error_details in str(error)
        assert "integrity compromised" in str(error).lower()
        assert error.agent_id == agent_id
        assert error.error_details == error_details
        assert error.error_code == "AUDIT_CHAIN_INTEGRITY_ERROR"

    def test_audit_chain_integrity_error_attributes(self):
        """Test AuditChainIntegrityError has correct attributes."""
        agent_id = uuid4()
        error = AuditChainIntegrityError(agent_id, "test error")

        assert hasattr(error, "agent_id")
        assert hasattr(error, "error_details")
        assert hasattr(error, "error_code")


class TestAuditHashMismatchError:
    """Test AuditHashMismatchError exception."""

    def test_audit_hash_mismatch_error_creation(self):
        """Test creation of AuditHashMismatchError."""
        entry_id = uuid4()
        expected_hash = "abc123"
        actual_hash = "def456"
        error = AuditHashMismatchError(entry_id, expected_hash, actual_hash)

        assert str(entry_id) in str(error)
        assert expected_hash in str(error)
        assert actual_hash in str(error)
        assert "hash mismatch" in str(error).lower()
        assert error.entry_id == entry_id
        assert error.expected_hash == expected_hash
        assert error.actual_hash == actual_hash
        assert error.error_code == "AUDIT_HASH_MISMATCH"

    def test_audit_hash_mismatch_error_attributes(self):
        """Test AuditHashMismatchError has correct attributes."""
        entry_id = uuid4()
        error = AuditHashMismatchError(entry_id, "expected", "actual")

        assert hasattr(error, "entry_id")
        assert hasattr(error, "expected_hash")
        assert hasattr(error, "actual_hash")
        assert hasattr(error, "error_code")


class TestAuditSequenceGapError:
    """Test AuditSequenceGapError exception."""

    def test_audit_sequence_gap_error_creation(self):
        """Test creation of AuditSequenceGapError."""
        agent_id = uuid4()
        gap_start = 10
        gap_end = 15
        error = AuditSequenceGapError(agent_id, gap_start, gap_end)

        assert str(agent_id) in str(error)
        assert str(gap_start) in str(error)
        assert str(gap_end) in str(error)
        assert "sequence gap" in str(error).lower()
        assert error.agent_id == agent_id
        assert error.gap_start == gap_start
        assert error.gap_end == gap_end
        assert error.error_code == "AUDIT_SEQUENCE_GAP"

    def test_audit_sequence_gap_error_attributes(self):
        """Test AuditSequenceGapError has correct attributes."""
        agent_id = uuid4()
        error = AuditSequenceGapError(agent_id, 5, 10)

        assert hasattr(error, "agent_id")
        assert hasattr(error, "gap_start")
        assert hasattr(error, "gap_end")
        assert hasattr(error, "error_code")


class TestAuditTimestampAnomalyError:
    """Test AuditTimestampAnomalyError exception."""

    def test_audit_timestamp_anomaly_error_creation(self):
        """Test creation of AuditTimestampAnomalyError."""
        entry_id = uuid4()
        anomaly_description = "Timestamp in the future"
        error = AuditTimestampAnomalyError(entry_id, anomaly_description)

        assert str(entry_id) in str(error)
        assert anomaly_description in str(error)
        assert "timestamp anomaly" in str(error).lower()
        assert error.entry_id == entry_id
        assert error.anomaly_description == anomaly_description
        assert error.error_code == "AUDIT_TIMESTAMP_ANOMALY"

    def test_audit_timestamp_anomaly_error_attributes(self):
        """Test AuditTimestampAnomalyError has correct attributes."""
        entry_id = uuid4()
        error = AuditTimestampAnomalyError(entry_id, "test anomaly")

        assert hasattr(error, "entry_id")
        assert hasattr(error, "anomaly_description")
        assert hasattr(error, "error_code")


class TestAuditStorageError:
    """Test AuditStorageError exception."""

    def test_audit_storage_error_creation(self):
        """Test creation of AuditStorageError."""
        operation = "write"
        error_details = "Database connection failed"
        error = AuditStorageError(operation, error_details)

        assert operation in str(error)
        assert error_details in str(error)
        assert "storage operation" in str(error).lower()
        assert error.operation == operation
        assert error.error_details == error_details
        assert error.error_code == "AUDIT_STORAGE_ERROR"

    def test_audit_storage_error_attributes(self):
        """Test AuditStorageError has correct attributes."""
        error = AuditStorageError("read", "disk error")

        assert hasattr(error, "operation")
        assert hasattr(error, "error_details")
        assert hasattr(error, "error_code")


class TestAuditExportError:
    """Test AuditExportError exception."""

    def test_audit_export_error_creation(self):
        """Test creation of AuditExportError."""
        export_format = "csv"
        error_details = "Invalid CSV format"
        error = AuditExportError(export_format, error_details)

        assert export_format in str(error)
        assert error_details in str(error)
        assert "export" in str(error).lower()
        assert error.format == export_format
        assert error.error_details == error_details
        assert error.error_code == "AUDIT_EXPORT_ERROR"

    def test_audit_export_error_attributes(self):
        """Test AuditExportError has correct attributes."""
        error = AuditExportError("json", "encoding error")

        assert hasattr(error, "format")
        assert hasattr(error, "error_details")
        assert hasattr(error, "error_code")


class TestAuditRetentionViolationError:
    """Test AuditRetentionViolationError exception."""

    def test_audit_retention_violation_error_creation(self):
        """Test creation of AuditRetentionViolationError."""
        requested = 30
        minimum = 90
        error = AuditRetentionViolationError(requested, minimum)

        assert str(requested) in str(error)
        assert str(minimum) in str(error)
        assert "retention" in str(error).lower()
        assert error.requested_retention_days == requested
        assert error.minimum_required == minimum
        assert error.error_code == "AUDIT_RETENTION_VIOLATION"

    def test_audit_retention_violation_error_attributes(self):
        """Test AuditRetentionViolationError has correct attributes."""
        error = AuditRetentionViolationError(60, 180)

        assert hasattr(error, "requested_retention_days")
        assert hasattr(error, "minimum_required")
        assert hasattr(error, "error_code")


class TestAuditAccessDeniedError:
    """Test AuditAccessDeniedError exception."""

    def test_audit_access_denied_error_creation(self):
        """Test creation of AuditAccessDeniedError."""
        tenant_id = uuid4()
        reason = "Insufficient permissions"
        error = AuditAccessDeniedError(tenant_id, reason)

        assert str(tenant_id) in str(error)
        assert reason in str(error)
        assert "access" in str(error).lower()
        assert "denied" in str(error).lower()
        assert error.tenant_id == tenant_id
        assert error.reason == reason
        assert error.error_code == "AUDIT_ACCESS_DENIED"

    def test_audit_access_denied_error_attributes(self):
        """Test AuditAccessDeniedError has correct attributes."""
        tenant_id = uuid4()
        error = AuditAccessDeniedError(tenant_id, "test reason")

        assert hasattr(error, "tenant_id")
        assert hasattr(error, "reason")
        assert hasattr(error, "error_code")


class TestAuditConfigurationError:
    """Test AuditConfigurationError exception."""

    def test_audit_configuration_error_creation(self):
        """Test creation of AuditConfigurationError."""
        config_issue = "Invalid storage backend"
        error = AuditConfigurationError(config_issue)

        assert config_issue in str(error)
        assert "configuration" in str(error).lower()
        assert error.configuration_issue == config_issue
        assert error.error_code == "AUDIT_CONFIGURATION_ERROR"

    def test_audit_configuration_error_attributes(self):
        """Test AuditConfigurationError has correct attributes."""
        error = AuditConfigurationError("missing required setting")

        assert hasattr(error, "configuration_issue")
        assert hasattr(error, "error_code")
