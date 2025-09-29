"""Audit-specific domain exceptions."""

from uuid import UUID

from domain.common.exceptions import DomainError


class AuditError(DomainError):
    """Base class for audit-specific domain exceptions."""

    pass


class AuditEntryNotFoundError(AuditError):
    """Raised when a requested audit entry cannot be found."""

    def __init__(self, entry_id: UUID) -> None:
        """Initialize audit entry not found error.

        Args:
            entry_id: ID of the audit entry that was not found
        """
        super().__init__(
            f"Audit entry with ID {entry_id} not found",
            error_code="AUDIT_ENTRY_NOT_FOUND",
        )
        self.entry_id = entry_id


class AuditChainIntegrityError(AuditError):
    """Raised when audit chain integrity is compromised."""

    def __init__(self, agent_id: UUID, error_details: str) -> None:
        """Initialize audit chain integrity error.

        Args:
            agent_id: Agent ID with integrity issues
            error_details: Details about the integrity violation
        """
        super().__init__(
            f"Audit chain integrity compromised for agent {agent_id}: {error_details}",
            error_code="AUDIT_CHAIN_INTEGRITY_ERROR",
        )
        self.agent_id = agent_id
        self.error_details = error_details


class AuditHashMismatchError(AuditError):
    """Raised when audit entry hash doesn't match expected value."""

    def __init__(self, entry_id: UUID, expected_hash: str, actual_hash: str) -> None:
        """Initialize audit hash mismatch error.

        Args:
            entry_id: ID of the audit entry with hash mismatch
            expected_hash: Expected hash value
            actual_hash: Actual hash value
        """
        super().__init__(
            f"Hash mismatch for audit entry {entry_id}: "
            f"expected {expected_hash}, got {actual_hash}",
            error_code="AUDIT_HASH_MISMATCH",
        )
        self.entry_id = entry_id
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash


class AuditSequenceGapError(AuditError):
    """Raised when gaps are detected in audit entry sequence."""

    def __init__(self, agent_id: UUID, gap_start: int, gap_end: int) -> None:
        """Initialize audit sequence gap error.

        Args:
            agent_id: Agent ID with sequence gap
            gap_start: Start of sequence gap
            gap_end: End of sequence gap
        """
        super().__init__(
            f"Sequence gap detected for agent {agent_id}: missing entries {gap_start}-{gap_end}",
            error_code="AUDIT_SEQUENCE_GAP",
        )
        self.agent_id = agent_id
        self.gap_start = gap_start
        self.gap_end = gap_end


class AuditTimestampAnomalyError(AuditError):
    """Raised when timestamp anomalies are detected in audit entries."""

    def __init__(self, entry_id: UUID, anomaly_description: str) -> None:
        """Initialize audit timestamp anomaly error.

        Args:
            entry_id: ID of the audit entry with timestamp anomaly
            anomaly_description: Description of the timestamp anomaly
        """
        super().__init__(
            f"Timestamp anomaly detected for audit entry {entry_id}: {anomaly_description}",
            error_code="AUDIT_TIMESTAMP_ANOMALY",
        )
        self.entry_id = entry_id
        self.anomaly_description = anomaly_description


class AuditStorageError(AuditError):
    """Raised when audit storage operations fail."""

    def __init__(self, operation: str, error_details: str) -> None:
        """Initialize audit storage error.

        Args:
            operation: Storage operation that failed
            error_details: Details about the storage failure
        """
        super().__init__(
            f"Audit storage operation '{operation}' failed: {error_details}",
            error_code="AUDIT_STORAGE_ERROR",
        )
        self.operation = operation
        self.error_details = error_details


class AuditExportError(AuditError):
    """Raised when audit log export operations fail."""

    def __init__(self, export_format: str, error_details: str) -> None:
        """Initialize audit export error.

        Args:
            export_format: Export format that failed
            error_details: Details about the export failure
        """
        super().__init__(
            f"Audit export to '{export_format}' format failed: {error_details}",
            error_code="AUDIT_EXPORT_ERROR",
        )
        self.format = export_format
        self.error_details = error_details


class AuditRetentionViolationError(AuditError):
    """Raised when audit retention policy is violated."""

    def __init__(self, requested_retention_days: int, minimum_required: int) -> None:
        """Initialize audit retention violation error.

        Args:
            requested_retention_days: Requested retention period
            minimum_required: Minimum required retention period
        """
        super().__init__(
            f"Retention period {requested_retention_days} days violates "
            f"minimum requirement of {minimum_required} days",
            error_code="AUDIT_RETENTION_VIOLATION",
        )
        self.requested_retention_days = requested_retention_days
        self.minimum_required = minimum_required


class AuditAccessDeniedError(AuditError):
    """Raised when access to audit logs is denied."""

    def __init__(self, tenant_id: UUID, reason: str) -> None:
        """Initialize audit access denied error.

        Args:
            tenant_id: Tenant ID that was denied access
            reason: Reason for access denial
        """
        super().__init__(
            f"Access to audit logs denied for tenant {tenant_id}: {reason}",
            error_code="AUDIT_ACCESS_DENIED",
        )
        self.tenant_id = tenant_id
        self.reason = reason


class AuditConfigurationError(AuditError):
    """Raised when audit system configuration is invalid."""

    def __init__(self, configuration_issue: str) -> None:
        """Initialize audit configuration error.

        Args:
            configuration_issue: Description of the configuration issue
        """
        super().__init__(
            f"Audit system configuration error: {configuration_issue}",
            error_code="AUDIT_CONFIGURATION_ERROR",
        )
        self.configuration_issue = configuration_issue
