"""Audit domain module."""

from .entity import AccessDecision, AuditEntry, ChainVerificationResult, TimedAccessContext
from .exceptions import (
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
from .hasher import AuditHashError, EnhancedAuditHasher
from .repository import AuditRepository
from .service import AccessRequest, AuditService


__all__ = [
    # Entities and Value Objects
    "AuditEntry",
    "AccessDecision",
    "TimedAccessContext",
    "ChainVerificationResult",
    "AccessRequest",
    # Services
    "AuditService",
    "EnhancedAuditHasher",
    # Repository
    "AuditRepository",
    # Exceptions
    "AuditError",
    "AuditEntryNotFoundError",
    "AuditChainIntegrityError",
    "AuditHashMismatchError",
    "AuditSequenceGapError",
    "AuditTimestampAnomalyError",
    "AuditStorageError",
    "AuditExportError",
    "AuditRetentionViolationError",
    "AuditAccessDeniedError",
    "AuditConfigurationError",
    "AuditHashError",
]
