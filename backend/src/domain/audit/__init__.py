"""Audit domain module."""

from .entity import AccessDecision
from .entity import AuditEntry
from .entity import ChainVerificationResult
from .entity import TimedAccessContext
from .exceptions import AuditAccessDeniedError
from .exceptions import AuditChainIntegrityError
from .exceptions import AuditConfigurationError
from .exceptions import AuditEntryNotFoundError
from .exceptions import AuditError
from .exceptions import AuditExportError
from .exceptions import AuditHashMismatchError
from .exceptions import AuditRetentionViolationError
from .exceptions import AuditSequenceGapError
from .exceptions import AuditStorageError
from .exceptions import AuditTimestampAnomalyError
from .hasher import AuditHashError
from .hasher import EnhancedAuditHasher
from .repository import AuditRepository
from .service import AccessRequest
from .service import AuditService

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
