"""Domain layer base exceptions following enterprise patterns."""

from typing import Any
from uuid import UUID


class DomainError(Exception):
    """Base class for all domain layer exceptions."""

    def __init__(self, message: str, error_code: str | None = None) -> None:
        """Initialize domain error.

        Args:
            message: Human-readable error message
            error_code: Optional machine-readable error code
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code


class ValidationError(DomainError):
    """Raised when domain validation rules are violated."""

    def __init__(
        self,
        message: str,
        field: str | None = None,
        value: str | int | float | bool | None = None,
        error_code: str = "VALIDATION_ERROR",
    ) -> None:
        """Initialize validation error.

        Args:
            message: Validation error message
            field: Name of the field that failed validation
            value: The invalid value (sanitized)
            error_code: Machine-readable error code
        """
        super().__init__(message, error_code)
        self.field = field
        self.value = value


class BusinessRuleViolationError(DomainError):
    """Raised when business rules are violated."""

    def __init__(
        self,
        message: str,
        rule_name: str,
        context: dict[str, Any] | None = None,
        error_code: str = "BUSINESS_RULE_VIOLATION",
    ) -> None:
        """Initialize business rule violation error.

        Args:
            message: Business rule violation message
            rule_name: Name of the violated business rule
            context: Additional context about the violation
            error_code: Machine-readable error code
        """
        super().__init__(message, error_code)
        self.rule_name = rule_name
        self.context = context or {}


class EntityNotFoundError(DomainError):
    """Raised when a requested entity cannot be found."""

    def __init__(
        self,
        entity_type: str,
        entity_id: UUID,
        error_code: str = "ENTITY_NOT_FOUND",
    ) -> None:
        """Initialize entity not found error.

        Args:
            entity_type: Type of entity that was not found
            entity_id: ID of the entity that was not found
            error_code: Machine-readable error code
        """
        message = f"{entity_type} with ID {entity_id} not found"
        super().__init__(message, error_code)
        self.entity_type = entity_type
        self.entity_id = entity_id


class DuplicateEntityError(DomainError):
    """Raised when attempting to create a duplicate entity."""

    def __init__(
        self,
        entity_type: str,
        field: str,
        value: str,
        error_code: str = "DUPLICATE_ENTITY",
    ) -> None:
        """Initialize duplicate entity error.

        Args:
            entity_type: Type of entity that would be duplicated
            field: Field name that would be duplicated
            value: Value that would be duplicated
            error_code: Machine-readable error code
        """
        message = f"{entity_type} with {field} '{value}' already exists"
        super().__init__(message, error_code)
        self.entity_type = entity_type
        self.field = field
        self.value = value


class InvalidStateTransitionError(DomainError):
    """Raised when an invalid state transition is attempted."""

    def __init__(
        self,
        entity_type: str,
        current_state: str,
        requested_state: str,
        error_code: str = "INVALID_STATE_TRANSITION",
    ) -> None:
        """Initialize invalid state transition error.

        Args:
            entity_type: Type of entity with invalid state transition
            current_state: Current state of the entity
            requested_state: Requested state that is invalid
            error_code: Machine-readable error code
        """
        message = (
            f"Invalid state transition for {entity_type}: {current_state} -> {requested_state}"
        )
        super().__init__(message, error_code)
        self.entity_type = entity_type
        self.current_state = current_state
        self.requested_state = requested_state


class SecurityViolationError(DomainError):
    """Raised when security rules are violated."""

    def __init__(
        self,
        message: str,
        violation_type: str,
        context: dict[str, Any] | None = None,
        error_code: str = "SECURITY_VIOLATION",
    ) -> None:
        """Initialize security violation error.

        Args:
            message: Security violation message
            violation_type: Type of security violation
            context: Additional context (sanitized)
            error_code: Machine-readable error code
        """
        super().__init__(message, error_code)
        self.violation_type = violation_type
        self.context = context or {}


class TimeSecurityError(SecurityViolationError):
    """Raised when time-based security rules are violated."""

    def __init__(
        self,
        message: str,
        violation_type: str = "TIME_SECURITY",
        context: dict[str, Any] | None = None,
    ) -> None:
        """Initialize time security error.

        Args:
            message: Time security violation message
            violation_type: Type of time-based violation
            context: Additional context about the violation
        """
        super().__init__(message, violation_type, context, error_code="TIME_SECURITY_VIOLATION")


class RateLimitExceededError(DomainError):
    """Raised when rate limits are exceeded."""

    def __init__(
        self,
        limit_type: str,
        current_count: int,
        max_allowed: int,
        reset_time: str | None = None,
        error_code: str = "RATE_LIMIT_EXCEEDED",
    ) -> None:
        """Initialize rate limit exceeded error.

        Args:
            limit_type: Type of rate limit that was exceeded
            current_count: Current count that exceeded the limit
            max_allowed: Maximum allowed count
            reset_time: When the rate limit resets (ISO format)
            error_code: Machine-readable error code
        """
        message = f"{limit_type} rate limit exceeded: {current_count}/{max_allowed}"
        if reset_time:
            message += f" (resets at {reset_time})"

        super().__init__(message, error_code)
        self.limit_type = limit_type
        self.current_count = current_count
        self.max_allowed = max_allowed
        self.reset_time = reset_time


class ConcurrencyError(DomainError):
    """Raised when concurrency conflicts occur."""

    def __init__(
        self,
        entity_type: str,
        entity_id: UUID,
        expected_version: int,
        actual_version: int,
        error_code: str = "CONCURRENCY_CONFLICT",
    ) -> None:
        """Initialize concurrency error.

        Args:
            entity_type: Type of entity with concurrency conflict
            entity_id: ID of the conflicting entity
            expected_version: Expected version number
            actual_version: Actual current version number
            error_code: Machine-readable error code
        """
        message = (
            f"Concurrency conflict for {entity_type} {entity_id}: "
            f"expected version {expected_version}, got {actual_version}"
        )
        super().__init__(message, error_code)
        self.entity_type = entity_type
        self.entity_id = entity_id
        self.expected_version = expected_version
        self.actual_version = actual_version
