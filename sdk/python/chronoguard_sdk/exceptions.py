"""Exceptions for ChronoGuard SDK.

This module defines the exception hierarchy for the SDK, providing
specific exception types for different error scenarios.
"""

from __future__ import annotations

from typing import Any


class ChronoGuardError(Exception):
    """Base exception for all ChronoGuard SDK errors.

    All SDK-specific exceptions inherit from this class, allowing
    users to catch all SDK errors with a single except clause.
    """

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        """Initialize ChronoGuard error.

        Args:
            message: Error message
            details: Optional additional error details
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        """Return string representation of error."""
        if self.details:
            return f"{self.message} (details: {self.details})"
        return self.message


class APIError(ChronoGuardError):
    """Error related to API communication.

    Raised when the API returns an error response or when
    communication with the API fails.
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response_data: dict[str, Any] | None = None,
    ) -> None:
        """Initialize API error.

        Args:
            message: Error message
            status_code: HTTP status code if available
            response_data: Response data from API if available
        """
        super().__init__(message, response_data)
        self.status_code = status_code
        self.response_data = response_data or {}

    @property
    def detail(self) -> str:
        """Get error detail from response data."""
        return str(self.response_data.get("detail", self.message))


class ValidationError(ChronoGuardError):
    """Error related to request validation.

    Raised when request parameters fail validation before
    being sent to the API or when the API returns a validation error.
    """

    def __init__(
        self,
        message: str,
        field_errors: dict[str, list[str]] | None = None,
    ) -> None:
        """Initialize validation error.

        Args:
            message: Error message
            field_errors: Map of field names to validation error messages
        """
        super().__init__(message, {"field_errors": field_errors} if field_errors else None)
        self.field_errors = field_errors or {}


class NotFoundError(APIError):
    """Error indicating a requested resource was not found.

    Raised when the API returns a 404 Not Found status code.
    """

    def __init__(
        self,
        message: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
    ) -> None:
        """Initialize not found error.

        Args:
            message: Error message
            resource_type: Type of resource that was not found
            resource_id: ID of resource that was not found
        """
        details = {}
        if resource_type:
            details["resource_type"] = resource_type
        if resource_id:
            details["resource_id"] = resource_id

        super().__init__(message, status_code=404, response_data=details)
        self.resource_type = resource_type
        self.resource_id = resource_id


class ConflictError(APIError):
    """Error indicating a resource conflict.

    Raised when the API returns a 409 Conflict status code,
    typically due to duplicate resources or constraint violations.
    """

    def __init__(
        self,
        message: str,
        conflicting_field: str | None = None,
        conflicting_value: str | None = None,
    ) -> None:
        """Initialize conflict error.

        Args:
            message: Error message
            conflicting_field: Field that caused the conflict
            conflicting_value: Value that caused the conflict
        """
        details = {}
        if conflicting_field:
            details["conflicting_field"] = conflicting_field
        if conflicting_value:
            details["conflicting_value"] = conflicting_value

        super().__init__(message, status_code=409, response_data=details)
        self.conflicting_field = conflicting_field
        self.conflicting_value = conflicting_value


class AuthenticationError(APIError):
    """Error related to authentication.

    Raised when authentication fails or when the API returns
    a 401 Unauthorized status code.
    """

    def __init__(self, message: str = "Authentication failed") -> None:
        """Initialize authentication error.

        Args:
            message: Error message
        """
        super().__init__(message, status_code=401)


class AuthorizationError(APIError):
    """Error related to authorization.

    Raised when the authenticated user lacks permission to perform
    an action, typically when the API returns a 403 Forbidden status code.
    """

    def __init__(self, message: str = "Not authorized to perform this action") -> None:
        """Initialize authorization error.

        Args:
            message: Error message
        """
        super().__init__(message, status_code=403)


class RateLimitError(APIError):
    """Error indicating rate limit exceeded.

    Raised when the API returns a 429 Too Many Requests status code.
    """

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: int | None = None,
    ) -> None:
        """Initialize rate limit error.

        Args:
            message: Error message
            retry_after: Seconds to wait before retrying, if provided by API
        """
        details = {"retry_after": retry_after} if retry_after else {}
        super().__init__(message, status_code=429, response_data=details)
        self.retry_after = retry_after


class RequestTimeoutError(ChronoGuardError):
    """Error indicating request timeout.

    Raised when a request to the API times out.
    """

    def __init__(self, message: str = "Request timed out", timeout_seconds: float = 30.0) -> None:
        """Initialize timeout error.

        Args:
            message: Error message
            timeout_seconds: Timeout duration in seconds
        """
        super().__init__(message, {"timeout_seconds": timeout_seconds})
        self.timeout_seconds = timeout_seconds


# Alias for backward compatibility
TimeoutError = RequestTimeoutError


class NetworkError(ChronoGuardError):
    """Error related to network connectivity.

    Raised when network-level errors occur during API communication.
    """

    def __init__(self, message: str, original_error: Exception | None = None) -> None:
        """Initialize network error.

        Args:
            message: Error message
            original_error: Original exception that caused the network error
        """
        super().__init__(message)
        self.original_error = original_error
