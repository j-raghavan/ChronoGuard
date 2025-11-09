"""Tests for SDK exceptions."""

import pytest
from chronoguard_sdk.exceptions import (
    APIError,
    AuthenticationError,
    AuthorizationError,
    ChronoGuardError,
    ConflictError,
    NetworkError,
    NotFoundError,
    RateLimitError,
    TimeoutError,
    ValidationError,
)


class TestExceptions:
    """Tests for exception classes."""

    def test_chronoguard_error_basic(self):
        """Test basic ChronoGuardError."""
        error = ChronoGuardError("Test error")

        assert str(error) == "Test error"
        assert error.message == "Test error"
        assert error.details == {}

    def test_chronoguard_error_with_details(self):
        """Test ChronoGuardError with details."""
        error = ChronoGuardError("Test error", details={"key": "value"})

        assert error.details["key"] == "value"
        assert "key" in str(error)

    def test_api_error_basic(self):
        """Test basic APIError."""
        error = APIError("API failed", status_code=500)

        assert error.status_code == 500
        assert error.detail == "API failed"

    def test_api_error_with_response_data(self):
        """Test APIError with response data."""
        response_data = {"detail": "Custom error message", "code": "ERROR_CODE"}
        error = APIError("Error", status_code=400, response_data=response_data)

        assert error.status_code == 400
        assert error.detail == "Custom error message"
        assert error.response_data["code"] == "ERROR_CODE"

    def test_validation_error_basic(self):
        """Test basic ValidationError."""
        error = ValidationError("Validation failed")

        assert str(error) == "Validation failed"
        assert error.field_errors == {}

    def test_validation_error_with_field_errors(self):
        """Test ValidationError with field errors."""
        field_errors = {"name": ["Name is required"], "email": ["Invalid email"]}
        error = ValidationError("Validation failed", field_errors=field_errors)

        assert error.field_errors == field_errors
        assert error.field_errors["name"][0] == "Name is required"

    def test_not_found_error(self):
        """Test NotFoundError."""
        error = NotFoundError("Resource not found", resource_type="agent", resource_id="123")

        assert error.status_code == 404
        assert error.resource_type == "agent"
        assert error.resource_id == "123"

    def test_conflict_error(self):
        """Test ConflictError."""
        error = ConflictError(
            "Duplicate resource",
            conflicting_field="name",
            conflicting_value="test-agent",
        )

        assert error.status_code == 409
        assert error.conflicting_field == "name"
        assert error.conflicting_value == "test-agent"

    def test_authentication_error(self):
        """Test AuthenticationError."""
        error = AuthenticationError("Authentication failed")

        assert error.status_code == 401
        assert "Authentication failed" in str(error)

    def test_authorization_error(self):
        """Test AuthorizationError."""
        error = AuthorizationError("Not authorized")

        assert error.status_code == 403
        assert "Not authorized" in str(error)

    def test_rate_limit_error(self):
        """Test RateLimitError."""
        error = RateLimitError("Rate limit exceeded", retry_after=60)

        assert error.status_code == 429
        assert error.retry_after == 60

    def test_timeout_error(self):
        """Test TimeoutError."""
        error = TimeoutError("Request timed out", timeout_seconds=30.0)

        assert error.timeout_seconds == 30.0
        assert "timed out" in str(error)

    def test_network_error(self):
        """Test NetworkError."""
        original = ConnectionError("Connection failed")
        error = NetworkError("Network error", original_error=original)

        assert error.original_error is original
        assert isinstance(error.original_error, ConnectionError)

    def test_exception_inheritance(self):
        """Test exception inheritance hierarchy."""
        assert issubclass(APIError, ChronoGuardError)
        assert issubclass(ValidationError, ChronoGuardError)
        assert issubclass(NotFoundError, APIError)
        assert issubclass(ConflictError, APIError)
        assert issubclass(AuthenticationError, APIError)
        assert issubclass(RateLimitError, APIError)
        assert issubclass(TimeoutError, ChronoGuardError)
        assert issubclass(NetworkError, ChronoGuardError)
