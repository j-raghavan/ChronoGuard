"""Tests for common domain exceptions."""

from uuid import uuid4

from domain.common.exceptions import ConcurrencyError, RateLimitExceededError, TimeSecurityError


class TestTimeSecurityError:
    """Test TimeSecurityError exception."""

    def test_time_security_error_creation(self) -> None:
        """Test creating TimeSecurityError."""
        error = TimeSecurityError(
            "Access denied outside business hours",
            violation_type="OUTSIDE_BUSINESS_HOURS",
            context={"hour": 22},
        )

        assert "business hours" in str(error).lower()
        assert error.violation_type == "OUTSIDE_BUSINESS_HOURS"
        assert error.error_code == "TIME_SECURITY_VIOLATION"


class TestRateLimitExceededError:
    """Test RateLimitExceededError exception."""

    def test_rate_limit_exceeded_error_without_reset_time(self) -> None:
        """Test RateLimitExceededError without reset time."""
        error = RateLimitExceededError(
            limit_type="requests_per_minute", current_count=105, max_allowed=100
        )

        assert "rate limit exceeded" in str(error).lower()
        assert "105/100" in str(error)
        assert error.limit_type == "requests_per_minute"
        assert error.current_count == 105
        assert error.max_allowed == 100
        assert error.reset_time is None

    def test_rate_limit_exceeded_error_with_reset_time(self) -> None:
        """Test RateLimitExceededError with reset time."""
        reset_time = "2023-09-14T10:00:00Z"
        error = RateLimitExceededError(
            limit_type="requests_per_hour",
            current_count=1050,
            max_allowed=1000,
            reset_time=reset_time,
        )

        assert "1050/1000" in str(error)
        assert "resets at" in str(error)
        assert reset_time in str(error)
        assert error.reset_time == reset_time


class TestConcurrencyError:
    """Test ConcurrencyError exception."""

    def test_concurrency_error_creation(self) -> None:
        """Test creating ConcurrencyError."""
        entity_id = uuid4()
        error = ConcurrencyError(
            entity_type="Agent", entity_id=entity_id, expected_version=5, actual_version=6
        )

        assert "Concurrency conflict" in str(error)
        assert "Agent" in str(error)
        assert str(entity_id) in str(error)
        assert "expected version 5" in str(error)
        assert "got 6" in str(error)
        assert error.entity_type == "Agent"
        assert error.entity_id == entity_id
        assert error.expected_version == 5
        assert error.actual_version == 6
