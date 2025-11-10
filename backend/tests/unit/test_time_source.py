"""Comprehensive unit tests for time source abstraction.

Tests cover all time source implementations, time manipulation utilities,
and the global time source registry with 95%+ coverage.
"""

from __future__ import annotations

import time as time_module
from datetime import UTC, datetime, timedelta

import pytest

from domain.common.time import (
    MockTimeSource,
    SystemTimeSource,
    TimeSource,
    TimeSourceRegistry,
    datetime_to_ns,
    format_ns_duration,
    get_time_source,
    ns_to_datetime,
)


class TestTimeSourceProtocol:
    """Test TimeSource protocol compliance."""

    def test_system_time_source_implements_protocol(self) -> None:
        """SystemTimeSource should implement TimeSource protocol."""
        # Given: A SystemTimeSource instance
        time_source: TimeSource = SystemTimeSource()

        # When/Then: It implements all protocol methods
        assert hasattr(time_source, "now")
        assert hasattr(time_source, "now_ns")
        assert hasattr(time_source, "sleep")
        assert callable(time_source.now)
        assert callable(time_source.now_ns)
        assert callable(time_source.sleep)

    def test_mock_time_source_implements_protocol(self) -> None:
        """MockTimeSource should implement TimeSource protocol."""
        # Given: A MockTimeSource instance
        time_source: TimeSource = MockTimeSource()

        # When/Then: It implements all protocol methods
        assert hasattr(time_source, "now")
        assert hasattr(time_source, "now_ns")
        assert hasattr(time_source, "sleep")
        assert callable(time_source.now)
        assert callable(time_source.now_ns)
        assert callable(time_source.sleep)


class TestSystemTimeSource:
    """Test SystemTimeSource implementation."""

    def test_now_returns_utc_datetime(self) -> None:
        """now() should return current time in UTC timezone."""
        # Given: A SystemTimeSource
        time_source = SystemTimeSource()

        # When: Getting current time
        current = time_source.now()

        # Then: Returns datetime with UTC timezone
        assert isinstance(current, datetime)
        assert current.tzinfo == UTC
        # Sanity check: time should be reasonable (after 2024)
        assert current.year >= 2024

    def test_now_returns_different_times_on_successive_calls(self) -> None:
        """now() should return different times on successive calls."""
        # Given: A SystemTimeSource
        time_source = SystemTimeSource()

        # When: Getting time twice with delay
        time1 = time_source.now()
        time_module.sleep(0.001)  # Sleep 1ms
        time2 = time_source.now()

        # Then: Second time should be later
        assert time2 > time1

    def test_now_ns_returns_positive_integer(self) -> None:
        """now_ns() should return positive nanoseconds since epoch."""
        # Given: A SystemTimeSource
        time_source = SystemTimeSource()

        # When: Getting current time in nanoseconds
        ns = time_source.now_ns()

        # Then: Returns positive integer
        assert isinstance(ns, int)
        assert ns > 0
        # Sanity check: should be after 2024-01-01
        assert ns > 1_704_067_200_000_000_000

    def test_now_ns_increases_on_successive_calls(self) -> None:
        """now_ns() should increase on successive calls."""
        # Given: A SystemTimeSource
        time_source = SystemTimeSource()

        # When: Getting time in nanoseconds twice
        ns1 = time_source.now_ns()
        time_module.sleep(0.001)
        ns2 = time_source.now_ns()

        # Then: Second reading should be larger
        assert ns2 > ns1

    def test_sleep_delays_execution(self) -> None:
        """sleep() should delay execution for specified duration."""
        # Given: A SystemTimeSource
        time_source = SystemTimeSource()

        # When: Sleeping for a short duration
        start = time_module.time()
        time_source.sleep(0.01)  # 10ms
        elapsed = time_module.time() - start

        # Then: Actual elapsed time should be approximately correct
        assert elapsed >= 0.01
        assert elapsed < 0.05  # Should not take too long

    def test_sleep_with_zero_duration(self) -> None:
        """sleep() should handle zero duration without error."""
        # Given: A SystemTimeSource
        time_source = SystemTimeSource()

        # When/Then: Sleeping for 0 seconds should not raise
        time_source.sleep(0.0)


class TestMockTimeSource:
    """Test MockTimeSource implementation."""

    def test_default_initialization_uses_2024_start(self) -> None:
        """Default initialization should start at 2024-01-01 00:00:00 UTC."""
        # Given/When: Creating MockTimeSource with defaults
        mock = MockTimeSource()

        # Then: Time should be at 2024 start
        current = mock.now()
        assert current == datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)

    def test_initialization_with_fixed_time(self) -> None:
        """Initialization with fixed_time should use that time."""
        # Given: A specific datetime
        fixed = datetime(2024, 6, 15, 10, 30, 45, tzinfo=UTC)

        # When: Creating MockTimeSource with fixed time
        mock = MockTimeSource(fixed_time=fixed)

        # Then: now() returns the fixed time
        assert mock.now() == fixed

    def test_initialization_with_naive_datetime_adds_utc(self) -> None:
        """Initialization with naive datetime should add UTC timezone."""
        # Given: A naive datetime (no timezone)
        naive = datetime(2024, 3, 15, 12, 0, 0)

        # When: Creating MockTimeSource with naive time
        mock = MockTimeSource(fixed_time=naive)

        # Then: Returned time has UTC timezone
        current = mock.now()
        assert current.tzinfo == UTC
        assert current.year == 2024
        assert current.month == 3
        assert current.day == 15

    def test_initialization_with_non_utc_timezone_converts(self) -> None:
        """Initialization with non-UTC timezone should convert to UTC."""
        # Given: A datetime with offset timezone
        import zoneinfo

        pst = zoneinfo.ZoneInfo("America/Los_Angeles")
        pst_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=pst)

        # When: Creating MockTimeSource
        mock = MockTimeSource(fixed_time=pst_time)

        # Then: Time is converted to UTC
        current = mock.now()
        assert current.tzinfo == UTC
        # PST is UTC-8, so 12:00 PST = 20:00 UTC
        assert current.hour == 20

    def test_now_returns_same_time_without_increment(self) -> None:
        """now() should return same time on multiple calls without increment."""
        # Given: MockTimeSource with no increment
        mock = MockTimeSource(fixed_time=datetime(2024, 1, 1, 12, 0, 0))

        # When: Calling now() multiple times
        time1 = mock.now()
        time2 = mock.now()
        time3 = mock.now()

        # Then: All times are identical
        assert time1 == time2 == time3

    def test_now_increments_with_configured_increment_ns(self) -> None:
        """now() should increment time when increment_ns is configured."""
        # Given: MockTimeSource with 1 second increment
        mock = MockTimeSource(fixed_time=datetime(2024, 1, 1, 12, 0, 0), increment_ns=1_000_000_000)

        # When: Calling now() twice
        time1 = mock.now()
        time2 = mock.now()

        # Then: Time increments by 1 second
        delta = time2 - time1
        assert delta.total_seconds() == 1.0

    def test_now_increments_with_millisecond_precision(self) -> None:
        """now() should handle millisecond increment precision."""
        # Given: MockTimeSource with 1ms increment
        mock = MockTimeSource(fixed_time=datetime(2024, 1, 1, 12, 0, 0), increment_ns=1_000_000)

        # When: Calling now() multiple times
        times = [mock.now() for _ in range(5)]

        # Then: Each increment is 1ms
        for i in range(len(times) - 1):
            delta = times[i + 1] - times[i]
            assert abs(delta.total_seconds() - 0.001) < 1e-6

    def test_now_increments_with_microsecond_precision(self) -> None:
        """now() should handle microsecond increment precision."""
        # Given: MockTimeSource with 1µs increment
        mock = MockTimeSource(fixed_time=datetime(2024, 1, 1, 12, 0, 0), increment_ns=1_000)

        # When: Calling now() multiple times
        times = [mock.now() for _ in range(3)]

        # Then: Each increment is 1µs
        for i in range(len(times) - 1):
            delta = times[i + 1] - times[i]
            assert abs(delta.total_seconds() - 0.000001) < 1e-9

    def test_now_ns_returns_nanoseconds_for_fixed_time(self) -> None:
        """now_ns() should return correct nanoseconds for fixed time."""
        # Given: MockTimeSource with known fixed time
        fixed = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
        mock = MockTimeSource(fixed_time=fixed)

        # When: Getting time in nanoseconds
        ns = mock.now_ns()

        # Then: Nanoseconds match expected value
        # 2024-01-01 00:00:00 UTC = 1704067200 seconds since epoch
        expected_ns = 1_704_067_200_000_000_000
        assert ns == expected_ns

    def test_now_ns_increments_correctly(self) -> None:
        """now_ns() should increment by configured amount."""
        # Given: MockTimeSource with 1 second increment
        mock = MockTimeSource(fixed_time=datetime(2024, 1, 1, 12, 0, 0), increment_ns=1_000_000_000)

        # When: Getting nanoseconds twice
        ns1 = mock.now_ns()
        ns2 = mock.now_ns()

        # Then: Increment is 1 second in nanoseconds
        assert ns2 - ns1 == 1_000_000_000

    def test_sleep_advances_time_without_delay_by_default(self) -> None:
        """sleep() should advance time without actual delay by default."""
        # Given: MockTimeSource without sleep enabled
        mock = MockTimeSource(fixed_time=datetime(2024, 1, 1, 12, 0, 0))

        # When: Sleeping for 5 seconds
        start_wall_time = time_module.time()
        time1 = mock.now()
        mock.sleep(5.0)
        time2 = mock.now()
        wall_time_elapsed = time_module.time() - start_wall_time

        # Then: Mocked time advanced by 5 seconds but no actual delay
        assert (time2 - time1).total_seconds() == 5.0
        assert wall_time_elapsed < 0.1  # Should be nearly instant

    def test_sleep_advances_time_by_fractional_seconds(self) -> None:
        """sleep() should handle fractional seconds correctly."""
        # Given: MockTimeSource
        mock = MockTimeSource(fixed_time=datetime(2024, 1, 1, 12, 0, 0))

        # When: Sleeping for 1.5 seconds
        time1 = mock.now()
        mock.sleep(1.5)
        time2 = mock.now()

        # Then: Time advances by 1.5 seconds
        assert (time2 - time1).total_seconds() == 1.5

    def test_sleep_with_sleep_enabled_actually_delays(self) -> None:
        """sleep() with sleep_enabled should perform actual delay."""
        # Given: MockTimeSource with sleep enabled
        mock = MockTimeSource(sleep_enabled=True)

        # When: Sleeping for a short duration
        start = time_module.time()
        mock.sleep(0.01)  # 10ms
        elapsed = time_module.time() - start

        # Then: Actual delay occurred
        assert elapsed >= 0.01
        assert elapsed < 0.05

    def test_sleep_with_zero_duration(self) -> None:
        """sleep() should handle zero duration without error."""
        # Given: MockTimeSource
        mock = MockTimeSource()

        # When: Sleeping for 0 seconds
        time1 = mock.now()
        mock.sleep(0.0)
        time2 = mock.now()

        # Then: No time advancement
        assert time1 == time2

    def test_set_time_changes_current_time(self) -> None:
        """set_time() should change the current mocked time."""
        # Given: MockTimeSource with initial time
        mock = MockTimeSource(fixed_time=datetime(2024, 1, 1, 12, 0, 0))

        # When: Setting new time
        new_time = datetime(2025, 12, 31, 23, 59, 59, tzinfo=UTC)
        mock.set_time(new_time)

        # Then: Current time is the new time
        assert mock.now() == new_time

    def test_set_time_with_naive_datetime_adds_utc(self) -> None:
        """set_time() with naive datetime should add UTC timezone."""
        # Given: MockTimeSource
        mock = MockTimeSource()

        # When: Setting time with naive datetime
        naive = datetime(2025, 6, 15, 10, 30, 0)
        mock.set_time(naive)

        # Then: Time has UTC timezone
        current = mock.now()
        assert current.tzinfo == UTC
        assert current.year == 2025
        assert current.month == 6

    def test_set_time_with_non_utc_timezone_converts(self) -> None:
        """set_time() with non-UTC timezone should convert to UTC."""
        # Given: MockTimeSource
        mock = MockTimeSource()
        import zoneinfo

        # When: Setting time with EST timezone
        est = zoneinfo.ZoneInfo("America/New_York")
        est_time = datetime(2024, 6, 15, 12, 0, 0, tzinfo=est)
        mock.set_time(est_time)

        # Then: Time is converted to UTC
        current = mock.now()
        assert current.tzinfo == UTC
        # EDT is UTC-4 in summer, so 12:00 EDT = 16:00 UTC
        assert current.hour == 16

    def test_advance_with_seconds_only(self) -> None:
        """advance() with seconds should advance time correctly."""
        # Given: MockTimeSource
        mock = MockTimeSource(fixed_time=datetime(2024, 1, 1, 12, 0, 0))

        # When: Advancing by 30 seconds
        time1 = mock.now()
        mock.advance(seconds=30)
        time2 = mock.now()

        # Then: Time advances by 30 seconds
        assert (time2 - time1).total_seconds() == 30.0

    def test_advance_with_minutes_only(self) -> None:
        """advance() with minutes should advance time correctly."""
        # Given: MockTimeSource
        mock = MockTimeSource(fixed_time=datetime(2024, 1, 1, 12, 0, 0))

        # When: Advancing by 15 minutes
        time1 = mock.now()
        mock.advance(minutes=15)
        time2 = mock.now()

        # Then: Time advances by 15 minutes
        assert (time2 - time1).total_seconds() == 900.0

    def test_advance_with_hours_only(self) -> None:
        """advance() with hours should advance time correctly."""
        # Given: MockTimeSource
        mock = MockTimeSource(fixed_time=datetime(2024, 1, 1, 12, 0, 0))

        # When: Advancing by 2 hours
        time1 = mock.now()
        mock.advance(hours=2)
        time2 = mock.now()

        # Then: Time advances by 2 hours
        assert (time2 - time1).total_seconds() == 7200.0

    def test_advance_with_combined_units(self) -> None:
        """advance() with multiple units should sum correctly."""
        # Given: MockTimeSource
        mock = MockTimeSource(fixed_time=datetime(2024, 1, 1, 12, 0, 0))

        # When: Advancing by 2 hours, 30 minutes, 45 seconds
        time1 = mock.now()
        mock.advance(hours=2, minutes=30, seconds=45)
        time2 = mock.now()

        # Then: Time advances by total duration
        expected_seconds = (2 * 3600) + (30 * 60) + 45
        assert (time2 - time1).total_seconds() == expected_seconds

    def test_advance_with_fractional_seconds(self) -> None:
        """advance() should handle fractional seconds."""
        # Given: MockTimeSource
        mock = MockTimeSource(fixed_time=datetime(2024, 1, 1, 12, 0, 0))

        # When: Advancing by 1.5 seconds
        time1 = mock.now()
        mock.advance(seconds=1.5)
        time2 = mock.now()

        # Then: Time advances by 1.5 seconds
        assert (time2 - time1).total_seconds() == 1.5

    def test_advance_with_no_parameters(self) -> None:
        """advance() with no parameters should not change time."""
        # Given: MockTimeSource
        mock = MockTimeSource(fixed_time=datetime(2024, 1, 1, 12, 0, 0))

        # When: Advancing with defaults (all zero)
        time1 = mock.now()
        mock.advance()
        time2 = mock.now()

        # Then: Time does not change
        assert time1 == time2


class TestTimeSourceRegistry:
    """Test TimeSourceRegistry for global time source management."""

    def test_default_instance_is_system_time_source(self) -> None:
        """Default instance should be SystemTimeSource."""
        # Given: Fresh registry state
        TimeSourceRegistry.reset()

        # When: Getting instance
        instance = TimeSourceRegistry.get_instance()

        # Then: Instance is SystemTimeSource
        assert isinstance(instance, SystemTimeSource)

    def test_set_instance_changes_global_time_source(self) -> None:
        """set_instance() should change the global time source."""
        # Given: A mock time source
        mock = MockTimeSource(fixed_time=datetime(2024, 6, 15, 10, 30, 0))

        # When: Setting it as global instance
        TimeSourceRegistry.set_instance(mock)
        instance = TimeSourceRegistry.get_instance()

        # Then: Global instance is the mock
        assert instance is mock
        assert instance.now() == datetime(2024, 6, 15, 10, 30, 0, tzinfo=UTC)

        # Cleanup
        TimeSourceRegistry.reset()

    def test_reset_restores_default_instance(self) -> None:
        """reset() should restore default SystemTimeSource."""
        # Given: Registry with mock time source
        mock = MockTimeSource(fixed_time=datetime(2024, 1, 1))
        TimeSourceRegistry.set_instance(mock)

        # When: Resetting registry
        TimeSourceRegistry.reset()
        instance = TimeSourceRegistry.get_instance()

        # Then: Instance is back to SystemTimeSource
        assert isinstance(instance, SystemTimeSource)

    def test_multiple_set_instance_calls_update_global(self) -> None:
        """Multiple set_instance() calls should update global instance."""
        # Given: Two different mock time sources
        mock1 = MockTimeSource(fixed_time=datetime(2024, 1, 1))
        mock2 = MockTimeSource(fixed_time=datetime(2025, 12, 31))

        # When: Setting them sequentially
        TimeSourceRegistry.set_instance(mock1)
        assert TimeSourceRegistry.get_instance().now().year == 2024

        TimeSourceRegistry.set_instance(mock2)
        assert TimeSourceRegistry.get_instance().now().year == 2025

        # Cleanup
        TimeSourceRegistry.reset()


class TestGetTimeSource:
    """Test get_time_source() convenience function."""

    def test_get_time_source_returns_registry_instance(self) -> None:
        """get_time_source() should return the registry instance."""
        # Given: Registry with mock time source
        mock = MockTimeSource(fixed_time=datetime(2024, 6, 15, 12, 0, 0))
        TimeSourceRegistry.set_instance(mock)

        # When: Getting time source via convenience function
        time_source = get_time_source()

        # Then: Returns the same instance as registry
        assert time_source is mock
        assert time_source.now() == datetime(2024, 6, 15, 12, 0, 0, tzinfo=UTC)

        # Cleanup
        TimeSourceRegistry.reset()

    def test_get_time_source_returns_system_by_default(self) -> None:
        """get_time_source() should return SystemTimeSource by default."""
        # Given: Fresh registry state
        TimeSourceRegistry.reset()

        # When: Getting time source
        time_source = get_time_source()

        # Then: Returns SystemTimeSource
        assert isinstance(time_source, SystemTimeSource)


class TestFormatNsDuration:
    """Test format_ns_duration() utility function."""

    def test_format_seconds(self) -> None:
        """Should format nanoseconds >= 1 second as seconds."""
        # Given: 1 second in nanoseconds
        ns = 1_000_000_000

        # When: Formatting
        result = format_ns_duration(ns)

        # Then: Formatted as seconds
        assert result == "1.000s"

    def test_format_multiple_seconds(self) -> None:
        """Should format multiple seconds correctly."""
        # Given: 2.5 seconds in nanoseconds
        ns = 2_500_000_000

        # When: Formatting
        result = format_ns_duration(ns)

        # Then: Formatted as seconds
        assert result == "2.500s"

    def test_format_milliseconds(self) -> None:
        """Should format nanoseconds >= 1ms as milliseconds."""
        # Given: 1.5 milliseconds in nanoseconds
        ns = 1_500_000

        # When: Formatting
        result = format_ns_duration(ns)

        # Then: Formatted as milliseconds
        assert result == "1.500ms"

    def test_format_microseconds(self) -> None:
        """Should format nanoseconds >= 1µs as microseconds."""
        # Given: 2.5 microseconds in nanoseconds
        ns = 2_500

        # When: Formatting
        result = format_ns_duration(ns)

        # Then: Formatted as microseconds
        assert result == "2.500µs"

    def test_format_nanoseconds(self) -> None:
        """Should format nanoseconds < 1µs as nanoseconds."""
        # Given: 100 nanoseconds
        ns = 100

        # When: Formatting
        result = format_ns_duration(ns)

        # Then: Formatted as nanoseconds
        assert result == "100ns"

    def test_format_zero_nanoseconds(self) -> None:
        """Should format zero nanoseconds correctly."""
        # Given: 0 nanoseconds
        ns = 0

        # When: Formatting
        result = format_ns_duration(ns)

        # Then: Formatted as nanoseconds
        assert result == "0ns"

    def test_format_boundary_values(self) -> None:
        """Should handle boundary values correctly."""
        # Given/When/Then: Test boundaries between units
        # Values just below threshold stay in current unit
        assert format_ns_duration(999_999_999) == "1000.000ms"
        assert format_ns_duration(999_999) == "999.999µs"
        assert format_ns_duration(999) == "999ns"
        # Values at threshold switch to next unit
        assert format_ns_duration(1_000_000_000) == "1.000s"
        assert format_ns_duration(1_000_000) == "1.000ms"
        assert format_ns_duration(1_000) == "1.000µs"


class TestDatetimeToNs:
    """Test datetime_to_ns() conversion function."""

    def test_converts_epoch_start_correctly(self) -> None:
        """Should convert Unix epoch start to 0 nanoseconds."""
        # Given: Unix epoch start
        dt = datetime(1970, 1, 1, 0, 0, 0, tzinfo=UTC)

        # When: Converting to nanoseconds
        ns = datetime_to_ns(dt)

        # Then: Result is 0
        assert ns == 0

    def test_converts_2024_start_correctly(self) -> None:
        """Should convert 2024-01-01 00:00:00 UTC correctly."""
        # Given: 2024 start
        dt = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)

        # When: Converting to nanoseconds
        ns = datetime_to_ns(dt)

        # Then: Result matches expected value
        assert ns == 1_704_067_200_000_000_000

    def test_converts_datetime_with_microseconds(self) -> None:
        """Should preserve microsecond precision."""
        # Given: Datetime with microseconds
        dt = datetime(2024, 1, 1, 0, 0, 0, 123456, tzinfo=UTC)

        # When: Converting to nanoseconds
        ns = datetime_to_ns(dt)

        # Then: Microseconds are preserved in result
        expected = 1_704_067_200_123_456_000
        assert ns == expected

    def test_converts_non_utc_timezone(self) -> None:
        """Should handle non-UTC timezones correctly."""
        # Given: Datetime with EST timezone
        import zoneinfo

        est = zoneinfo.ZoneInfo("America/New_York")
        dt = datetime(2024, 1, 1, 0, 0, 0, tzinfo=est)

        # When: Converting to nanoseconds
        ns = datetime_to_ns(dt)

        # Then: Conversion accounts for timezone offset
        # EST is UTC-5, so 00:00 EST = 05:00 UTC
        expected_utc = datetime(2024, 1, 1, 5, 0, 0, tzinfo=UTC)
        assert ns == datetime_to_ns(expected_utc)


class TestNsToDatetime:
    """Test ns_to_datetime() conversion function."""

    def test_converts_zero_to_epoch_start(self) -> None:
        """Should convert 0 nanoseconds to Unix epoch start."""
        # Given: 0 nanoseconds
        ns = 0

        # When: Converting to datetime
        dt = ns_to_datetime(ns)

        # Then: Result is epoch start in UTC
        assert dt == datetime(1970, 1, 1, 0, 0, 0, tzinfo=UTC)

    def test_converts_2024_start_correctly(self) -> None:
        """Should convert 2024 start nanoseconds correctly."""
        # Given: 2024-01-01 00:00:00 in nanoseconds
        ns = 1_704_067_200_000_000_000

        # When: Converting to datetime
        dt = ns_to_datetime(ns)

        # Then: Result is 2024 start in UTC
        assert dt == datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)

    def test_converts_with_microsecond_precision(self) -> None:
        """Should preserve microsecond precision."""
        # Given: Nanoseconds with microsecond component
        ns = 1_704_067_200_123_456_000

        # When: Converting to datetime
        dt = ns_to_datetime(ns)

        # Then: Microseconds are preserved
        assert dt.microsecond == 123456

    def test_returns_utc_timezone(self) -> None:
        """Should always return datetime with UTC timezone."""
        # Given: Any nanosecond value
        ns = 1_704_067_200_000_000_000

        # When: Converting to datetime
        dt = ns_to_datetime(ns)

        # Then: Timezone is UTC
        assert dt.tzinfo == UTC


class TestRoundTripConversions:
    """Test round-trip conversions between datetime and nanoseconds."""

    def test_datetime_to_ns_to_datetime_preserves_value(self) -> None:
        """Converting datetime to ns and back should preserve value."""
        # Given: A datetime with microsecond precision
        original = datetime(2024, 6, 15, 10, 30, 45, 123456, tzinfo=UTC)

        # When: Converting to ns and back
        ns = datetime_to_ns(original)
        result = ns_to_datetime(ns)

        # Then: Result equals original
        assert result == original

    def test_ns_to_datetime_to_ns_preserves_microseconds(self) -> None:
        """Converting ns to datetime and back preserves microsecond precision."""
        # Given: Nanoseconds with microsecond precision
        # Note: Python datetime only supports microsecond precision
        original_ns = 1_704_067_200_123_456_000

        # When: Converting to datetime and back
        dt = ns_to_datetime(original_ns)
        result_ns = datetime_to_ns(dt)

        # Then: Result equals original (within microsecond precision)
        assert result_ns == original_ns

    def test_multiple_round_trips_maintain_precision(self) -> None:
        """Multiple round trips should maintain precision."""
        # Given: Original datetime
        original = datetime(2024, 1, 1, 12, 30, 45, 987654, tzinfo=UTC)

        # When: Performing multiple round trips
        result = original
        for _ in range(5):
            ns = datetime_to_ns(result)
            result = ns_to_datetime(ns)

        # Then: Result still equals original
        assert result == original


class TestIntegrationScenarios:
    """Test integration scenarios combining multiple components."""

    def test_can_switch_between_system_and_mock_time(self) -> None:
        """Should be able to switch between system and mock time sources."""
        # Given: Starting with system time
        TimeSourceRegistry.reset()
        system_time = get_time_source().now()

        # When: Switching to mock time
        mock = MockTimeSource(fixed_time=datetime(2024, 1, 1, 12, 0, 0))
        TimeSourceRegistry.set_instance(mock)
        mock_time = get_time_source().now()

        # Then: Times are different
        assert mock_time == datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        assert mock_time != system_time

        # When: Switching back to system time
        TimeSourceRegistry.reset()
        new_system_time = get_time_source().now()

        # Then: Back to real time
        assert isinstance(get_time_source(), SystemTimeSource)

    def test_mock_time_source_with_registry_for_testing(self) -> None:
        """Should use mock time source via registry for deterministic testing."""
        # Given: Mock time source registered globally
        fixed_time = datetime(2024, 6, 15, 14, 30, 0, tzinfo=UTC)
        mock = MockTimeSource(fixed_time=fixed_time, increment_ns=1_000_000_000)
        TimeSourceRegistry.set_instance(mock)

        # When: Getting time multiple times via registry
        time1 = get_time_source().now()
        time2 = get_time_source().now()
        time3 = get_time_source().now()

        # Then: Times increment predictably
        assert time1 == fixed_time
        assert (time2 - time1).total_seconds() == 1.0
        assert (time3 - time2).total_seconds() == 1.0

        # Cleanup
        TimeSourceRegistry.reset()

    def test_timing_operation_with_nanosecond_precision(self) -> None:
        """Should accurately time operations with nanosecond precision."""
        # Given: Mock time source with millisecond increments to avoid floating point issues
        mock = MockTimeSource(increment_ns=1_000_000)  # 1ms per call

        # When: Timing an operation
        start_ns = mock.now_ns()  # Gets current time, then increments
        for _ in range(99):
            mock.now()  # 99 more increments
        end_ns = mock.now_ns()  # Gets current time, then increments

        # Then: Can measure precise duration
        # Total: start (1) + loop (99) + end (1) = 101 increments
        # Duration is end - start = 100 increments
        duration_ns = end_ns - start_ns
        formatted = format_ns_duration(duration_ns)
        assert duration_ns == 100_000_000  # 100 * 1ms
        assert formatted == "100.000ms"

    def test_sleep_and_advance_combination(self) -> None:
        """Should handle combination of sleep() and advance()."""
        # Given: Mock time source
        mock = MockTimeSource(fixed_time=datetime(2024, 1, 1, 12, 0, 0))

        # When: Using sleep and advance
        start = mock.now()
        mock.sleep(60)  # 1 minute
        mock.advance(hours=1)  # 1 hour
        mock.sleep(30)  # 30 seconds
        end = mock.now()

        # Then: Total time advancement is correct
        total_seconds = (end - start).total_seconds()
        expected = 60 + 3600 + 30  # 1h 1m 30s
        assert total_seconds == expected
