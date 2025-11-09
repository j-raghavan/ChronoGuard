"""Pluggable time source abstraction for deterministic testing.

This module provides a time abstraction layer that allows for deterministic testing
by enabling time manipulation and mocking. It supports nanosecond precision and
provides both system-based and mock-based time sources.

Example:
    # Production code using system time
    time_source = SystemTimeSource()
    current_time = time_source.now()

    # Test code with fixed time
    mock_time = MockTimeSource(fixed_time=datetime(2024, 1, 1, 12, 0, 0))
    test_time = mock_time.now()

    # Test code with incrementing time
    inc_time = MockTimeSource(increment_ns=1_000_000)  # 1ms increments
    time1 = inc_time.now()
    time2 = inc_time.now()  # 1ms later
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Protocol


class TimeSource(Protocol):
    """Protocol defining the interface for time sources.

    This protocol allows different time source implementations to be used
    interchangeably, enabling deterministic testing while using real system
    time in production.
    """

    def now(self) -> datetime:
        """Get current datetime in UTC.

        Returns:
            Current datetime with UTC timezone

        Example:
            current = time_source.now()
            assert current.tzinfo == UTC
        """
        ...

    def now_ns(self) -> int:
        """Get current time as nanoseconds since epoch.

        Returns:
            Nanoseconds since Unix epoch (January 1, 1970, 00:00:00 UTC)

        Example:
            ns = time_source.now_ns()
            assert isinstance(ns, int)
            assert ns > 0
        """
        ...

    def sleep(self, seconds: float) -> None:
        """Sleep for specified duration.

        Args:
            seconds: Duration to sleep in seconds

        Example:
            time_source.sleep(0.1)  # Sleep for 100ms
        """
        ...


class SystemTimeSource:
    """Production time source using actual system time.

    This implementation uses Python's datetime and time modules to provide
    real system time. It should be used in production code.

    Example:
        time_source = SystemTimeSource()
        current = time_source.now()
        ns = time_source.now_ns()
    """

    def now(self) -> datetime:
        """Get current system datetime in UTC.

        Returns:
            Current system datetime with UTC timezone

        Example:
            current = SystemTimeSource().now()
            assert current.tzinfo == UTC
        """
        return datetime.now(UTC)

    def now_ns(self) -> int:
        """Get current system time as nanoseconds since epoch.

        Returns:
            Nanoseconds since Unix epoch

        Example:
            ns = SystemTimeSource().now_ns()
            assert ns > 1_600_000_000_000_000_000  # After Sep 2020
        """
        return time.time_ns()

    def sleep(self, seconds: float) -> None:
        """Sleep for specified duration using system sleep.

        Args:
            seconds: Duration to sleep in seconds

        Example:
            SystemTimeSource().sleep(0.001)  # Sleep for 1ms
        """
        time.sleep(seconds)


class MockTimeSource:
    """Mock time source for deterministic testing.

    This implementation provides controllable time for testing purposes.
    Time can be fixed at a specific value or configured to increment
    automatically on each call.

    Attributes:
        _current_time: Current mocked datetime
        _increment_ns: Nanoseconds to increment on each now() call
        _sleep_enabled: Whether sleep() actually delays or is a no-op

    Example:
        # Fixed time
        mock = MockTimeSource(fixed_time=datetime(2024, 1, 1, 12, 0, 0))
        assert mock.now() == datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        assert mock.now() == datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)

        # Auto-incrementing time
        mock = MockTimeSource(
            fixed_time=datetime(2024, 1, 1, 12, 0, 0),
            increment_ns=1_000_000_000  # 1 second
        )
        time1 = mock.now()
        time2 = mock.now()
        assert (time2 - time1).total_seconds() == 1.0
    """

    def __init__(
        self,
        fixed_time: datetime | None = None,
        increment_ns: int = 0,
        sleep_enabled: bool = False,
    ) -> None:
        """Initialize mock time source.

        Args:
            fixed_time: Initial fixed time (defaults to 2024-01-01 00:00:00 UTC)
            increment_ns: Nanoseconds to increment on each now() call
            sleep_enabled: Whether sleep() should actually delay (default: False)

        Example:
            # Basic fixed time
            mock = MockTimeSource()

            # Custom starting time with auto-increment
            mock = MockTimeSource(
                fixed_time=datetime(2024, 6, 15, 10, 30, 0),
                increment_ns=1_000_000  # 1ms per call
            )

            # With real sleep enabled
            mock = MockTimeSource(sleep_enabled=True)
        """
        if fixed_time is None:
            self._current_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
        else:
            # Ensure UTC timezone
            if fixed_time.tzinfo is None:
                self._current_time = fixed_time.replace(tzinfo=UTC)
            else:
                self._current_time = fixed_time.astimezone(UTC)

        self._increment_ns = increment_ns
        self._sleep_enabled = sleep_enabled

    def now(self) -> datetime:
        """Get current mocked datetime in UTC.

        If increment_ns is configured, the time will advance by that amount
        on each call.

        Returns:
            Current mocked datetime with UTC timezone

        Example:
            mock = MockTimeSource(increment_ns=1_000_000_000)
            t1 = mock.now()
            t2 = mock.now()
            assert (t2 - t1).total_seconds() == 1.0
        """
        current = self._current_time
        if self._increment_ns > 0:
            self._current_time += timedelta(microseconds=self._increment_ns / 1000)
        return current

    def now_ns(self) -> int:
        """Get current mocked time as nanoseconds since epoch.

        Returns:
            Nanoseconds since Unix epoch

        Example:
            mock = MockTimeSource(fixed_time=datetime(2024, 1, 1, tzinfo=UTC))
            ns = mock.now_ns()
            assert ns == 1704067200000000000
        """
        current = self.now()
        return int(current.timestamp() * 1_000_000_000)

    def sleep(self, seconds: float) -> None:
        """Mock sleep operation.

        If sleep_enabled is True, performs actual sleep. Otherwise, advances
        the mocked time by the specified duration without delaying.

        Args:
            seconds: Duration to sleep/advance in seconds

        Example:
            # No actual delay, just time advancement
            mock = MockTimeSource()
            t1 = mock.now()
            mock.sleep(5.0)
            t2 = mock.now()
            assert (t2 - t1).total_seconds() == 5.0

            # With actual delay
            mock = MockTimeSource(sleep_enabled=True)
            mock.sleep(0.1)  # Actually sleeps for 100ms
        """
        if self._sleep_enabled:
            time.sleep(seconds)
        else:
            # Advance mocked time without actual delay
            self._current_time += timedelta(seconds=seconds)

    def set_time(self, new_time: datetime) -> None:
        """Set the current mocked time to a specific value.

        Args:
            new_time: New time to set

        Example:
            mock = MockTimeSource()
            mock.set_time(datetime(2025, 12, 31, 23, 59, 59, tzinfo=UTC))
            assert mock.now().year == 2025
        """
        if new_time.tzinfo is None:
            self._current_time = new_time.replace(tzinfo=UTC)
        else:
            self._current_time = new_time.astimezone(UTC)

    def advance(self, seconds: float = 0, minutes: float = 0, hours: float = 0) -> None:
        """Advance the mocked time by specified duration.

        Args:
            seconds: Seconds to advance
            minutes: Minutes to advance
            hours: Hours to advance

        Example:
            mock = MockTimeSource(fixed_time=datetime(2024, 1, 1, 12, 0, 0))
            mock.advance(hours=2, minutes=30)
            assert mock.now() == datetime(2024, 1, 1, 14, 30, 0, tzinfo=UTC)
        """
        total_seconds = seconds + (minutes * 60) + (hours * 3600)
        self._current_time += timedelta(seconds=total_seconds)


class TimeSourceRegistry:
    """Global registry for managing the active time source.

    This registry provides a singleton pattern for accessing the time source
    throughout the application. In production, it uses SystemTimeSource by
    default. In tests, it can be configured to use MockTimeSource.

    Example:
        # Production usage
        current = TimeSourceRegistry.get_instance().now()

        # Test usage
        mock = MockTimeSource(fixed_time=datetime(2024, 1, 1))
        TimeSourceRegistry.set_instance(mock)
        test_time = TimeSourceRegistry.get_instance().now()
        TimeSourceRegistry.reset()  # Restore default after test
    """

    _instance: TimeSource = SystemTimeSource()
    _default_instance: TimeSource = SystemTimeSource()

    @classmethod
    def get_instance(cls) -> TimeSource:
        """Get the current global time source instance.

        Returns:
            Current time source

        Example:
            time_source = TimeSourceRegistry.get_instance()
            current = time_source.now()
        """
        return cls._instance

    @classmethod
    def set_instance(cls, time_source: TimeSource) -> None:
        """Set the global time source instance.

        Args:
            time_source: New time source to use globally

        Example:
            mock = MockTimeSource(fixed_time=datetime(2024, 1, 1))
            TimeSourceRegistry.set_instance(mock)
        """
        cls._instance = time_source

    @classmethod
    def reset(cls) -> None:
        """Reset the global time source to default (SystemTimeSource).

        Example:
            # In test teardown
            TimeSourceRegistry.reset()
        """
        cls._instance = cls._default_instance


def get_time_source() -> TimeSource:
    """Get the current global time source.

    This is a convenience function that delegates to TimeSourceRegistry.

    Returns:
        Current global time source

    Example:
        current_time = get_time_source().now()
    """
    return TimeSourceRegistry.get_instance()


def format_ns_duration(nanoseconds: int) -> str:
    """Format nanosecond duration as human-readable string.

    Args:
        nanoseconds: Duration in nanoseconds

    Returns:
        Formatted duration string

    Example:
        assert format_ns_duration(1_000_000_000) == "1.000s"
        assert format_ns_duration(1_500_000) == "1.500ms"
        assert format_ns_duration(2_500) == "2.500µs"
        assert format_ns_duration(100) == "100ns"
    """
    if nanoseconds >= 1_000_000_000:
        return f"{nanoseconds / 1_000_000_000:.3f}s"
    if nanoseconds >= 1_000_000:
        return f"{nanoseconds / 1_000_000:.3f}ms"
    if nanoseconds >= 1_000:
        return f"{nanoseconds / 1_000:.3f}µs"
    return f"{nanoseconds}ns"


def datetime_to_ns(dt: datetime) -> int:
    """Convert datetime to nanoseconds since epoch.

    Args:
        dt: Datetime to convert

    Returns:
        Nanoseconds since Unix epoch

    Example:
        dt = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
        ns = datetime_to_ns(dt)
        assert ns == 1704067200000000000
    """
    return int(dt.timestamp() * 1_000_000_000)


def ns_to_datetime(nanoseconds: int) -> datetime:
    """Convert nanoseconds since epoch to datetime.

    Args:
        nanoseconds: Nanoseconds since Unix epoch

    Returns:
        Datetime in UTC

    Example:
        ns = 1704067200000000000
        dt = ns_to_datetime(ns)
        assert dt == datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    """
    return datetime.fromtimestamp(nanoseconds / 1_000_000_000, tz=UTC)
