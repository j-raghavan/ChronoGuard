"""Time range value object for temporal access controls."""

from __future__ import annotations

from datetime import UTC, datetime, time

from pydantic import BaseModel, field_validator

from domain.common.exceptions import ValidationError


class TimeRange(BaseModel):
    """Immutable time range value object for access control windows."""

    start_hour: int
    start_minute: int
    end_hour: int
    end_minute: int
    timezone_name: str = "UTC"

    class Config:
        """Pydantic configuration."""

        frozen = True

    @field_validator("start_hour", "end_hour", mode="before")
    @classmethod
    def validate_hour(cls, v: int) -> int:
        """Validate hour is in valid range.

        Args:
            v: Hour value to validate

        Returns:
            Validated hour value

        Raises:
            ValidationError: If hour is not in range 0-23
        """
        if not 0 <= v <= 23:
            raise ValidationError(
                f"Hour must be between 0 and 23, got {v}",
                field="hour",
                value=v,
            )
        return v

    @field_validator("start_minute", "end_minute", mode="before")
    @classmethod
    def validate_minute(cls, v: int) -> int:
        """Validate minute is in valid range.

        Args:
            v: Minute value to validate

        Returns:
            Validated minute value

        Raises:
            ValidationError: If minute is not in range 0-59
        """
        if not 0 <= v <= 59:
            raise ValidationError(
                f"Minute must be between 0 and 59, got {v}",
                field="minute",
                value=v,
            )
        return v

    @field_validator("timezone_name", mode="before")
    @classmethod
    def validate_timezone(cls, v: str) -> str:
        """Validate timezone name is valid.

        Args:
            v: Timezone name to validate

        Returns:
            Validated timezone name

        Raises:
            ValidationError: If timezone is invalid
        """
        try:
            # Try to create timezone to validate
            import zoneinfo

            zoneinfo.ZoneInfo(v)
        except Exception as e:
            raise ValidationError(
                f"Invalid timezone: {v}",
                field="timezone_name",
                value=v,
            ) from e
        return v

    @property
    def start_time(self) -> time:
        """Get start time as datetime.time object.

        Returns:
            Start time object
        """
        return time(hour=self.start_hour, minute=self.start_minute)

    @property
    def end_time(self) -> time:
        """Get end time as datetime.time object.

        Returns:
            End time object
        """
        return time(hour=self.end_hour, minute=self.end_minute)

    @property
    def duration_minutes(self) -> int:
        """Calculate duration in minutes.

        Returns:
            Duration in minutes, handling day overflow
        """
        start_minutes = self.start_hour * 60 + self.start_minute
        end_minutes = self.end_hour * 60 + self.end_minute

        if end_minutes >= start_minutes:
            return end_minutes - start_minutes
        # Crosses midnight
        return (24 * 60) - start_minutes + end_minutes

    def contains_time(self, check_time: datetime, target_timezone: str | None = None) -> bool:
        """Check if a given datetime falls within this time range.

        Args:
            check_time: Datetime to check
            target_timezone: Optional timezone to convert to (defaults to range timezone)

        Returns:
            True if time falls within range, False otherwise
        """
        import zoneinfo

        # Convert to target timezone
        tz_name = target_timezone or self.timezone_name
        target_tz = zoneinfo.ZoneInfo(tz_name)

        if check_time.tzinfo is None:
            # Assume UTC if no timezone
            check_time = check_time.replace(tzinfo=UTC)

        localized_time = check_time.astimezone(target_tz)
        current_time = localized_time.time()

        # Handle ranges that don't cross midnight
        if self.start_time <= self.end_time:
            return self.start_time <= current_time <= self.end_time
        # Handle ranges that cross midnight
        return current_time >= self.start_time or current_time <= self.end_time

    def overlaps_with(self, other: TimeRange) -> bool:
        """Check if this time range overlaps with another.

        Args:
            other: Other time range to check overlap with

        Returns:
            True if ranges overlap, False otherwise
        """
        # Convert both to minutes for easier comparison
        self_start = self.start_hour * 60 + self.start_minute
        self_end = self.end_hour * 60 + self.end_minute
        other_start = other.start_hour * 60 + other.start_minute
        other_end = other.end_hour * 60 + other.end_minute

        # Handle midnight crossing
        if self_end < self_start:
            self_end += 24 * 60
        if other_end < other_start:
            other_end += 24 * 60

        # Check for overlap
        return max(self_start, other_start) < min(self_end, other_end)

    @classmethod
    def business_hours(cls, timezone_name: str = "UTC") -> TimeRange:
        """Create a standard business hours time range (9 AM - 5 PM).

        Args:
            timezone_name: Timezone for business hours

        Returns:
            TimeRange representing business hours
        """
        return cls(
            start_hour=9,
            start_minute=0,
            end_hour=17,
            end_minute=0,
            timezone_name=timezone_name,
        )

    @classmethod
    def all_day(cls, timezone_name: str = "UTC") -> TimeRange:
        """Create an all-day time range (24 hours).

        Args:
            timezone_name: Timezone for the range

        Returns:
            TimeRange representing all day
        """
        return cls(
            start_hour=0,
            start_minute=0,
            end_hour=23,
            end_minute=59,
            timezone_name=timezone_name,
        )

    def __str__(self) -> str:
        """String representation of time range.

        Returns:
            Human-readable time range string
        """
        return (
            f"{self.start_hour:02d}:{self.start_minute:02d}"
            f"-{self.end_hour:02d}:{self.end_minute:02d} {self.timezone_name}"
        )
