"""Data Transfer Objects for Audit domain.

This module provides DTOs for audit-related API operations, following Clean Architecture
principles by separating presentation concerns from domain models.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class TimedAccessContextDTO(BaseModel):
    """Data Transfer Object for Timed Access Context."""

    request_timestamp: datetime
    processing_timestamp: datetime
    timezone_offset: int
    day_of_week: int
    hour_of_day: int
    is_business_hours: bool
    is_weekend: bool
    week_of_year: int
    month_of_year: int
    quarter_of_year: int

    class Config:
        """Pydantic configuration."""

        frozen = True


class AuditEntryDTO(BaseModel):
    """Data Transfer Object for Audit Entry.

    Used for API responses and data serialization. This DTO exposes audit entry data
    in a format suitable for external consumption.
    """

    entry_id: UUID
    tenant_id: UUID
    agent_id: UUID
    timestamp: datetime
    timestamp_nanos: int
    domain: str
    decision: str
    reason: str
    policy_id: UUID | None = None
    rule_id: UUID | None = None
    request_method: str
    request_path: str
    user_agent: str | None = None
    source_ip: str | None = None
    response_status: int | None = None
    response_size_bytes: int | None = None
    processing_time_ms: float | None = None
    timed_access_metadata: TimedAccessContextDTO
    previous_hash: str
    current_hash: str
    sequence_number: int
    metadata: dict[str, str] = Field(default_factory=dict)

    class Config:
        """Pydantic configuration."""

        frozen = True
        json_schema_extra = {
            "example": {
                "entry_id": "550e8400-e29b-41d4-a716-446655440000",
                "tenant_id": "550e8400-e29b-41d4-a716-446655440001",
                "agent_id": "550e8400-e29b-41d4-a716-446655440002",
                "timestamp": "2025-01-15T14:30:00Z",
                "timestamp_nanos": 1736951400000000000,
                "domain": "example.com",
                "decision": "allow",
                "reason": "Policy matched: production-qa-policy",
                "policy_id": "550e8400-e29b-41d4-a716-446655440003",
                "request_method": "GET",
                "request_path": "/api/data",
                "user_agent": "Mozilla/5.0 Playwright",
                "source_ip": "10.0.1.5",
                "response_status": 200,
                "processing_time_ms": 12.5,
                "timed_access_metadata": {
                    "request_timestamp": "2025-01-15T14:30:00Z",
                    "processing_timestamp": "2025-01-15T14:30:00Z",
                    "timezone_offset": 0,
                    "day_of_week": 2,
                    "hour_of_day": 14,
                    "is_business_hours": True,
                    "is_weekend": False,
                    "week_of_year": 3,
                    "month_of_year": 1,
                    "quarter_of_year": 1,
                },
                "previous_hash": "abc123...",
                "current_hash": "def456...",
                "sequence_number": 1234,
                "metadata": {},
            }
        }


class AuditQueryRequest(BaseModel):
    """Request model for querying audit entries.

    Used by API endpoints to filter and paginate audit log queries.
    """

    tenant_id: UUID | None = None
    agent_id: UUID | None = None
    domain: str | None = None
    decision: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=1000)

    @field_validator("decision")
    @classmethod
    def validate_decision(cls, v: str | None) -> str | None:
        """Validate access decision value.

        Args:
            v: Decision to validate

        Returns:
            Validated decision or None

        Raises:
            ValueError: If decision is invalid
        """
        if v is not None:
            valid_decisions = {
                "allow",
                "deny",
                "block",
                "rate_limited",
                "time_restricted",
                "policy_violation",
            }
            if v.lower() not in valid_decisions:
                raise ValueError(f"Invalid decision: {v}. Must be one of {valid_decisions}")
            return v.lower()
        return v

    @field_validator("end_time")
    @classmethod
    def validate_time_range(cls, v: datetime | None, info: Any) -> datetime | None:
        """Validate end_time is after start_time.

        Args:
            v: End time to validate
            info: Validation context with other field values

        Returns:
            Validated end time or None

        Raises:
            ValueError: If time range is invalid
        """
        if v is not None and "start_time" in info.data:
            start_time = info.data["start_time"]
            if start_time is not None and v <= start_time:
                raise ValueError("end_time must be after start_time")
        return v

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "tenant_id": "550e8400-e29b-41d4-a716-446655440001",
                "agent_id": "550e8400-e29b-41d4-a716-446655440002",
                "decision": "allow",
                "start_time": "2025-01-01T00:00:00Z",
                "end_time": "2025-01-31T23:59:59Z",
                "page": 1,
                "page_size": 50,
            }
        }


class AuditListResponse(BaseModel):
    """Response model for listing audit entries.

    Provides paginated list of audit entries with metadata.
    """

    entries: list[AuditEntryDTO]
    total_count: int
    page: int
    page_size: int
    has_more: bool

    class Config:
        """Pydantic configuration."""

        frozen = True


class AuditExportRequest(BaseModel):
    """Request model for exporting audit logs.

    Used by API endpoints to configure audit log export parameters.
    """

    tenant_id: UUID
    start_time: datetime
    end_time: datetime
    format: str = Field(default="csv", pattern="^(csv|json)$")
    include_metadata: bool = Field(default=True)
    pretty_json: bool = Field(default=False)

    @field_validator("end_time")
    @classmethod
    def validate_time_range(cls, v: datetime, info: Any) -> datetime:
        """Validate end_time is after start_time.

        Args:
            v: End time to validate
            info: Validation context with other field values

        Returns:
            Validated end time

        Raises:
            ValueError: If time range is invalid
        """
        if "start_time" in info.data:
            start_time = info.data["start_time"]
            if v <= start_time:
                raise ValueError("end_time must be after start_time")

            # Limit export range to 90 days
            time_diff = v - start_time
            if time_diff.days > 90:
                raise ValueError(f"Export range too large: {time_diff.days} days (maximum 90)")

        return v

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "tenant_id": "550e8400-e29b-41d4-a716-446655440001",
                "start_time": "2025-01-01T00:00:00Z",
                "end_time": "2025-01-31T23:59:59Z",
                "format": "csv",
                "include_metadata": True,
                "pretty_json": False,
            }
        }
