"""Pydantic models for ChronoGuard SDK.

This module defines all data models used by the SDK, matching the API DTOs
from the ChronoGuard backend.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class Agent(BaseModel):
    """Agent entity model."""

    agent_id: UUID
    tenant_id: UUID
    name: str
    status: str
    certificate_fingerprint: str | None = None
    certificate_subject: str | None = None
    certificate_expiry: datetime | None = None
    policy_ids: list[UUID] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    last_seen_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    version: int

    class Config:
        """Pydantic configuration."""

        frozen = True


class CreateAgentRequest(BaseModel):
    """Request model for creating a new agent."""

    name: str = Field(..., min_length=3, max_length=100)
    certificate_pem: str = Field(..., description="X.509 certificate in PEM format")
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate agent name."""
        v = v.strip()
        if not v:
            raise ValueError("Agent name cannot be empty or whitespace")
        return v

    @field_validator("certificate_pem")
    @classmethod
    def validate_certificate_pem(cls, v: str) -> str:
        """Validate certificate PEM format."""
        v = v.strip()
        if not v.startswith("-----BEGIN CERTIFICATE-----"):
            raise ValueError("Certificate must be in PEM format")
        if not v.endswith("-----END CERTIFICATE-----"):
            raise ValueError("Certificate PEM format incomplete")
        return v


class UpdateAgentRequest(BaseModel):
    """Request model for updating an existing agent."""

    name: str | None = Field(None, min_length=3, max_length=100)
    certificate_pem: str | None = Field(None, description="X.509 certificate in PEM format")
    metadata: dict[str, Any] | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        """Validate agent name if provided."""
        if v is not None:
            v = v.strip()
            if not v:
                raise ValueError("Agent name cannot be empty or whitespace")
        return v

    @field_validator("certificate_pem")
    @classmethod
    def validate_certificate_pem(cls, v: str | None) -> str | None:
        """Validate certificate PEM format if provided."""
        if v is not None:
            v = v.strip()
            if not v.startswith("-----BEGIN CERTIFICATE-----"):
                raise ValueError("Certificate must be in PEM format")
            if not v.endswith("-----END CERTIFICATE-----"):
                raise ValueError("Certificate PEM format incomplete")
        return v


class AgentListResponse(BaseModel):
    """Response model for listing agents."""

    agents: list[Agent]
    total_count: int
    page: int = 1
    page_size: int = 50

    class Config:
        """Pydantic configuration."""

        frozen = True


class RuleCondition(BaseModel):
    """Policy rule condition model."""

    field: str
    operator: str
    value: str

    class Config:
        """Pydantic configuration."""

        frozen = True


class PolicyRule(BaseModel):
    """Policy rule model."""

    rule_id: UUID
    name: str
    description: str
    conditions: list[RuleCondition]
    action: str
    priority: int
    enabled: bool
    metadata: dict[str, str] = Field(default_factory=dict)

    class Config:
        """Pydantic configuration."""

        frozen = True


class TimeRange(BaseModel):
    """Time range model."""

    start_hour: int
    start_minute: int
    end_hour: int
    end_minute: int

    class Config:
        """Pydantic configuration."""

        frozen = True


class TimeRestriction(BaseModel):
    """Time restriction model."""

    allowed_time_ranges: list[TimeRange]
    allowed_days_of_week: list[int]
    timezone: str
    enabled: bool

    class Config:
        """Pydantic configuration."""

        frozen = True


class RateLimit(BaseModel):
    """Rate limit model."""

    requests_per_minute: int
    requests_per_hour: int
    requests_per_day: int
    burst_limit: int
    enabled: bool

    class Config:
        """Pydantic configuration."""

        frozen = True


class Policy(BaseModel):
    """Policy entity model."""

    policy_id: UUID
    tenant_id: UUID
    name: str
    description: str
    rules: list[PolicyRule] = Field(default_factory=list)
    time_restrictions: TimeRestriction | None = None
    rate_limits: RateLimit | None = None
    priority: int
    status: str
    allowed_domains: list[str] = Field(default_factory=list)
    blocked_domains: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    created_by: UUID
    version: int
    metadata: dict[str, str] = Field(default_factory=dict)

    class Config:
        """Pydantic configuration."""

        frozen = True


class CreatePolicyRequest(BaseModel):
    """Request model for creating a new policy."""

    name: str = Field(..., min_length=3, max_length=100)
    description: str = Field(..., min_length=1, max_length=500)
    priority: int = Field(default=500, ge=1, le=1000)
    allowed_domains: list[str] = Field(default_factory=list)
    blocked_domains: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate policy name."""
        v = v.strip()
        if not v:
            raise ValueError("Policy name cannot be empty or whitespace")
        return v

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str) -> str:
        """Validate policy description."""
        v = v.strip()
        if not v:
            raise ValueError("Policy description cannot be empty or whitespace")
        return v

    @field_validator("allowed_domains", "blocked_domains")
    @classmethod
    def validate_domain_lists(cls, v: list[str]) -> list[str]:
        """Validate domain lists."""
        if len(v) > 1000:
            raise ValueError(f"Too many domains: {len(v)} (maximum 1000)")
        return [d.strip() for d in v if d.strip()]


class UpdatePolicyRequest(BaseModel):
    """Request model for updating an existing policy."""

    name: str | None = Field(None, min_length=3, max_length=100)
    description: str | None = Field(None, min_length=1, max_length=500)
    priority: int | None = Field(None, ge=1, le=1000)
    allowed_domains: list[str] | None = None
    blocked_domains: list[str] | None = None
    metadata: dict[str, str] | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        """Validate policy name if provided."""
        if v is not None:
            v = v.strip()
            if not v:
                raise ValueError("Policy name cannot be empty or whitespace")
        return v

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str | None) -> str | None:
        """Validate policy description if provided."""
        if v is not None:
            v = v.strip()
            if not v:
                raise ValueError("Policy description cannot be empty or whitespace")
        return v

    @field_validator("allowed_domains", "blocked_domains")
    @classmethod
    def validate_domain_lists(cls, v: list[str] | None) -> list[str] | None:
        """Validate domain lists if provided."""
        if v is not None:
            if len(v) > 1000:
                raise ValueError(f"Too many domains: {len(v)} (maximum 1000)")
            return [d.strip() for d in v if d.strip()]
        return v


class PolicyListResponse(BaseModel):
    """Response model for listing policies."""

    policies: list[Policy]
    total_count: int
    page: int = 1
    page_size: int = 50

    class Config:
        """Pydantic configuration."""

        frozen = True


class TimedAccessContext(BaseModel):
    """Timed access context model."""

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


class AuditEntry(BaseModel):
    """Audit entry model."""

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
    timed_access_metadata: TimedAccessContext
    previous_hash: str
    current_hash: str
    sequence_number: int
    metadata: dict[str, str] = Field(default_factory=dict)

    class Config:
        """Pydantic configuration."""

        frozen = True


class AuditQueryRequest(BaseModel):
    """Request model for querying audit entries."""

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
        """Validate access decision value."""
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
        """Validate end_time is after start_time."""
        if v is not None and "start_time" in info.data:
            start_time = info.data["start_time"]
            if start_time is not None and v <= start_time:
                raise ValueError("end_time must be after start_time")
        return v


class AuditListResponse(BaseModel):
    """Response model for listing audit entries."""

    entries: list[AuditEntry]
    total_count: int
    page: int
    page_size: int
    has_more: bool

    class Config:
        """Pydantic configuration."""

        frozen = True


class AuditExportRequest(BaseModel):
    """Request model for exporting audit logs."""

    tenant_id: UUID
    start_time: datetime
    end_time: datetime
    format: str = Field(default="csv", pattern="^(csv|json)$")
    include_metadata: bool = Field(default=True)
    pretty_json: bool = Field(default=False)

    @field_validator("end_time")
    @classmethod
    def validate_time_range(cls, v: datetime, info: Any) -> datetime:
        """Validate end_time is after start_time."""
        if "start_time" in info.data:
            start_time = info.data["start_time"]
            if v <= start_time:
                raise ValueError("end_time must be after start_time")

            time_diff = v - start_time
            if time_diff.days > 90:
                raise ValueError(f"Export range too large: {time_diff.days} days (maximum 90)")

        return v


class TemporalPattern(BaseModel):
    """Temporal pattern analysis model."""

    tenant_id: UUID
    start_time: datetime
    end_time: datetime
    hourly_distribution: dict[int, int] = Field(default_factory=dict)
    daily_distribution: dict[str, int] = Field(default_factory=dict)
    peak_hours: list[int] = Field(default_factory=list)
    off_hours_activity_percentage: float = 0.0
    weekend_activity_percentage: float = 0.0
    top_domains: list[dict[str, Any]] = Field(default_factory=list)
    anomalies: list[dict[str, Any]] = Field(default_factory=list)
    compliance_score: float = 0.0

    class Config:
        """Pydantic configuration."""

        frozen = True
