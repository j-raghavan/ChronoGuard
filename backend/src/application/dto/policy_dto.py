"""Data Transfer Objects for Policy domain.

This module provides DTOs for policy-related API operations, following Clean Architecture
principles by separating presentation concerns from domain models.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class RuleConditionDTO(BaseModel):
    """Data Transfer Object for Rule Condition."""

    field: str
    operator: str
    value: str

    class Config:
        """Pydantic configuration."""

        frozen = True


class PolicyRuleDTO(BaseModel):
    """Data Transfer Object for Policy Rule."""

    rule_id: UUID
    name: str
    description: str
    conditions: list[RuleConditionDTO]
    action: str
    priority: int
    enabled: bool
    metadata: dict[str, str] = Field(default_factory=dict)

    class Config:
        """Pydantic configuration."""

        frozen = True


class TimeRangeDTO(BaseModel):
    """Data Transfer Object for Time Range."""

    start_hour: int
    start_minute: int
    end_hour: int
    end_minute: int

    class Config:
        """Pydantic configuration."""

        frozen = True


class TimeRestrictionDTO(BaseModel):
    """Data Transfer Object for Time Restriction."""

    allowed_time_ranges: list[TimeRangeDTO]
    allowed_days_of_week: list[int]  # Converted from set for JSON serialization
    timezone: str
    enabled: bool

    class Config:
        """Pydantic configuration."""

        frozen = True


class RateLimitDTO(BaseModel):
    """Data Transfer Object for Rate Limit."""

    requests_per_minute: int
    requests_per_hour: int
    requests_per_day: int
    burst_limit: int
    enabled: bool

    class Config:
        """Pydantic configuration."""

        frozen = True


class PolicyDTO(BaseModel):
    """Data Transfer Object for Policy entity.

    Used for API responses and data serialization. This DTO exposes policy data
    in a format suitable for external consumption.
    """

    policy_id: UUID
    tenant_id: UUID
    name: str
    description: str
    rules: list[PolicyRuleDTO] = Field(default_factory=list)
    time_restrictions: TimeRestrictionDTO | None = None
    rate_limits: RateLimitDTO | None = None
    priority: int
    status: str
    allowed_domains: list[str] = Field(default_factory=list)  # Converted from set
    blocked_domains: list[str] = Field(default_factory=list)  # Converted from set
    created_at: datetime
    updated_at: datetime
    created_by: UUID
    version: int
    metadata: dict[str, str] = Field(default_factory=dict)

    class Config:
        """Pydantic configuration."""

        frozen = True
        json_schema_extra = {
            "example": {
                "policy_id": "550e8400-e29b-41d4-a716-446655440000",
                "tenant_id": "550e8400-e29b-41d4-a716-446655440001",
                "name": "production-qa-policy",
                "description": "Access policy for production QA agents",
                "rules": [],
                "priority": 500,
                "status": "active",
                "allowed_domains": ["example.com", "test.example.com"],
                "blocked_domains": ["malicious.com"],
                "created_at": "2025-01-01T00:00:00Z",
                "updated_at": "2025-01-15T10:30:00Z",
                "created_by": "550e8400-e29b-41d4-a716-446655440002",
                "version": 1,
                "metadata": {"environment": "production"},
            }
        }


class CreatePolicyRequest(BaseModel):
    """Request model for creating a new policy.

    Used by API endpoints to receive and validate policy creation requests.
    """

    name: str = Field(..., min_length=3, max_length=100)
    description: str = Field(..., min_length=1, max_length=500)
    priority: int = Field(default=500, ge=1, le=1000)
    allowed_domains: list[str] = Field(default_factory=list)
    blocked_domains: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate policy name.

        Args:
            v: Policy name to validate

        Returns:
            Validated and trimmed policy name

        Raises:
            ValueError: If name is invalid
        """
        v = v.strip()
        if not v:
            raise ValueError("Policy name cannot be empty or whitespace")
        return v

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str) -> str:
        """Validate policy description.

        Args:
            v: Description to validate

        Returns:
            Validated and trimmed description

        Raises:
            ValueError: If description is invalid
        """
        v = v.strip()
        if not v:
            raise ValueError("Policy description cannot be empty or whitespace")
        return v

    @field_validator("allowed_domains", "blocked_domains")
    @classmethod
    def validate_domain_lists(cls, v: list[str]) -> list[str]:
        """Validate domain lists.

        Args:
            v: List of domains to validate

        Returns:
            Validated domain list

        Raises:
            ValueError: If domain list is invalid
        """
        if len(v) > 1000:
            raise ValueError(f"Too many domains: {len(v)} (maximum 1000)")

        # Strip whitespace from all domains
        return [d.strip() for d in v if d.strip()]

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "name": "production-qa-policy",
                "description": "Access policy for production QA agents",
                "priority": 500,
                "allowed_domains": ["example.com", "test.example.com"],
                "blocked_domains": [],
                "metadata": {"environment": "production", "team": "qa"},
            }
        }


class UpdatePolicyRequest(BaseModel):
    """Request model for updating an existing policy.

    All fields are optional - only provided fields will be updated.
    """

    name: str | None = Field(None, min_length=3, max_length=100)
    description: str | None = Field(None, min_length=1, max_length=500)
    priority: int | None = Field(None, ge=1, le=1000)
    allowed_domains: list[str] | None = None
    blocked_domains: list[str] | None = None
    metadata: dict[str, str] | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        """Validate policy name if provided.

        Args:
            v: Policy name to validate

        Returns:
            Validated and trimmed policy name or None

        Raises:
            ValueError: If name is invalid
        """
        if v is not None:
            v = v.strip()
            if not v:
                raise ValueError("Policy name cannot be empty or whitespace")
        return v

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str | None) -> str | None:
        """Validate policy description if provided.

        Args:
            v: Description to validate

        Returns:
            Validated and trimmed description or None

        Raises:
            ValueError: If description is invalid
        """
        if v is not None:
            v = v.strip()
            if not v:
                raise ValueError("Policy description cannot be empty or whitespace")
        return v

    @field_validator("allowed_domains", "blocked_domains")
    @classmethod
    def validate_domain_lists(cls, v: list[str] | None) -> list[str] | None:
        """Validate domain lists if provided.

        Args:
            v: List of domains to validate

        Returns:
            Validated domain list or None

        Raises:
            ValueError: If domain list is invalid
        """
        if v is not None:
            if len(v) > 1000:
                raise ValueError(f"Too many domains: {len(v)} (maximum 1000)")
            # Strip whitespace from all domains
            return [d.strip() for d in v if d.strip()]
        return v

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "name": "updated-policy-name",
                "description": "Updated policy description",
                "priority": 600,
                "allowed_domains": ["newdomain.com"],
            }
        }


class PolicyListResponse(BaseModel):
    """Response model for listing policies.

    Provides paginated list of policies with metadata.
    """

    policies: list[PolicyDTO]
    total_count: int
    page: int = 1
    page_size: int = 50

    class Config:
        """Pydantic configuration."""

        frozen = True
