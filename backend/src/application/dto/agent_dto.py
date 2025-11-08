"""Data Transfer Objects for Agent domain.

This module provides DTOs for agent-related API operations, following Clean Architecture
principles by separating presentation concerns from domain models.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class AgentDTO(BaseModel):
    """Data Transfer Object for Agent entity.

    Used for API responses and data serialization. This DTO exposes agent data
    in a format suitable for external consumption.
    """

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

        frozen = True  # DTOs are immutable
        json_schema_extra = {
            "example": {
                "agent_id": "550e8400-e29b-41d4-a716-446655440000",
                "tenant_id": "550e8400-e29b-41d4-a716-446655440001",
                "name": "qa-agent-prod-01",
                "status": "active",
                "certificate_fingerprint": "sha256:abcdef123456...",
                "certificate_subject": "CN=qa-agent-prod-01",
                "certificate_expiry": "2025-12-31T23:59:59Z",
                "policy_ids": ["550e8400-e29b-41d4-a716-446655440002"],
                "created_at": "2025-01-01T00:00:00Z",
                "updated_at": "2025-01-15T10:30:00Z",
                "last_seen_at": "2025-01-15T10:30:00Z",
                "metadata": {"environment": "production"},
                "version": 1,
            }
        }


class CreateAgentRequest(BaseModel):
    """Request model for creating a new agent.

    Used by API endpoints to receive and validate agent creation requests.
    """

    name: str = Field(..., min_length=3, max_length=100)
    certificate_pem: str = Field(..., description="X.509 certificate in PEM format")
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate agent name.

        Args:
            v: Agent name to validate

        Returns:
            Validated and trimmed agent name

        Raises:
            ValueError: If name is invalid
        """
        v = v.strip()
        if not v:
            raise ValueError("Agent name cannot be empty or whitespace")
        return v

    @field_validator("certificate_pem")
    @classmethod
    def validate_certificate_pem(cls, v: str) -> str:
        """Validate certificate PEM format.

        Args:
            v: Certificate PEM data

        Returns:
            Validated certificate PEM

        Raises:
            ValueError: If PEM format is invalid
        """
        v = v.strip()
        if not v.startswith("-----BEGIN CERTIFICATE-----"):
            raise ValueError("Certificate must be in PEM format")
        if not v.endswith("-----END CERTIFICATE-----"):
            raise ValueError("Certificate PEM format incomplete")
        return v

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "name": "qa-agent-prod-01",
                "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
                "metadata": {"environment": "production", "team": "qa"},
            }
        }


class UpdateAgentRequest(BaseModel):
    """Request model for updating an existing agent.

    All fields are optional - only provided fields will be updated.
    """

    name: str | None = Field(None, min_length=3, max_length=100)
    certificate_pem: str | None = Field(None, description="X.509 certificate in PEM format")
    metadata: dict[str, Any] | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        """Validate agent name if provided.

        Args:
            v: Agent name to validate

        Returns:
            Validated and trimmed agent name or None

        Raises:
            ValueError: If name is invalid
        """
        if v is not None:
            v = v.strip()
            if not v:
                raise ValueError("Agent name cannot be empty or whitespace")
        return v

    @field_validator("certificate_pem")
    @classmethod
    def validate_certificate_pem(cls, v: str | None) -> str | None:
        """Validate certificate PEM format if provided.

        Args:
            v: Certificate PEM data

        Returns:
            Validated certificate PEM or None

        Raises:
            ValueError: If PEM format is invalid
        """
        if v is not None:
            v = v.strip()
            if not v.startswith("-----BEGIN CERTIFICATE-----"):
                raise ValueError("Certificate must be in PEM format")
            if not v.endswith("-----END CERTIFICATE-----"):
                raise ValueError("Certificate PEM format incomplete")
        return v

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "name": "qa-agent-prod-02",
                "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
                "metadata": {"environment": "staging"},
            }
        }


class AgentListResponse(BaseModel):
    """Response model for listing agents.

    Provides paginated list of agents with metadata.
    """

    agents: list[AgentDTO]
    total_count: int
    page: int = 1
    page_size: int = 50

    class Config:
        """Pydantic configuration."""

        frozen = True
