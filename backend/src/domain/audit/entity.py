"""Audit domain entities for immutable access logging and verification."""

from __future__ import annotations

import hashlib
import hmac
import time
from datetime import UTC
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID
from uuid import uuid4

from pydantic import BaseModel
from pydantic import Field
from pydantic import field_validator

from domain.common.exceptions import ValidationError
from domain.common.value_objects import DomainName


class AccessDecision(str, Enum):
    """Enumeration of access control decisions."""

    ALLOW = "allow"
    DENY = "deny"
    BLOCK = "block"
    RATE_LIMITED = "rate_limited"
    TIME_RESTRICTED = "time_restricted"
    POLICY_VIOLATION = "policy_violation"


class TimedAccessContext(BaseModel):
    """Temporal context information for access attempts."""

    request_timestamp: datetime
    processing_timestamp: datetime
    timezone_offset: int  # Minutes from UTC
    day_of_week: int  # 0=Monday, 6=Sunday
    hour_of_day: int
    is_business_hours: bool
    is_weekend: bool
    week_of_year: int
    month_of_year: int
    quarter_of_year: int

    class Config:
        """Pydantic configuration."""

        frozen = True

    @classmethod
    def create_from_timestamp(cls, timestamp: datetime) -> TimedAccessContext:
        """Create timed access context from a timestamp.

        Args:
            timestamp: Timestamp to create context from

        Returns:
            TimedAccessContext instance
        """
        # Ensure UTC timezone
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        elif timestamp.tzinfo != UTC:
            timestamp = timestamp.astimezone(UTC)

        # Calculate business hours (9 AM - 5 PM UTC)
        is_business_hours = 9 <= timestamp.hour < 17
        is_weekend = timestamp.weekday() >= 5  # Saturday=5, Sunday=6

        return cls(
            request_timestamp=timestamp,
            processing_timestamp=datetime.now(UTC),
            timezone_offset=0,  # Always UTC for consistency
            day_of_week=timestamp.weekday(),
            hour_of_day=timestamp.hour,
            is_business_hours=is_business_hours,
            is_weekend=is_weekend,
            week_of_year=timestamp.isocalendar()[1],
            month_of_year=timestamp.month,
            quarter_of_year=((timestamp.month - 1) // 3) + 1,
        )


class AuditEntry(BaseModel):
    """Immutable audit log entry with cryptographic integrity."""

    entry_id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    agent_id: UUID
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    timestamp_nanos: int = Field(default_factory=time.time_ns)
    domain: DomainName
    decision: AccessDecision
    reason: str = ""
    policy_id: UUID | None = None
    rule_id: UUID | None = None
    request_method: str = "GET"
    request_path: str = "/"
    user_agent: str | None = None
    source_ip: str | None = None
    response_status: int | None = None
    response_size_bytes: int | None = None
    processing_time_ms: float | None = None
    timed_access_metadata: TimedAccessContext
    previous_hash: str = ""
    current_hash: str = ""
    sequence_number: int = 0
    metadata: dict[str, str] = Field(default_factory=dict)

    class Config:
        """Pydantic configuration."""

        frozen = True

    def __init__(self, **data: Any) -> None:
        """Initialize audit entry with temporal context and hash calculation."""
        # Create timed access metadata if not provided
        if "timed_access_metadata" not in data and "timestamp" in data:
            data["timed_access_metadata"] = TimedAccessContext.create_from_timestamp(
                data["timestamp"]
            )
        elif "timed_access_metadata" not in data:
            timestamp = datetime.now(UTC)
            data["timestamp"] = timestamp
            data["timed_access_metadata"] = TimedAccessContext.create_from_timestamp(timestamp)

        super().__init__(**data)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str | DomainName) -> DomainName:
        """Validate domain is a DomainName instance.

        Args:
            v: Domain value to validate

        Returns:
            Validated DomainName

        Raises:
            ValidationError: If domain is invalid
        """
        if isinstance(v, str):
            return DomainName(value=v)
        if isinstance(v, DomainName):
            return v
        raise ValidationError(
            f"Domain must be string or DomainName, got {type(v)}",
            field="domain",
            value=str(v),
        )

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: datetime) -> datetime:
        """Validate timestamp is timezone-aware UTC.

        Args:
            v: Timestamp to validate

        Returns:
            Validated UTC timestamp

        Raises:
            ValidationError: If timestamp is invalid
        """
        if v.tzinfo is None:
            # Assume UTC if no timezone
            return v.replace(tzinfo=UTC)
        if v.tzinfo != UTC:
            # Convert to UTC
            return v.astimezone(UTC)
        return v

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, v: str) -> str:
        """Validate reason string.

        Args:
            v: Reason to validate

        Returns:
            Validated reason

        Raises:
            ValidationError: If reason is too long
        """
        if len(v) > 500:
            raise ValidationError(
                f"Reason too long: {len(v)} characters (maximum 500)",
                field="reason",
                value=len(v),
            )
        return v.strip()

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, v: str | None) -> str | None:
        """Validate source IP address format.

        Args:
            v: IP address to validate

        Returns:
            Validated IP address

        Raises:
            ValidationError: If IP format is invalid
        """
        if v is None:
            return v

        import ipaddress

        try:
            ipaddress.ip_address(v)
            return v
        except ValueError as e:
            raise ValidationError(
                f"Invalid IP address format: {v}",
                field="source_ip",
                value=v,
            ) from e

    @field_validator("sequence_number")
    @classmethod
    def validate_sequence_number(cls, v: int) -> int:
        """Validate sequence number is non-negative.

        Args:
            v: Sequence number to validate

        Returns:
            Validated sequence number

        Raises:
            ValidationError: If sequence number is negative
        """
        if v < 0:
            raise ValidationError(
                f"Sequence number must be non-negative, got {v}",
                field="sequence_number",
                value=v,
            )
        return v

    def calculate_hash(self, previous_hash: str = "", secret_key: bytes | None = None) -> str:
        """Calculate cryptographic hash for this audit entry.

        Args:
            previous_hash: Hash of the previous entry in the chain
            secret_key: Optional secret key for HMAC

        Returns:
            Calculated hash as hex string
        """
        # Create deterministic serialization of entry data
        hash_data = (
            f"{self.entry_id}|"
            f"{self.tenant_id}|"
            f"{self.agent_id}|"
            f"{self.timestamp.isoformat()}|"
            f"{self.timestamp_nanos}|"
            f"{self.domain.value}|"
            f"{self.decision.value}|"
            f"{self.reason}|"
            f"{self.policy_id or ''}|"
            f"{self.rule_id or ''}|"
            f"{self.request_method}|"
            f"{self.request_path}|"
            f"{self.user_agent or ''}|"
            f"{self.source_ip or ''}|"
            f"{self.response_status or ''}|"
            f"{self.response_size_bytes or ''}|"
            f"{self.processing_time_ms or ''}|"
            f"{self.sequence_number}|"
            f"{previous_hash}"
        )

        if secret_key:
            # Use HMAC for authenticated hashing
            return hmac.new(secret_key, hash_data.encode("utf-8"), hashlib.sha256).hexdigest()
        # Use regular SHA-256 hash
        return hashlib.sha256(hash_data.encode("utf-8")).hexdigest()

    def with_hash(self, previous_hash: str = "", secret_key: bytes | None = None) -> AuditEntry:
        """Create a new audit entry with calculated hash.

        Args:
            previous_hash: Hash of the previous entry
            secret_key: Optional secret key for HMAC

        Returns:
            New AuditEntry with calculated hash
        """
        calculated_hash = self.calculate_hash(previous_hash, secret_key)

        # Create new instance with updated hash values
        return self.__class__(
            **{
                **self.model_dump(),
                "previous_hash": previous_hash,
                "current_hash": calculated_hash,
            }
        )

    def verify_hash(self, secret_key: bytes | None = None) -> bool:
        """Verify the integrity of this audit entry's hash.

        Args:
            secret_key: Optional secret key used for original hash

        Returns:
            True if hash is valid, False otherwise
        """
        if not self.current_hash:
            return False

        expected_hash = self.calculate_hash(self.previous_hash, secret_key)
        return hmac.compare_digest(self.current_hash, expected_hash)

    def is_access_allowed(self) -> bool:
        """Check if this audit entry represents an allowed access.

        Returns:
            True if access was allowed
        """
        return self.decision == AccessDecision.ALLOW

    def is_access_denied(self) -> bool:
        """Check if this audit entry represents a denied access.

        Returns:
            True if access was denied
        """
        return self.decision in {
            AccessDecision.DENY,
            AccessDecision.BLOCK,
            AccessDecision.RATE_LIMITED,
            AccessDecision.TIME_RESTRICTED,
            AccessDecision.POLICY_VIOLATION,
        }

    def get_risk_score(self) -> int:
        """Calculate risk score for this access attempt.

        Returns:
            Risk score from 0 (low) to 100 (high)
        """
        score = 0

        # Base score for denied access
        if self.is_access_denied():
            score += 30

        # Off-hours access
        if not self.timed_access_metadata.is_business_hours:
            score += 20

        # Weekend access
        if self.timed_access_metadata.is_weekend:
            score += 15

        # Suspicious user agents
        if self.user_agent:
            suspicious_agents = ["curl", "wget", "python", "bot", "crawler"]
            if any(agent in self.user_agent.lower() for agent in suspicious_agents):
                score += 25

        # Multiple rapid denials would require additional context
        # This could be enhanced with request frequency analysis

        return min(score, 100)

    def to_json_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dictionary.

        Returns:
            Dictionary representation suitable for JSON serialization
        """
        return {
            "entry_id": str(self.entry_id),
            "tenant_id": str(self.tenant_id),
            "agent_id": str(self.agent_id),
            "timestamp": self.timestamp.isoformat(),
            "timestamp_nanos": self.timestamp_nanos,
            "domain": self.domain.value,
            "decision": self.decision.value,
            "reason": self.reason,
            "policy_id": str(self.policy_id) if self.policy_id else None,
            "rule_id": str(self.rule_id) if self.rule_id else None,
            "request_method": self.request_method,
            "request_path": self.request_path,
            "user_agent": self.user_agent,
            "source_ip": self.source_ip,
            "response_status": self.response_status,
            "response_size_bytes": self.response_size_bytes,
            "processing_time_ms": self.processing_time_ms,
            "timed_access_metadata": self.timed_access_metadata.model_dump(),
            "previous_hash": self.previous_hash,
            "current_hash": self.current_hash,
            "sequence_number": self.sequence_number,
            "metadata": self.metadata,
            "risk_score": self.get_risk_score(),
        }

    def __str__(self) -> str:
        """String representation of audit entry.

        Returns:
            Human-readable audit entry description
        """
        return (
            f"AuditEntry(id={self.entry_id}, agent={self.agent_id}, "
            f"domain={self.domain.value}, decision={self.decision.value})"
        )

    def __repr__(self) -> str:
        """Detailed string representation of audit entry.

        Returns:
            Detailed audit entry representation
        """
        return (
            f"AuditEntry(entry_id={self.entry_id}, tenant_id={self.tenant_id}, "
            f"agent_id={self.agent_id}, timestamp={self.timestamp.isoformat()}, "
            f"domain={self.domain.value}, decision={self.decision.value}, "
            f"sequence={self.sequence_number})"
        )


class ChainVerificationResult(BaseModel):
    """Result of audit chain verification."""

    is_valid: bool
    total_entries: int
    verified_entries: int
    broken_chains: int
    hash_mismatches: int
    sequence_gaps: int
    errors: list[str] = Field(default_factory=list)
    verification_timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def integrity_percentage(self) -> float:
        """Calculate integrity percentage.

        Returns:
            Percentage of entries with valid integrity
        """
        if self.total_entries == 0:
            return 100.0
        return (self.verified_entries / self.total_entries) * 100.0

    @property
    def has_critical_issues(self) -> bool:
        """Check if there are critical integrity issues.

        Returns:
            True if critical issues are detected
        """
        return self.hash_mismatches > 0 or self.broken_chains > 0
