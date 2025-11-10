"""Agent domain entity representing browser automation agents."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator

from domain.common.exceptions import (
    BusinessRuleViolationError,
    InvalidStateTransitionError,
    ValidationError,
)
from domain.common.value_objects import X509Certificate


class AgentStatus(str, Enum):
    """Status enumeration for agent lifecycle."""

    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEACTIVATED = "deactivated"
    EXPIRED = "expired"


class Agent(BaseModel):
    """Agent domain entity representing a browser automation agent."""

    agent_id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    name: str
    certificate: X509Certificate
    status: AgentStatus = AgentStatus.PENDING
    policy_ids: list[UUID] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    version: int = Field(default=1)

    class Config:
        """Pydantic configuration."""

        use_enum_values = True

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate agent name meets business requirements.

        Args:
            v: Agent name to validate

        Returns:
            Validated agent name

        Raises:
            ValidationError: If name is invalid
        """
        if not v or not v.strip():
            raise ValidationError("Agent name cannot be empty", field="name", value=v)

        v = v.strip()

        if len(v) < 3:
            raise ValidationError(
                f"Agent name too short: {len(v)} characters (minimum 3)",
                field="name",
                value=v,
            )

        if len(v) > 100:
            raise ValidationError(
                f"Agent name too long: {len(v)} characters (maximum 100)",
                field="name",
                value=v,
            )

        # Only allow alphanumeric, hyphens, underscores, and spaces
        import re

        if not re.match(r"^[a-zA-Z0-9\s\-_]+$", v):
            raise ValidationError(
                f"Agent name contains invalid characters: {v}",
                field="name",
                value=v,
            )

        return v

    @field_validator("policy_ids")
    @classmethod
    def validate_policy_ids(cls, v: list[UUID]) -> list[UUID]:
        """Validate policy IDs list.

        Args:
            v: List of policy IDs

        Returns:
            Validated policy IDs list

        Raises:
            ValidationError: If policy IDs are invalid
        """
        if len(v) > 50:
            raise ValidationError(
                f"Too many policies assigned: {len(v)} (maximum 50)",
                field="policy_ids",
                value=len(v),
            )

        # Remove duplicates while preserving order
        seen = set()
        unique_ids = []
        for policy_id in v:
            if policy_id not in seen:
                seen.add(policy_id)
                unique_ids.append(policy_id)

        return unique_ids

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: int) -> int:
        """Validate version number.

        Args:
            v: Version number

        Returns:
            Validated version number

        Raises:
            ValidationError: If version is invalid
        """
        if v < 1:
            raise ValidationError(
                f"Version must be positive: {v}",
                field="version",
                value=v,
            )
        return v

    def activate(self) -> None:
        """Activate the agent.

        Raises:
            InvalidStateTransitionError: If activation is not allowed from current state
        """
        valid_transitions = {AgentStatus.PENDING, AgentStatus.SUSPENDED}

        if self.status not in valid_transitions:
            raise InvalidStateTransitionError(
                entity_type="Agent",
                current_state=self.status,
                requested_state=AgentStatus.ACTIVE,
            )

        self._update_status(AgentStatus.ACTIVE)

    def suspend(self, reason: str | None = None) -> None:
        """Suspend the agent.

        Args:
            reason: Optional reason for suspension

        Raises:
            InvalidStateTransitionError: If suspension is not allowed from current state
        """
        valid_transitions = {AgentStatus.ACTIVE}

        if self.status not in valid_transitions:
            raise InvalidStateTransitionError(
                entity_type="Agent",
                current_state=self.status,
                requested_state=AgentStatus.SUSPENDED,
            )

        if reason:
            self.metadata["suspension_reason"] = reason
            self.metadata["suspended_at"] = datetime.now(UTC).isoformat()

        self._update_status(AgentStatus.SUSPENDED)

    def deactivate(self, reason: str | None = None) -> None:
        """Deactivate the agent permanently.

        Args:
            reason: Optional reason for deactivation

        Raises:
            InvalidStateTransitionError: If deactivation is not allowed from current state
        """
        valid_transitions = {AgentStatus.ACTIVE, AgentStatus.SUSPENDED}

        if self.status not in valid_transitions:
            raise InvalidStateTransitionError(
                entity_type="Agent",
                current_state=self.status,
                requested_state=AgentStatus.DEACTIVATED,
            )

        if reason:
            self.metadata["deactivation_reason"] = reason
            self.metadata["deactivated_at"] = datetime.now(UTC).isoformat()

        self._update_status(AgentStatus.DEACTIVATED)

    def mark_expired(self) -> None:
        """Mark agent as expired due to certificate expiry.

        Raises:
            InvalidStateTransitionError: If expiry is not allowed from current state
        """
        valid_transitions = {AgentStatus.ACTIVE, AgentStatus.SUSPENDED}

        if self.status not in valid_transitions:
            raise InvalidStateTransitionError(
                entity_type="Agent",
                current_state=self.status,
                requested_state=AgentStatus.EXPIRED,
            )

        self.metadata["expired_at"] = datetime.now(UTC).isoformat()
        self.metadata["expiry_reason"] = "certificate_expired"

        self._update_status(AgentStatus.EXPIRED)

    def update_last_seen(self) -> None:
        """Update the last seen timestamp to current time."""
        self.last_seen_at = datetime.now(UTC)
        self._update_metadata()

    def assign_policy(self, policy_id: UUID) -> None:
        """Assign a policy to this agent.

        Args:
            policy_id: ID of the policy to assign

        Raises:
            BusinessRuleViolationError: If policy assignment violates business rules
        """
        if policy_id in self.policy_ids:
            raise BusinessRuleViolationError(
                f"Policy {policy_id} already assigned to agent {self.agent_id}",
                rule_name="unique_policy_assignment",
                context={"agent_id": str(self.agent_id), "policy_id": str(policy_id)},
            )

        if len(self.policy_ids) >= 50:
            raise BusinessRuleViolationError(
                f"Cannot assign more than 50 policies to agent {self.agent_id}",
                rule_name="max_policies_per_agent",
                context={
                    "agent_id": str(self.agent_id),
                    "current_count": len(self.policy_ids),
                },
            )

        self.policy_ids.append(policy_id)
        self._update_metadata()

    def remove_policy(self, policy_id: UUID) -> None:
        """Remove a policy from this agent.

        Args:
            policy_id: ID of the policy to remove

        Raises:
            BusinessRuleViolationError: If policy is not assigned
        """
        if policy_id not in self.policy_ids:
            raise BusinessRuleViolationError(
                f"Policy {policy_id} not assigned to agent {self.agent_id}",
                rule_name="policy_must_exist_to_remove",
                context={"agent_id": str(self.agent_id), "policy_id": str(policy_id)},
            )

        self.policy_ids.remove(policy_id)
        self._update_metadata()

    def update_certificate(self, new_certificate: X509Certificate) -> None:
        """Update the agent's certificate.

        Args:
            new_certificate: New certificate to assign

        Raises:
            BusinessRuleViolationError: If certificate update violates business rules
        """
        # Validate certificate is not expired
        if not new_certificate.is_valid_now:
            raise BusinessRuleViolationError(
                "Cannot assign expired certificate to agent",
                rule_name="certificate_must_be_valid",
                context={
                    "agent_id": str(self.agent_id),
                    "certificate_expiry": new_certificate.not_valid_after.isoformat(),
                },
            )

        # Store old certificate fingerprint for audit
        old_fingerprint = self.certificate.fingerprint_sha256
        self.metadata["previous_certificate_sha256"] = old_fingerprint
        self.metadata["certificate_updated_at"] = datetime.now(UTC).isoformat()

        self.certificate = new_certificate
        self._update_metadata()

    def is_certificate_expired(self) -> bool:
        """Check if the agent's certificate is expired.

        Returns:
            True if certificate is expired, False otherwise
        """
        return not self.certificate.is_valid_now

    def days_until_certificate_expiry(self) -> int:
        """Get number of days until certificate expires.

        Returns:
            Days until expiry (negative if already expired)
        """
        return self.certificate.days_until_expiry

    def is_active(self) -> bool:
        """Check if agent is in active status.

        Returns:
            True if agent is active, False otherwise
        """
        return self.status == AgentStatus.ACTIVE

    def can_make_requests(self) -> bool:
        """Check if agent can make requests based on status and certificate.

        Returns:
            True if agent can make requests, False otherwise
        """
        return self.is_active() and not self.is_certificate_expired()

    def _update_status(self, new_status: AgentStatus) -> None:
        """Update agent status and metadata.

        Args:
            new_status: New status to set
        """
        old_status = self.status
        self.status = new_status
        self.updated_at = datetime.now(UTC)
        self.version += 1

        # Store status transition in metadata
        self.metadata["status_transitions"] = self.metadata.get("status_transitions", [])
        self.metadata["status_transitions"].append(
            {
                "from": old_status,
                "to": new_status,
                "timestamp": self.updated_at.isoformat(),
            }
        )

    def _update_metadata(self) -> None:
        """Update metadata timestamps and version."""
        self.updated_at = datetime.now(UTC)
        self.version += 1

    def __str__(self) -> str:
        """String representation of agent.

        Returns:
            Human-readable agent description
        """
        return f"Agent(id={self.agent_id}, name='{self.name}', status={self.status})"

    def __repr__(self) -> str:
        """Detailed string representation of agent.

        Returns:
            Detailed agent representation
        """
        return (
            f"Agent(agent_id={self.agent_id}, tenant_id={self.tenant_id}, "
            f"name='{self.name}', status={self.status}, "
            f"policies={len(self.policy_ids)}, version={self.version})"
        )
