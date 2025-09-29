"""Policy domain entities for access control and restrictions."""

from __future__ import annotations

from datetime import UTC
from datetime import datetime
from enum import Enum
from uuid import UUID
from uuid import uuid4

from pydantic import BaseModel
from pydantic import Field
from pydantic import field_validator

from domain.common.exceptions import ValidationError
from domain.common.value_objects import DomainName
from domain.common.value_objects import TimeRange


class RuleAction(str, Enum):
    """Actions that can be taken by policy rules."""

    ALLOW = "allow"
    DENY = "deny"
    LOG = "log"
    RATE_LIMIT = "rate_limit"


class RuleCondition(BaseModel):
    """Individual rule condition for policy evaluation."""

    field: str
    operator: str
    value: str

    @field_validator("field")
    @classmethod
    def validate_field(cls, v: str) -> str:
        """Validate condition field name.

        Args:
            v: Field name to validate

        Returns:
            Validated field name

        Raises:
            ValidationError: If field name is invalid
        """
        valid_fields = {
            "domain",
            "method",
            "path",
            "user_agent",
            "source_ip",
            "time",
            "day_of_week",
            "request_count",
        }

        if v not in valid_fields:
            raise ValidationError(
                f"Invalid rule condition field: {v}",
                field="field",
                value=v,
            )

        return v

    @field_validator("operator")
    @classmethod
    def validate_operator(cls, v: str) -> str:
        """Validate condition operator.

        Args:
            v: Operator to validate

        Returns:
            Validated operator

        Raises:
            ValidationError: If operator is invalid
        """
        valid_operators = {
            "equals",
            "not_equals",
            "contains",
            "not_contains",
            "starts_with",
            "ends_with",
            "regex_match",
            "in",
            "not_in",
            "greater_than",
            "less_than",
            "greater_equal",
            "less_equal",
        }

        if v not in valid_operators:
            raise ValidationError(
                f"Invalid rule condition operator: {v}",
                field="operator",
                value=v,
            )

        return v


class PolicyRule(BaseModel):
    """Individual policy rule with conditions and actions."""

    rule_id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    conditions: list[RuleCondition]
    action: RuleAction
    priority: int = Field(default=100)
    enabled: bool = Field(default=True)
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate rule name.

        Args:
            v: Rule name to validate

        Returns:
            Validated rule name

        Raises:
            ValidationError: If name is invalid
        """
        if not v or not v.strip():
            raise ValidationError("Rule name cannot be empty", field="name", value=v)

        v = v.strip()
        if len(v) > 200:
            raise ValidationError(
                f"Rule name too long: {len(v)} characters (maximum 200)",
                field="name",
                value=v,
            )

        return v

    @field_validator("conditions")
    @classmethod
    def validate_conditions(cls, v: list[RuleCondition]) -> list[RuleCondition]:
        """Validate rule conditions.

        Args:
            v: List of conditions to validate

        Returns:
            Validated conditions list

        Raises:
            ValidationError: If conditions are invalid
        """
        if not v:
            raise ValidationError(
                "Rule must have at least one condition",
                field="conditions",
                value=len(v),
            )

        if len(v) > 20:
            raise ValidationError(
                f"Too many conditions: {len(v)} (maximum 20)",
                field="conditions",
                value=len(v),
            )

        return v

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: int) -> int:
        """Validate rule priority.

        Args:
            v: Priority value to validate

        Returns:
            Validated priority

        Raises:
            ValidationError: If priority is invalid
        """
        if not 1 <= v <= 1000:
            raise ValidationError(
                f"Rule priority must be between 1 and 1000, got {v}",
                field="priority",
                value=v,
            )

        return v


class RateLimit(BaseModel):
    """Rate limiting configuration for policies."""

    requests_per_minute: int
    requests_per_hour: int
    requests_per_day: int
    burst_limit: int = Field(default=10)
    enabled: bool = Field(default=True)

    @field_validator("requests_per_minute", "requests_per_hour", "requests_per_day")
    @classmethod
    def validate_positive(cls, v: int) -> int:
        """Validate rate limit values are positive.

        Args:
            v: Rate limit value to validate

        Returns:
            Validated value

        Raises:
            ValidationError: If value is not positive
        """
        if v < 1:
            raise ValidationError(
                f"Rate limit must be positive, got {v}",
                field="rate_limit",
                value=v,
            )

        return v

    @field_validator("burst_limit")
    @classmethod
    def validate_burst_limit(cls, v: int) -> int:
        """Validate burst limit is reasonable.

        Args:
            v: Burst limit to validate

        Returns:
            Validated burst limit

        Raises:
            ValidationError: If burst limit is invalid
        """
        if not 1 <= v <= 1000:
            raise ValidationError(
                f"Burst limit must be between 1 and 1000, got {v}",
                field="burst_limit",
                value=v,
            )

        return v


class TimeRestriction(BaseModel):
    """Time-based access restrictions for policies."""

    allowed_time_ranges: list[TimeRange]
    allowed_days_of_week: set[int] = Field(default_factory=lambda: {0, 1, 2, 3, 4, 5, 6})
    timezone: str = Field(default="UTC")
    enabled: bool = Field(default=True)

    @field_validator("allowed_days_of_week")
    @classmethod
    def validate_days_of_week(cls, v: set[int]) -> set[int]:
        """Validate days of week are valid.

        Args:
            v: Set of day numbers to validate

        Returns:
            Validated set of days

        Raises:
            ValidationError: If days are invalid
        """
        if not v:
            raise ValidationError(
                "At least one day of week must be allowed",
                field="allowed_days_of_week",
                value=len(v),
            )

        invalid_days = {day for day in v if not 0 <= day <= 6}
        if invalid_days:
            raise ValidationError(
                f"Invalid days of week: {invalid_days} (must be 0-6)",
                field="allowed_days_of_week",
                value=invalid_days,
            )

        return v

    @field_validator("allowed_time_ranges")
    @classmethod
    def validate_time_ranges(cls, v: list[TimeRange]) -> list[TimeRange]:
        """Validate time ranges.

        Args:
            v: List of time ranges to validate

        Returns:
            Validated time ranges

        Raises:
            ValidationError: If time ranges are invalid
        """
        if not v:
            raise ValidationError(
                "At least one time range must be specified",
                field="allowed_time_ranges",
                value=len(v),
            )

        if len(v) > 10:
            raise ValidationError(
                f"Too many time ranges: {len(v)} (maximum 10)",
                field="allowed_time_ranges",
                value=len(v),
            )

        return v


class PolicyStatus(str, Enum):
    """Status enumeration for policy lifecycle."""

    DRAFT = "draft"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class Policy(BaseModel):
    """Policy domain entity for access control and restrictions."""

    policy_id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    name: str
    description: str
    rules: list[PolicyRule] = Field(default_factory=list)
    time_restrictions: TimeRestriction | None = None
    rate_limits: RateLimit | None = None
    priority: int = Field(default=500)
    status: PolicyStatus = PolicyStatus.DRAFT
    allowed_domains: set[str] = Field(default_factory=set)
    blocked_domains: set[str] = Field(default_factory=set)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    created_by: UUID
    version: int = Field(default=1)
    metadata: dict[str, str] = Field(default_factory=dict)

    class Config:
        """Pydantic configuration."""

        use_enum_values = True

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate policy name.

        Args:
            v: Policy name to validate

        Returns:
            Validated policy name

        Raises:
            ValidationError: If name is invalid
        """
        if not v or not v.strip():
            raise ValidationError("Policy name cannot be empty", field="name", value=v)

        v = v.strip()
        if len(v) < 3:
            raise ValidationError(
                f"Policy name too short: {len(v)} characters (minimum 3)",
                field="name",
                value=v,
            )

        if len(v) > 100:
            raise ValidationError(
                f"Policy name too long: {len(v)} characters (maximum 100)",
                field="name",
                value=v,
            )

        return v

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str) -> str:
        """Validate policy description.

        Args:
            v: Description to validate

        Returns:
            Validated description

        Raises:
            ValidationError: If description is invalid
        """
        if len(v) > 1000:
            raise ValidationError(
                f"Description too long: {len(v)} characters (maximum 1000)",
                field="description",
                value=len(v),
            )

        return v.strip()

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: int) -> int:
        """Validate policy priority.

        Args:
            v: Priority to validate

        Returns:
            Validated priority

        Raises:
            ValidationError: If priority is invalid
        """
        if not 1 <= v <= 1000:
            raise ValidationError(
                f"Policy priority must be between 1 and 1000, got {v}",
                field="priority",
                value=v,
            )

        return v

    @field_validator("rules")
    @classmethod
    def validate_rules(cls, v: list[PolicyRule]) -> list[PolicyRule]:
        """Validate policy rules.

        Args:
            v: List of rules to validate

        Returns:
            Validated rules list

        Raises:
            ValidationError: If rules are invalid
        """
        if len(v) > 100:
            raise ValidationError(
                f"Too many rules: {len(v)} (maximum 100)",
                field="rules",
                value=len(v),
            )

        return v

    @field_validator("allowed_domains", "blocked_domains")
    @classmethod
    def validate_domains(cls, v: set[str]) -> set[str]:
        """Validate domain lists.

        Args:
            v: Set of domains to validate

        Returns:
            Validated domain set

        Raises:
            ValidationError: If domains are invalid
        """
        if len(v) > 1000:
            raise ValidationError(
                f"Too many domains: {len(v)} (maximum 1000)",
                field="domains",
                value=len(v),
            )

        # Validate each domain
        validated_domains = set()
        for domain in v:
            domain_obj = DomainName(value=domain)  # This validates the domain
            validated_domains.add(domain_obj.value)

        return validated_domains

    def add_rule(self, rule: PolicyRule) -> None:
        """Add a rule to this policy.

        Args:
            rule: Rule to add

        Raises:
            ValidationError: If adding rule would violate constraints
        """
        if len(self.rules) >= 100:
            raise ValidationError(
                "Cannot add more than 100 rules to a policy",
                field="rules",
                value=len(self.rules),
            )

        # Check for duplicate rule names
        if any(r.name == rule.name for r in self.rules):
            raise ValidationError(
                f"Rule with name '{rule.name}' already exists in policy",
                field="rule_name",
                value=rule.name,
            )

        self.rules.append(rule)
        self._update_metadata()

    def remove_rule(self, rule_id: UUID) -> bool:
        """Remove a rule from this policy.

        Args:
            rule_id: ID of rule to remove

        Returns:
            True if rule was removed, False if not found
        """
        original_count = len(self.rules)
        self.rules = [rule for rule in self.rules if rule.rule_id != rule_id]

        if len(self.rules) < original_count:
            self._update_metadata()
            return True

        return False

    def activate(self) -> None:
        """Activate this policy.

        Raises:
            ValidationError: If policy cannot be activated
        """
        if self.status == PolicyStatus.ARCHIVED:
            raise ValidationError(
                "Cannot activate archived policy",
                field="status",
                value=self.status,
            )

        if not self.rules and not self.allowed_domains and not self.blocked_domains:
            raise ValidationError(
                "Cannot activate policy without rules or domain restrictions",
                field="policy_content",
                value="empty",
            )

        self.status = PolicyStatus.ACTIVE
        self._update_metadata()

    def suspend(self) -> None:
        """Suspend this policy."""
        if self.status == PolicyStatus.ACTIVE:
            self.status = PolicyStatus.SUSPENDED
            self._update_metadata()

    def archive(self) -> None:
        """Archive this policy permanently."""
        self.status = PolicyStatus.ARCHIVED
        self._update_metadata()

    def is_active(self) -> bool:
        """Check if policy is active.

        Returns:
            True if policy is active
        """
        return self.status == PolicyStatus.ACTIVE

    def add_allowed_domain(self, domain: str) -> None:
        """Add a domain to the allowed list.

        Args:
            domain: Domain to allow

        Raises:
            ValidationError: If domain is invalid or already blocked
        """
        domain_obj = DomainName(value=domain)  # Validates domain
        validated_domain = domain_obj.value

        if validated_domain in self.blocked_domains:
            raise ValidationError(
                f"Domain {validated_domain} is already in blocked list",
                field="domain",
                value=validated_domain,
            )

        self.allowed_domains.add(validated_domain)
        self._update_metadata()

    def add_blocked_domain(self, domain: str) -> None:
        """Add a domain to the blocked list.

        Args:
            domain: Domain to block

        Raises:
            ValidationError: If domain is invalid or already allowed
        """
        domain_obj = DomainName(value=domain)  # Validates domain
        validated_domain = domain_obj.value

        if validated_domain in self.allowed_domains:
            raise ValidationError(
                f"Domain {validated_domain} is already in allowed list",
                field="domain",
                value=validated_domain,
            )

        self.blocked_domains.add(validated_domain)
        self._update_metadata()

    def remove_domain(self, domain: str) -> bool:
        """Remove a domain from both allowed and blocked lists.

        Args:
            domain: Domain to remove

        Returns:
            True if domain was removed, False if not found
        """
        removed = False

        if domain in self.allowed_domains:
            self.allowed_domains.remove(domain)
            removed = True

        if domain in self.blocked_domains:
            self.blocked_domains.remove(domain)
            removed = True

        if removed:
            self._update_metadata()

        return removed

    def set_time_restrictions(self, time_restrictions: TimeRestriction) -> None:
        """Set time restrictions for this policy.

        Args:
            time_restrictions: Time restrictions to apply
        """
        self.time_restrictions = time_restrictions
        self._update_metadata()

    def set_rate_limits(self, rate_limits: RateLimit) -> None:
        """Set rate limits for this policy.

        Args:
            rate_limits: Rate limits to apply
        """
        self.rate_limits = rate_limits
        self._update_metadata()

    def _update_metadata(self) -> None:
        """Update policy metadata."""
        self.updated_at = datetime.now(UTC)
        self.version += 1

    def __str__(self) -> str:
        """String representation of policy.

        Returns:
            Human-readable policy description
        """
        return f"Policy(id={self.policy_id}, name='{self.name}', status={self.status})"

    def __repr__(self) -> str:
        """Detailed string representation of policy.

        Returns:
            Detailed policy representation
        """
        return (
            f"Policy(policy_id={self.policy_id}, tenant_id={self.tenant_id}, "
            f"name='{self.name}', status={self.status}, "
            f"rules={len(self.rules)}, version={self.version})"
        )
