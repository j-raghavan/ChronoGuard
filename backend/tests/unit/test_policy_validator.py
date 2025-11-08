"""Tests for PolicyValidator domain service."""

import pytest
from domain.common.exceptions import ValidationError
from domain.policy.entity import RateLimit
from domain.policy.validator import PolicyValidator


class TestPolicyValidator:
    """Test PolicyValidator domain service."""

    @pytest.fixture
    def validator(self) -> PolicyValidator:
        """Create PolicyValidator instance."""
        return PolicyValidator()

    def test_validate_domain_list_consistency_with_valid_domains(
        self, validator: PolicyValidator
    ) -> None:
        """Test domain list validation with valid non-overlapping domains."""
        allowed = {"example.com", "test.example.com"}
        blocked = {"malicious.com", "spam.example.com"}

        # Should not raise
        validator.validate_domain_list_consistency(allowed, blocked)

    def test_validate_domain_list_consistency_with_overlap(
        self, validator: PolicyValidator
    ) -> None:
        """Test domain list validation detects overlaps."""
        allowed = {"example.com", "test.com"}
        blocked = {"example.com", "spam.com"}  # example.com in both

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_domain_list_consistency(allowed, blocked)

        assert "cannot be both allowed and blocked" in str(exc_info.value).lower()
        assert "example.com" in str(exc_info.value)

    def test_validate_domain_list_consistency_with_invalid_domain(
        self, validator: PolicyValidator
    ) -> None:
        """Test domain list validation detects invalid domain formats."""
        from domain.common.exceptions import SecurityViolationError

        allowed = {"valid.example.com"}
        blocked = {"192.168.1.1", "malicious.com"}  # IP address - raises SecurityViolationError

        # IP addresses raise SecurityViolationError which gets caught and added to invalid list
        with pytest.raises((ValidationError, SecurityViolationError)):
            validator.validate_domain_list_consistency(allowed, blocked)

    def test_validate_domain_list_consistency_with_empty_sets(
        self, validator: PolicyValidator
    ) -> None:
        """Test domain list validation with empty sets."""
        allowed: set[str] = set()
        blocked: set[str] = set()

        # Should not raise - empty is valid
        validator.validate_domain_list_consistency(allowed, blocked)

    def test_validate_rate_limit_consistency_valid(self, validator: PolicyValidator) -> None:
        """Test rate limit validation with consistent limits."""
        rate_limit = RateLimit(
            requests_per_minute=10,
            requests_per_hour=600,  # 10 * 60 = 600
            requests_per_day=14400,  # 600 * 24 = 14400
            burst_limit=15,  # <= 10 * 2
        )

        # Should not raise
        validator.validate_rate_limit_consistency(rate_limit)

    def test_validate_rate_limit_consistency_hourly_too_low(
        self, validator: PolicyValidator
    ) -> None:
        """Test rate limit validation detects hourly limit too low."""
        rate_limit = RateLimit(
            requests_per_minute=100,
            requests_per_hour=1000,  # Should be >= 100 * 60 = 6000
            requests_per_day=24000,
            burst_limit=150,
        )

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_rate_limit_consistency(rate_limit)

        assert "hourly rate limit" in str(exc_info.value).lower()
        assert "per-minute" in str(exc_info.value).lower()

    def test_validate_rate_limit_consistency_daily_too_low(
        self, validator: PolicyValidator
    ) -> None:
        """Test rate limit validation detects daily limit too low."""
        rate_limit = RateLimit(
            requests_per_minute=10,
            requests_per_hour=600,
            requests_per_day=1000,  # Should be >= 600 * 24 = 14400
            burst_limit=15,
        )

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_rate_limit_consistency(rate_limit)

        assert "daily rate limit" in str(exc_info.value).lower()
        assert "per-hour" in str(exc_info.value).lower()

    def test_validate_rate_limit_consistency_burst_too_high(
        self, validator: PolicyValidator
    ) -> None:
        """Test rate limit validation detects burst limit too high."""
        rate_limit = RateLimit(
            requests_per_minute=10,
            requests_per_hour=600,
            requests_per_day=14400,
            burst_limit=25,  # > 10 * 2 = 20
        )

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_rate_limit_consistency(rate_limit)

        assert "burst limit" in str(exc_info.value).lower()
        assert "per-minute" in str(exc_info.value).lower()

    def test_validate_time_restriction_logic_valid(self, validator: PolicyValidator) -> None:
        """Test time restriction validation with valid restrictions."""
        from domain.common.value_objects import TimeRange
        from domain.policy.entity import TimeRestriction

        time_restriction = TimeRestriction(
            allowed_time_ranges=[
                TimeRange(start_hour=9, start_minute=0, end_hour=17, end_minute=0)
            ],
            allowed_days_of_week={0, 1, 2, 3, 4},
            timezone="UTC",
        )

        # Should not raise
        validator.validate_time_restriction_logic(time_restriction)

    def test_validate_time_restriction_logic_invalid_timezone(
        self, validator: PolicyValidator
    ) -> None:
        """Test time restriction validation detects invalid timezone."""
        from domain.common.value_objects import TimeRange
        from domain.policy.entity import TimeRestriction

        time_restriction = TimeRestriction(
            allowed_time_ranges=[
                TimeRange(start_hour=9, start_minute=0, end_hour=17, end_minute=0)
            ],
            allowed_days_of_week={0, 1, 2, 3, 4},
            timezone="Invalid/Timezone",
        )

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_time_restriction_logic(time_restriction)

        assert "timezone" in str(exc_info.value).lower()

    def test_validate_policy_priority_conflicts_no_conflict(
        self, validator: PolicyValidator
    ) -> None:
        """Test priority validation with no conflicts."""
        from uuid import uuid4

        from domain.policy.entity import Policy

        existing_policies = [
            Policy(
                tenant_id=uuid4(),
                name="policy1",
                description="Test",
                created_by=uuid4(),
                priority=100,
            )
        ]

        # Different priority - no conflict
        validator.validate_policy_priority_conflicts(existing_policies, new_priority=200)

    def test_validate_policy_priority_conflicts_with_conflict(
        self, validator: PolicyValidator
    ) -> None:
        """Test priority validation detects conflicts."""
        from uuid import uuid4

        from domain.policy.entity import Policy

        existing_policies = [
            Policy(
                tenant_id=uuid4(),
                name="policy1",
                description="Test",
                created_by=uuid4(),
                priority=100,
            )
        ]

        # Same priority - conflict!
        with pytest.raises(ValidationError) as exc_info:
            validator.validate_policy_priority_conflicts(existing_policies, new_priority=100)

        assert "priority" in str(exc_info.value).lower()
        assert "conflict" in str(exc_info.value).lower()

    def test_validate_policy_rule_limits_within_limit(self, validator: PolicyValidator) -> None:
        """Test policy rule limit validation when within limits."""
        from uuid import uuid4

        from domain.policy.entity import Policy

        policy = Policy(
            tenant_id=uuid4(), name="test-policy", description="Test", created_by=uuid4()
        )

        # Adding 10 rules (well within 100 limit)
        validator.validate_policy_rule_limits(policy, new_rule_count=10)

    def test_validate_policy_rule_limits_exceeds_limit(self, validator: PolicyValidator) -> None:
        """Test policy rule limit validation when limit exceeded."""
        from uuid import uuid4

        from domain.policy.entity import Policy

        policy = Policy(
            tenant_id=uuid4(), name="test-policy", description="Test", created_by=uuid4()
        )

        # Trying to add 101 rules (exceeds 100 limit)
        with pytest.raises(ValidationError) as exc_info:
            validator.validate_policy_rule_limits(policy, new_rule_count=101)

        assert "rule limit" in str(exc_info.value).lower()

    def test_validate_priority_conflicts_with_exclusion(self, validator: PolicyValidator) -> None:
        """Test priority validation excludes specified policy."""
        from uuid import uuid4

        from domain.policy.entity import Policy

        policy_id = uuid4()
        existing_policies = [
            Policy(
                policy_id=policy_id,
                tenant_id=uuid4(),
                name="policy1",
                description="Test",
                created_by=uuid4(),
                priority=100,
            )
        ]

        # Same priority but excluded - no conflict
        validator.validate_policy_priority_conflicts(
            existing_policies, new_priority=100, exclude_policy_id=policy_id
        )

    def test_validate_policy_for_activation_with_rules(self, validator: PolicyValidator) -> None:
        """Test policy activation validation with rules."""
        from uuid import uuid4

        from domain.policy.entity import Policy, PolicyRule, RuleAction, RuleCondition

        policy = Policy(
            tenant_id=uuid4(), name="test-policy", description="Test", created_by=uuid4()
        )

        # Add a valid rule
        rule = PolicyRule(
            name="test-rule",
            description="Test",
            conditions=[RuleCondition(field="domain", operator="equals", value="example.com")],
            action=RuleAction.ALLOW,
        )
        policy.add_rule(rule)

        # Should validate successfully
        validator.validate_policy_for_activation(policy)

    def test_validate_policy_for_activation_empty_policy_fails(
        self, validator: PolicyValidator
    ) -> None:
        """Test policy activation validation fails for empty policy."""
        from uuid import uuid4

        from domain.policy.entity import Policy

        # Create policy with no rules, domains, or restrictions
        policy = Policy(
            tenant_id=uuid4(), name="empty-policy", description="Test", created_by=uuid4()
        )

        # Should fail - no enforcement mechanisms
        with pytest.raises(ValidationError) as exc_info:
            validator.validate_policy_for_activation(policy)

        assert "at least one" in str(exc_info.value).lower()

    def test_validate_policy_for_activation_with_domain_overlap(
        self, validator: PolicyValidator
    ) -> None:
        """Test policy activation validation detects domain overlaps."""
        from uuid import uuid4

        from domain.policy.entity import Policy

        policy = Policy(
            tenant_id=uuid4(),
            name="test-policy",
            description="Test",
            created_by=uuid4(),
            allowed_domains={"example.com"},
            blocked_domains={"example.com"},  # Overlap!
        )

        # Should fail due to overlap
        with pytest.raises(ValidationError) as exc_info:
            validator.validate_policy_for_activation(policy)

        assert (
            "allowed and blocked" in str(exc_info.value).lower()
            or "overlap" in str(exc_info.value).lower()
        )

    def test_validate_policy_for_activation_with_time_restrictions(
        self, validator: PolicyValidator
    ) -> None:
        """Test policy activation validation with time restrictions."""
        from uuid import uuid4

        from domain.common.value_objects import TimeRange
        from domain.policy.entity import Policy, TimeRestriction

        policy = Policy(
            tenant_id=uuid4(), name="test-policy", description="Test", created_by=uuid4()
        )

        # Add time restrictions
        time_restriction = TimeRestriction(
            allowed_time_ranges=[
                TimeRange(start_hour=9, start_minute=0, end_hour=17, end_minute=0)
            ],
            allowed_days_of_week={0, 1, 2, 3, 4},
            timezone="UTC",
        )
        policy.set_time_restrictions(time_restriction)

        # Should validate successfully with time restrictions
        validator.validate_policy_for_activation(policy)

    def test_validate_policy_for_activation_with_rate_limits(
        self, validator: PolicyValidator
    ) -> None:
        """Test policy activation validation with rate limits."""
        from uuid import uuid4

        from domain.policy.entity import Policy, RateLimit

        policy = Policy(
            tenant_id=uuid4(), name="test-policy", description="Test", created_by=uuid4()
        )

        # Add rate limits
        rate_limit = RateLimit(
            requests_per_minute=60, requests_per_hour=3600, requests_per_day=86400, burst_limit=100
        )
        policy.set_rate_limits(rate_limit)

        # Should validate successfully with rate limits
        validator.validate_policy_for_activation(policy)

    def test_validate_policy_for_activation_with_both_allowed_and_blocked(
        self, validator: PolicyValidator
    ) -> None:
        """Test policy activation validation with both allowed and blocked domains."""
        from uuid import uuid4

        from domain.policy.entity import Policy

        policy = Policy(
            tenant_id=uuid4(),
            name="test-policy",
            description="Test",
            created_by=uuid4(),
            allowed_domains={"allowed.com"},
            blocked_domains={"blocked.com"},  # Different domain - no overlap
        )

        # Should validate successfully - different domains
        validator.validate_policy_for_activation(policy)

    def test_validate_time_restriction_logic_with_overlapping_ranges(
        self, validator: PolicyValidator
    ) -> None:
        """Test time restriction validation with overlapping ranges."""
        from domain.common.value_objects import TimeRange
        from domain.policy.entity import TimeRestriction

        time_restriction = TimeRestriction(
            allowed_time_ranges=[
                TimeRange(start_hour=9, start_minute=0, end_hour=13, end_minute=0),
                TimeRange(start_hour=12, start_minute=0, end_hour=17, end_minute=0),  # Overlaps!
            ],
            allowed_days_of_week={0, 1, 2, 3, 4},
            timezone="UTC",
        )

        # Overlapping ranges are allowed (just triggers warning in production)
        validator.validate_time_restriction_logic(time_restriction)

    def test_validate_policy_for_activation_with_invalid_rate_limits(
        self, validator: PolicyValidator
    ) -> None:
        """Test policy activation validation detects invalid rate limits."""
        from uuid import uuid4

        from domain.policy.entity import Policy, RateLimit

        policy = Policy(
            tenant_id=uuid4(), name="test-policy", description="Test", created_by=uuid4()
        )

        # Add rate limits with invalid values
        rate_limit = RateLimit(
            requests_per_minute=100,
            requests_per_hour=1000,  # Too low (should be >= 100 * 60)
            requests_per_day=24000,
            burst_limit=150,
        )
        policy.set_rate_limits(rate_limit)

        # Should fail - hourly rate too low
        with pytest.raises(ValidationError) as exc_info:
            validator.validate_policy_for_activation(policy)

        assert "rate" in str(exc_info.value).lower()

    def test_validate_rule_logic_with_contradictory_equals_conditions(
        self, validator: PolicyValidator
    ) -> None:
        """Test rule validation detects contradictory equals conditions."""
        from domain.policy.entity import PolicyRule, RuleAction, RuleCondition

        rule = PolicyRule(
            name="test-rule",
            description="Test",
            conditions=[
                RuleCondition(field="domain", operator="equals", value="example.com"),
                RuleCondition(
                    field="domain", operator="equals", value="test.com"
                ),  # Different value!
            ],
            action=RuleAction.ALLOW,
        )

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_rule_logic(rule)

        assert "contradictory" in str(exc_info.value).lower()
        assert "equals" in str(exc_info.value).lower()

    def test_validate_rule_logic_with_contradictory_equals_not_equals(
        self, validator: PolicyValidator
    ) -> None:
        """Test rule validation detects contradictory equals/not_equals conditions."""
        from domain.policy.entity import PolicyRule, RuleAction, RuleCondition

        rule = PolicyRule(
            name="test-rule",
            description="Test",
            conditions=[
                RuleCondition(field="domain", operator="equals", value="example.com"),
                RuleCondition(
                    field="domain", operator="not_equals", value="example.com"
                ),  # Contradiction!
            ],
            action=RuleAction.ALLOW,
        )

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_rule_logic(rule)

        assert "contradictory" in str(exc_info.value).lower()

    def test_validate_rule_logic_with_invalid_domain_value(
        self, validator: PolicyValidator
    ) -> None:
        """Test rule validation detects invalid domain in condition."""
        from domain.common.exceptions import SecurityViolationError
        from domain.policy.entity import PolicyRule, RuleAction, RuleCondition

        rule = PolicyRule(
            name="test-rule",
            description="Test",
            conditions=[
                RuleCondition(
                    field="domain", operator="equals", value="192.168.1.1"
                )  # IP address (invalid)
            ],
            action=RuleAction.ALLOW,
        )

        # Should raise ValidationError or SecurityViolationError
        with pytest.raises((ValidationError, SecurityViolationError)):
            validator.validate_rule_logic(rule)

    def test_validate_rule_logic_with_invalid_http_method(self, validator: PolicyValidator) -> None:
        """Test rule validation detects invalid HTTP method."""
        from domain.policy.entity import PolicyRule, RuleAction, RuleCondition

        rule = PolicyRule(
            name="test-rule",
            description="Test",
            conditions=[
                RuleCondition(
                    field="method", operator="equals", value="INVALID"
                )  # Not a valid HTTP method
            ],
            action=RuleAction.ALLOW,
        )

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_rule_logic(rule)

        assert "method" in str(exc_info.value).lower()

    def test_validate_rule_logic_with_valid_http_methods(self, validator: PolicyValidator) -> None:
        """Test rule validation accepts valid HTTP methods."""
        from domain.policy.entity import PolicyRule, RuleAction, RuleCondition

        valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT"]

        for method in valid_methods:
            rule = PolicyRule(
                name=f"test-rule-{method}",
                description="Test",
                conditions=[RuleCondition(field="method", operator="equals", value=method)],
                action=RuleAction.ALLOW,
            )

            # Should not raise for valid methods
            validator.validate_rule_logic(rule)
