"""Unit tests for policy domain components."""

from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from domain.common.exceptions import (
    BusinessRuleViolationError,
    DuplicateEntityError,
    ValidationError,
)
from domain.common.value_objects import TimeRange
from domain.policy.entity import (
    Policy,
    PolicyRule,
    PolicyStatus,
    RateLimit,
    RuleAction,
    RuleCondition,
    TimeRestriction,
)
from domain.policy.service import PolicyEvaluationResult, PolicyService
from domain.policy.validator import PolicyValidator


class TestRuleCondition:
    """Unit tests for RuleCondition value object."""

    def test_create_valid_condition(self) -> None:
        """Test creating a valid rule condition."""
        condition = RuleCondition(field="domain", operator="equals", value="example.com")

        assert condition.field == "domain"
        assert condition.operator == "equals"
        assert condition.value == "example.com"

    def test_invalid_field_validation(self) -> None:
        """Test validation of invalid field."""
        with pytest.raises(ValidationError) as exc_info:
            RuleCondition(field="invalid_field", operator="equals", value="test")

        assert "Invalid rule condition field" in str(exc_info.value)

    def test_invalid_operator_validation(self) -> None:
        """Test validation of invalid operator."""
        with pytest.raises(ValidationError) as exc_info:
            RuleCondition(field="domain", operator="invalid_operator", value="test")

        assert "Invalid rule condition operator" in str(exc_info.value)

    def test_valid_fields(self) -> None:
        """Test all valid fields work."""
        valid_fields = [
            "domain",
            "method",
            "path",
            "user_agent",
            "source_ip",
            "time",
            "day_of_week",
            "request_count",
        ]

        for field in valid_fields:
            condition = RuleCondition(field=field, operator="equals", value="test")
            assert condition.field == field

    def test_valid_operators(self) -> None:
        """Test all valid operators work."""
        valid_operators = [
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
        ]

        for operator in valid_operators:
            condition = RuleCondition(field="domain", operator=operator, value="test")
            assert condition.operator == operator


class TestPolicyRule:
    """Unit tests for PolicyRule entity."""

    def test_create_valid_rule(self, test_rule_condition: RuleCondition) -> None:
        """Test creating a valid policy rule."""
        rule = PolicyRule(
            name="Test Rule",
            description="Test rule description",
            conditions=[test_rule_condition],
            action=RuleAction.ALLOW,
            priority=100,
        )

        assert rule.name == "Test Rule"
        assert rule.description == "Test rule description"
        assert len(rule.conditions) == 1
        assert rule.action == RuleAction.ALLOW
        assert rule.priority == 100
        assert rule.enabled is True

    def test_rule_name_validation_empty(self, test_rule_condition: RuleCondition) -> None:
        """Test rule name validation with empty name."""
        with pytest.raises(ValidationError) as exc_info:
            PolicyRule(
                name="",
                description="Test",
                conditions=[test_rule_condition],
                action=RuleAction.ALLOW,
            )

        assert "Rule name cannot be empty" in str(exc_info.value)

    def test_rule_name_validation_too_long(self, test_rule_condition: RuleCondition) -> None:
        """Test rule name validation with too long name."""
        long_name = "a" * 201

        with pytest.raises(ValidationError) as exc_info:
            PolicyRule(
                name=long_name,
                description="Test",
                conditions=[test_rule_condition],
                action=RuleAction.ALLOW,
            )

        assert "Rule name too long" in str(exc_info.value)

    def test_rule_conditions_validation_empty(self) -> None:
        """Test rule conditions validation with empty list."""
        with pytest.raises(ValidationError) as exc_info:
            PolicyRule(
                name="Test Rule",
                description="Test",
                conditions=[],
                action=RuleAction.ALLOW,
            )

        assert "Rule must have at least one condition" in str(exc_info.value)

    def test_rule_conditions_validation_too_many(self) -> None:
        """Test rule conditions validation with too many conditions."""
        conditions = [
            RuleCondition(field="domain", operator="equals", value=f"domain{i}.com")
            for i in range(21)
        ]

        with pytest.raises(ValidationError) as exc_info:
            PolicyRule(
                name="Test Rule",
                description="Test",
                conditions=conditions,
                action=RuleAction.ALLOW,
            )

        assert "Too many conditions" in str(exc_info.value)

    def test_rule_priority_validation_invalid(self, test_rule_condition: RuleCondition) -> None:
        """Test rule priority validation with invalid values."""
        invalid_priorities = [0, -1, 1001]

        for priority in invalid_priorities:
            with pytest.raises(ValidationError) as exc_info:
                PolicyRule(
                    name="Test Rule",
                    description="Test",
                    conditions=[test_rule_condition],
                    action=RuleAction.ALLOW,
                    priority=priority,
                )

            assert "Rule priority must be between 1 and 1000" in str(exc_info.value)


class TestRateLimit:
    """Unit tests for RateLimit value object."""

    def test_create_valid_rate_limit(self) -> None:
        """Test creating a valid rate limit."""
        rate_limit = RateLimit(
            requests_per_minute=60,
            requests_per_hour=3600,
            requests_per_day=86400,
            burst_limit=10,
        )

        assert rate_limit.requests_per_minute == 60
        assert rate_limit.requests_per_hour == 3600
        assert rate_limit.requests_per_day == 86400
        assert rate_limit.burst_limit == 10
        assert rate_limit.enabled is True

    def test_rate_limit_validation_negative(self) -> None:
        """Test rate limit validation with negative values."""
        with pytest.raises(ValidationError) as exc_info:
            RateLimit(requests_per_minute=-1, requests_per_hour=3600, requests_per_day=86400)

        assert "Rate limit must be positive" in str(exc_info.value)

    def test_burst_limit_validation_invalid(self) -> None:
        """Test burst limit validation with invalid values."""
        invalid_burst_limits = [0, -1, 1001]

        for burst_limit in invalid_burst_limits:
            with pytest.raises(ValidationError) as exc_info:
                RateLimit(
                    requests_per_minute=60,
                    requests_per_hour=3600,
                    requests_per_day=86400,
                    burst_limit=burst_limit,
                )

            assert "Burst limit must be between 1 and 1000" in str(exc_info.value)


class TestTimeRestriction:
    """Unit tests for TimeRestriction value object."""

    def test_create_valid_time_restriction(self, test_time_range: TimeRange) -> None:
        """Test creating a valid time restriction."""
        restriction = TimeRestriction(
            allowed_time_ranges=[test_time_range],
            allowed_days_of_week={0, 1, 2, 3, 4},
            timezone="UTC",
        )

        assert len(restriction.allowed_time_ranges) == 1
        assert restriction.allowed_days_of_week == {0, 1, 2, 3, 4}
        assert restriction.timezone == "UTC"
        assert restriction.enabled is True

    def test_days_of_week_validation_empty(self, test_time_range: TimeRange) -> None:
        """Test days of week validation with empty set."""
        with pytest.raises(ValidationError) as exc_info:
            TimeRestriction(
                allowed_time_ranges=[test_time_range],
                allowed_days_of_week=set(),
                timezone="UTC",
            )

        assert "At least one day of week must be allowed" in str(exc_info.value)

    def test_days_of_week_validation_invalid(self, test_time_range: TimeRange) -> None:
        """Test days of week validation with invalid values."""
        with pytest.raises(ValidationError) as exc_info:
            TimeRestriction(
                allowed_time_ranges=[test_time_range],
                allowed_days_of_week={0, 1, 7, 8},  # 7 and 8 are invalid
                timezone="UTC",
            )

        assert "Invalid days of week" in str(exc_info.value)

    def test_time_ranges_validation_empty(self) -> None:
        """Test time ranges validation with empty list."""
        with pytest.raises(ValidationError) as exc_info:
            TimeRestriction(
                allowed_time_ranges=[],
                allowed_days_of_week={0, 1, 2, 3, 4},
                timezone="UTC",
            )

        assert "At least one time range must be specified" in str(exc_info.value)

    def test_time_ranges_validation_too_many(self, test_time_range: TimeRange) -> None:
        """Test time ranges validation with too many ranges."""
        # Create 11 time ranges (exceeds maximum of 10)
        too_many_ranges = [test_time_range] * 11

        with pytest.raises(ValidationError) as exc_info:
            TimeRestriction(
                allowed_time_ranges=too_many_ranges,
                allowed_days_of_week={0, 1, 2, 3, 4},
                timezone="UTC",
            )

        assert "Too many time ranges" in str(exc_info.value)


class TestPolicy:
    """Unit tests for Policy entity."""

    def test_create_valid_policy(self, test_tenant_id: UUID, test_user_id: UUID) -> None:
        """Test creating a valid policy."""
        policy = Policy(
            tenant_id=test_tenant_id,
            name="Test Policy",
            description="Test policy description",
            created_by=test_user_id,
            priority=500,
        )

        assert policy.tenant_id == test_tenant_id
        assert policy.name == "Test Policy"
        assert policy.description == "Test policy description"
        assert policy.created_by == test_user_id
        assert policy.priority == 500
        assert policy.status == PolicyStatus.DRAFT
        assert policy.version == 1

    def test_policy_name_validation_empty(self, test_tenant_id: UUID, test_user_id: UUID) -> None:
        """Test policy name validation with empty name."""
        with pytest.raises(ValidationError) as exc_info:
            Policy(
                tenant_id=test_tenant_id,
                name="",
                description="Test",
                created_by=test_user_id,
            )

        assert "Policy name cannot be empty" in str(exc_info.value)

    def test_policy_name_validation_too_short(
        self, test_tenant_id: UUID, test_user_id: UUID
    ) -> None:
        """Test policy name validation with too short name."""
        with pytest.raises(ValidationError) as exc_info:
            Policy(
                tenant_id=test_tenant_id,
                name="ab",
                description="Test",
                created_by=test_user_id,
            )

        assert "Policy name too short" in str(exc_info.value)

    def test_policy_name_validation_too_long(
        self, test_tenant_id: UUID, test_user_id: UUID
    ) -> None:
        """Test policy name validation with too long name."""
        with pytest.raises(ValidationError) as exc_info:
            Policy(
                tenant_id=test_tenant_id,
                name="a" * 101,  # 101 characters - exceeds 100 limit
                description="Test",
                created_by=test_user_id,
            )

        assert "Policy name too long" in str(exc_info.value)

    def test_policy_priority_validation_invalid(
        self, test_tenant_id: UUID, test_user_id: UUID
    ) -> None:
        """Test policy priority validation with invalid values."""
        invalid_priorities = [0, -1, 1001]

        for priority in invalid_priorities:
            with pytest.raises(ValidationError) as exc_info:
                Policy(
                    tenant_id=test_tenant_id,
                    name="Test Policy",
                    description="Test",
                    created_by=test_user_id,
                    priority=priority,
                )

            assert "Policy priority must be between 1 and 1000" in str(exc_info.value)

    def test_policy_add_rule(self, test_policy: Policy, test_rule_condition: RuleCondition) -> None:
        """Test adding rule to policy."""
        initial_version = test_policy.version

        # Create a new rule with different name to avoid duplicate
        new_rule = PolicyRule(
            name="Additional Test Rule",
            description="Another test rule",
            conditions=[test_rule_condition],
            action=RuleAction.DENY,
            priority=200,
        )
        test_policy.add_rule(new_rule)

        assert len(test_policy.rules) == 2  # Already has one rule from fixture
        assert test_policy.version == initial_version + 1

    def test_policy_add_duplicate_rule_name(
        self, test_policy: Policy, test_rule_condition: RuleCondition
    ) -> None:
        """Test adding rule with duplicate name."""
        existing_rule_name = test_policy.rules[0].name

        duplicate_rule = PolicyRule(
            name=existing_rule_name,
            description="Duplicate",
            conditions=[test_rule_condition],
            action=RuleAction.DENY,
        )

        with pytest.raises(ValidationError) as exc_info:
            test_policy.add_rule(duplicate_rule)

        assert "already exists" in str(exc_info.value)

    def test_policy_remove_rule(self, test_policy: Policy) -> None:
        """Test removing rule from policy."""
        rule_id = test_policy.rules[0].rule_id
        initial_version = test_policy.version

        result = test_policy.remove_rule(rule_id)

        assert result is True
        assert len(test_policy.rules) == 0
        assert test_policy.version == initial_version + 1

    def test_policy_remove_nonexistent_rule(self, test_policy: Policy) -> None:
        """Test removing non-existent rule."""
        nonexistent_id = uuid4()
        result = test_policy.remove_rule(nonexistent_id)

        assert result is False

    def test_policy_activate(self, test_policy: Policy) -> None:
        """Test activating policy."""
        test_policy.activate()

        assert test_policy.status == PolicyStatus.ACTIVE

    def test_policy_activate_without_content(
        self, test_tenant_id: UUID, test_user_id: UUID
    ) -> None:
        """Test activating policy without rules or domains."""
        empty_policy = Policy(
            tenant_id=test_tenant_id,
            name="Empty Policy",
            description="Empty",
            created_by=test_user_id,
        )

        with pytest.raises(ValidationError) as exc_info:
            empty_policy.activate()

        assert "without rules or domain restrictions" in str(exc_info.value)

    def test_policy_suspend(self, test_policy: Policy) -> None:
        """Test suspending policy."""
        test_policy.activate()
        test_policy.suspend()

        assert test_policy.status == PolicyStatus.SUSPENDED

    def test_policy_archive(self, test_policy: Policy) -> None:
        """Test archiving policy."""
        test_policy.archive()

        assert test_policy.status == PolicyStatus.ARCHIVED

    def test_policy_add_allowed_domain(self, test_policy: Policy) -> None:
        """Test adding allowed domain."""
        test_policy.add_allowed_domain("example.com")

        assert "example.com" in test_policy.allowed_domains

    def test_policy_add_blocked_domain(self, test_policy: Policy) -> None:
        """Test adding blocked domain."""
        test_policy.add_blocked_domain("malicious.com")

        assert "malicious.com" in test_policy.blocked_domains

    def test_policy_domain_conflict(self, test_policy: Policy) -> None:
        """Test domain conflict between allowed and blocked."""
        test_policy.add_allowed_domain("example.com")

        with pytest.raises(ValidationError) as exc_info:
            test_policy.add_blocked_domain("example.com")

        assert "already in allowed list" in str(exc_info.value)

    def test_policy_remove_blocked_domain(self, test_policy: Policy) -> None:
        """Test removing domain from blocked domains."""
        test_policy.add_blocked_domain("malicious.com")
        assert "malicious.com" in test_policy.blocked_domains

        test_policy.remove_domain("malicious.com")
        assert "malicious.com" not in test_policy.blocked_domains

    def test_policy_with_initial_domains(self, test_tenant_id: UUID, test_user_id: UUID) -> None:
        """Test policy creation with domains in constructor."""
        policy = Policy(
            tenant_id=test_tenant_id,
            name="test-policy",
            description="Test",
            created_by=test_user_id,
            allowed_domains={"example.com", "test.example.com"},
            blocked_domains={"malicious.com"},
        )

        assert "example.com" in policy.allowed_domains
        assert "test.example.com" in policy.allowed_domains
        assert "malicious.com" in policy.blocked_domains

    def test_policy_set_time_restrictions(
        self, test_policy: Policy, test_time_restriction: TimeRestriction
    ) -> None:
        """Test setting time restrictions."""
        test_policy.set_time_restrictions(test_time_restriction)

        assert test_policy.time_restrictions == test_time_restriction

    def test_policy_set_rate_limits(self, test_policy: Policy, test_rate_limit: RateLimit) -> None:
        """Test setting rate limits."""
        test_policy.set_rate_limits(test_rate_limit)

        assert test_policy.rate_limits == test_rate_limit


class TestPolicyService:
    """Unit tests for PolicyService."""

    @pytest.fixture
    def mock_policy_repository(self) -> AsyncMock:
        """Mock policy repository."""
        return AsyncMock()

    @pytest.fixture
    def mock_agent_repository(self) -> AsyncMock:
        """Mock agent repository."""
        return AsyncMock()

    @pytest.fixture
    def policy_service(
        self, mock_policy_repository: AsyncMock, mock_agent_repository: AsyncMock
    ) -> PolicyService:
        """Policy service with mock repositories."""
        return PolicyService(mock_policy_repository, mock_agent_repository)

    async def test_create_policy_success(
        self,
        policy_service: PolicyService,
        mock_policy_repository: AsyncMock,
        test_tenant_id: UUID,
        test_user_id: UUID,
    ) -> None:
        """Test successful policy creation."""
        # Setup mocks
        mock_policy_repository.exists_by_name.return_value = False
        mock_policy_repository.count_by_tenant.return_value = 10
        mock_policy_repository.find_duplicate_priority.return_value = []
        mock_policy_repository.save.return_value = None

        # Create policy
        policy = await policy_service.create_policy(
            tenant_id=test_tenant_id,
            name="Test Policy",
            description="Test description",
            created_by=test_user_id,
            priority=500,
        )

        # Verify policy properties
        assert policy.tenant_id == test_tenant_id
        assert policy.name == "Test Policy"
        assert policy.description == "Test description"
        assert policy.created_by == test_user_id
        assert policy.priority == 500
        assert policy.status == PolicyStatus.DRAFT

        # Verify repository calls
        mock_policy_repository.exists_by_name.assert_called_once()
        mock_policy_repository.save.assert_called_once()

    async def test_create_policy_duplicate_name(
        self,
        policy_service: PolicyService,
        mock_policy_repository: AsyncMock,
        test_tenant_id: UUID,
        test_user_id: UUID,
    ) -> None:
        """Test policy creation with duplicate name."""
        mock_policy_repository.exists_by_name.return_value = True

        with pytest.raises(DuplicateEntityError):
            await policy_service.create_policy(
                tenant_id=test_tenant_id,
                name="Test Policy",
                description="Test",
                created_by=test_user_id,
            )

    async def test_create_policy_limit_exceeded(
        self,
        policy_service: PolicyService,
        mock_policy_repository: AsyncMock,
        test_tenant_id: UUID,
        test_user_id: UUID,
    ) -> None:
        """Test policy creation when limit is exceeded."""
        mock_policy_repository.exists_by_name.return_value = False
        mock_policy_repository.count_by_tenant.return_value = 500  # At limit

        with pytest.raises(BusinessRuleViolationError) as exc_info:
            await policy_service.create_policy(
                tenant_id=test_tenant_id,
                name="Test Policy",
                description="Test",
                created_by=test_user_id,
            )

        assert "maximum policy limit" in str(exc_info.value)

    async def test_activate_policy_success(
        self,
        policy_service: PolicyService,
        mock_policy_repository: AsyncMock,
        test_policy: Policy,
    ) -> None:
        """Test successful policy activation."""
        mock_policy_repository.find_by_id.return_value = test_policy
        mock_policy_repository.save.return_value = None

        activated_policy = await policy_service.activate_policy(test_policy.policy_id)

        assert activated_policy.status == PolicyStatus.ACTIVE

    async def test_evaluate_access_request(
        self,
        policy_service: PolicyService,
        mock_policy_repository: AsyncMock,
        test_tenant_id: UUID,
    ) -> None:
        """Test access request evaluation."""
        # Import AccessRequest from the service module where it's defined
        from domain.policy.service import AccessRequest

        # Create access request
        request = AccessRequest(
            tenant_id=test_tenant_id,
            agent_id=uuid4(),
            domain="example.com",
        )

        # Mock empty policies (should deny by default)
        mock_policy_repository.find_policies_for_evaluation.return_value = []

        result = await policy_service.evaluate_access_request(request)

        assert isinstance(result, PolicyEvaluationResult)
        assert result.allowed is False
        assert "No policies found" in result.reason


class TestPolicyValidator:
    """Unit tests for PolicyValidator."""

    @pytest.fixture
    def validator(self) -> PolicyValidator:
        """Policy validator instance."""
        return PolicyValidator()

    def test_validate_policy_for_activation_success(
        self, validator: PolicyValidator, test_policy: Policy
    ) -> None:
        """Test successful policy validation for activation."""
        # Should not raise any exceptions
        validator.validate_policy_for_activation(test_policy)

    def test_validate_policy_for_activation_empty(
        self, validator: PolicyValidator, test_tenant_id: UUID, test_user_id: UUID
    ) -> None:
        """Test policy validation with empty policy."""
        empty_policy = Policy(
            tenant_id=test_tenant_id,
            name="Empty Policy",
            description="Empty",
            created_by=test_user_id,
        )

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_policy_for_activation(empty_policy)

        assert "at least one rule" in str(exc_info.value)

    def test_validate_domain_list_consistency_success(self, validator: PolicyValidator) -> None:
        """Test successful domain list consistency validation."""
        allowed = {"example.com", "test.com"}
        blocked = {"malicious.com", "evil.com"}

        # Should not raise any exceptions
        validator.validate_domain_list_consistency(allowed, blocked)

    def test_validate_domain_list_consistency_overlap(self, validator: PolicyValidator) -> None:
        """Test domain list consistency with overlap."""
        allowed = {"example.com", "test.com"}
        blocked = {"example.com", "evil.com"}  # Overlap

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_domain_list_consistency(allowed, blocked)

        assert "cannot be both allowed and blocked" in str(exc_info.value)

    def test_validate_rate_limit_consistency_success(
        self, validator: PolicyValidator, test_rate_limit: RateLimit
    ) -> None:
        """Test successful rate limit validation."""
        # Should not raise any exceptions
        validator.validate_rate_limit_consistency(test_rate_limit)

    def test_validate_rate_limit_consistency_failure(self, validator: PolicyValidator) -> None:
        """Test rate limit validation with inconsistent limits."""
        inconsistent_rate_limit = RateLimit(
            requests_per_minute=100,  # 100 per minute
            requests_per_hour=1000,  # Would be 6000 per hour at minute rate
            requests_per_day=86400,
        )

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_rate_limit_consistency(inconsistent_rate_limit)

        assert "Hourly rate limit must be >=" in str(exc_info.value)
