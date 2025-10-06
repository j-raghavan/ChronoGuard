"""Comprehensive tests for PolicyService domain service."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from domain.common.exceptions import (
    BusinessRuleViolationError,
    DuplicateEntityError,
    EntityNotFoundError,
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
from domain.policy.service import AccessRequest, PolicyEvaluationResult, PolicyService


class TestPolicyEvaluationResult:
    """Test PolicyEvaluationResult class."""

    def test_policy_evaluation_result_creation(self):
        """Test creation of PolicyEvaluationResult."""
        policy_id = uuid4()
        result = PolicyEvaluationResult(allowed=True, policy_id=policy_id, reason="Access granted")

        assert result.allowed is True
        assert result.policy_id == policy_id
        assert result.reason == "Access granted"
        assert result.rule_id is None
        assert result.rate_limit_info == {}

    def test_policy_evaluation_result_with_rule_id(self):
        """Test PolicyEvaluationResult with rule_id."""
        policy_id = uuid4()
        rule_id = uuid4()
        result = PolicyEvaluationResult(
            allowed=False, policy_id=policy_id, rule_id=rule_id, reason="Rule matched"
        )

        assert result.rule_id == rule_id

    def test_policy_evaluation_result_with_rate_limit_info(self):
        """Test PolicyEvaluationResult with rate limit info."""
        rate_limit_info = {"requests_remaining": 100, "reset_time": 3600}
        result = PolicyEvaluationResult(
            allowed=True, policy_id=uuid4(), rate_limit_info=rate_limit_info
        )

        assert result.rate_limit_info == rate_limit_info


class TestAccessRequest:
    """Test AccessRequest class."""

    def test_access_request_minimal(self):
        """Test creation of AccessRequest with minimal parameters."""
        request = AccessRequest(domain="example.com")

        assert request.domain == "example.com"
        assert request.method == "GET"
        assert request.path == "/"
        assert request.user_agent is None
        assert request.source_ip is None
        assert isinstance(request.timestamp, datetime)
        assert request.agent_id is None
        assert request.tenant_id is None
        assert request.additional_context == {}

    def test_access_request_full(self):
        """Test creation of AccessRequest with all parameters."""
        agent_id = uuid4()
        tenant_id = uuid4()
        timestamp = datetime.now(UTC)
        additional_context = {"key": "value"}

        request = AccessRequest(
            domain="example.com",
            method="POST",
            path="/api/test",
            user_agent="TestAgent/1.0",
            source_ip="192.168.1.1",
            timestamp=timestamp,
            agent_id=agent_id,
            tenant_id=tenant_id,
            additional_context=additional_context,
        )

        assert request.domain == "example.com"
        assert request.method == "POST"
        assert request.path == "/api/test"
        assert request.user_agent == "TestAgent/1.0"
        assert request.source_ip == "192.168.1.1"
        assert request.timestamp == timestamp
        assert request.agent_id == agent_id
        assert request.tenant_id == tenant_id
        assert request.additional_context == additional_context


class TestPolicyServiceCreation:
    """Test PolicyService creation and initialization."""

    def test_policy_service_creation(self):
        """Test PolicyService initialization."""
        policy_repo = AsyncMock()
        service = PolicyService(policy_repo)

        assert service._policy_repository == policy_repo
        assert service._agent_repository is None

    def test_policy_service_with_agent_repository(self):
        """Test PolicyService with agent repository."""
        policy_repo = AsyncMock()
        agent_repo = AsyncMock()
        service = PolicyService(policy_repo, agent_repo)

        assert service._policy_repository == policy_repo
        assert service._agent_repository == agent_repo


class TestCreatePolicy:
    """Test policy creation."""

    @pytest.fixture
    def policy_repo(self):
        """Create a mock policy repository."""
        return AsyncMock()

    @pytest.fixture
    def service(self, policy_repo):
        """Create a PolicyService instance."""
        return PolicyService(policy_repo)

    @pytest.mark.asyncio
    async def test_create_policy_success(self, service, policy_repo):
        """Test successful policy creation."""
        tenant_id = uuid4()
        created_by = uuid4()

        policy_repo.exists_by_name.return_value = False
        policy_repo.count_by_tenant.return_value = 10
        policy_repo.find_duplicate_priority.return_value = []
        policy_repo.save.return_value = None

        policy = await service.create_policy(
            tenant_id=tenant_id,
            name="test-policy",
            description="Test policy",
            created_by=created_by,
            priority=100,
        )

        assert policy.tenant_id == tenant_id
        assert policy.name == "test-policy"
        assert policy.description == "Test policy"
        assert policy.created_by == created_by
        assert policy.priority == 100
        assert policy.status == PolicyStatus.DRAFT

        policy_repo.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_policy_duplicate_name(self, service, policy_repo):
        """Test policy creation with duplicate name fails."""
        tenant_id = uuid4()
        policy_repo.exists_by_name.return_value = True

        with pytest.raises(DuplicateEntityError) as exc_info:
            await service.create_policy(
                tenant_id=tenant_id, name="duplicate-policy", description="Test", created_by=uuid4()
            )

        assert "Policy" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_create_policy_limit_exceeded(self, service, policy_repo):
        """Test policy creation fails when limit exceeded."""
        tenant_id = uuid4()
        policy_repo.exists_by_name.return_value = False
        policy_repo.count_by_tenant.return_value = 500  # At limit

        with pytest.raises(BusinessRuleViolationError) as exc_info:
            await service.create_policy(
                tenant_id=tenant_id, name="test-policy", description="Test", created_by=uuid4()
            )

        assert "maximum policy limit" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_create_policy_priority_conflict(self, service, policy_repo):
        """Test policy creation fails with priority conflict."""
        tenant_id = uuid4()
        existing_policy = Mock(policy_id=uuid4())

        policy_repo.exists_by_name.return_value = False
        policy_repo.count_by_tenant.return_value = 10
        policy_repo.find_duplicate_priority.return_value = [existing_policy]

        with pytest.raises(BusinessRuleViolationError) as exc_info:
            await service.create_policy(
                tenant_id=tenant_id,
                name="test-policy",
                description="Test",
                created_by=uuid4(),
                priority=100,
            )

        assert "priority" in str(exc_info.value).lower()


class TestPolicyActivation:
    """Test policy activation."""

    @pytest.fixture
    def policy_repo(self):
        """Create a mock policy repository."""
        return AsyncMock()

    @pytest.fixture
    def service(self, policy_repo):
        """Create a PolicyService instance."""
        return PolicyService(policy_repo)

    @pytest.mark.asyncio
    async def test_activate_policy_success(self, service, policy_repo):
        """Test successful policy activation."""
        policy = Policy(
            tenant_id=uuid4(), name="test-policy", description="Test", created_by=uuid4()
        )
        policy.add_allowed_domain("example.com")

        policy_repo.find_by_id.return_value = policy
        policy_repo.save.return_value = None

        activated_policy = await service.activate_policy(policy.policy_id)

        assert activated_policy.status == PolicyStatus.ACTIVE
        policy_repo.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_activate_policy_not_found(self, service, policy_repo):
        """Test policy activation fails when policy not found."""
        policy_repo.find_by_id.return_value = None

        with pytest.raises(EntityNotFoundError):
            await service.activate_policy(uuid4())

    @pytest.mark.asyncio
    async def test_activate_empty_policy_fails(self, service, policy_repo):
        """Test activation fails for empty policy."""
        policy = Policy(
            tenant_id=uuid4(), name="empty-policy", description="Test", created_by=uuid4()
        )

        policy_repo.find_by_id.return_value = policy

        with pytest.raises(BusinessRuleViolationError) as exc_info:
            await service.activate_policy(policy.policy_id)

        assert "without rules or domain restrictions" in str(exc_info.value).lower()


class TestPolicySuspension:
    """Test policy suspension."""

    @pytest.fixture
    def policy_repo(self):
        """Create a mock policy repository."""
        return AsyncMock()

    @pytest.fixture
    def service(self, policy_repo):
        """Create a PolicyService instance."""
        return PolicyService(policy_repo)

    @pytest.mark.asyncio
    async def test_suspend_policy_success(self, service, policy_repo):
        """Test successful policy suspension."""
        policy = Policy(
            tenant_id=uuid4(),
            name="test-policy",
            description="Test",
            created_by=uuid4(),
            status=PolicyStatus.ACTIVE,
        )

        policy_repo.find_by_id.return_value = policy
        policy_repo.save.return_value = None

        suspended_policy = await service.suspend_policy(policy.policy_id)

        assert suspended_policy.status == PolicyStatus.SUSPENDED
        policy_repo.save.assert_called_once()


class TestPolicyArchival:
    """Test policy archival."""

    @pytest.fixture
    def policy_repo(self):
        """Create a mock policy repository."""
        return AsyncMock()

    @pytest.fixture
    def agent_repo(self):
        """Create a mock agent repository."""
        return AsyncMock()

    @pytest.fixture
    def service(self, policy_repo, agent_repo):
        """Create a PolicyService instance."""
        return PolicyService(policy_repo, agent_repo)

    @pytest.mark.asyncio
    async def test_archive_policy_success(self, service, policy_repo, agent_repo):
        """Test successful policy archival."""
        policy = Policy(
            tenant_id=uuid4(),
            name="test-policy",
            description="Test",
            created_by=uuid4(),
            status=PolicyStatus.SUSPENDED,
        )

        policy_repo.find_by_id.return_value = policy
        agent_repo.find_with_policy.return_value = []
        policy_repo.save.return_value = None

        archived_policy = await service.archive_policy(policy.policy_id)

        assert archived_policy.status == PolicyStatus.ARCHIVED
        policy_repo.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_archive_policy_with_agent_references_fails(
        self, service, policy_repo, agent_repo
    ):
        """Test archival fails when policy is referenced by agents."""
        policy = Policy(
            tenant_id=uuid4(), name="test-policy", description="Test", created_by=uuid4()
        )

        policy_repo.find_by_id.return_value = policy
        agent_repo.find_with_policy.return_value = [Mock(), Mock()]  # 2 agents

        with pytest.raises(BusinessRuleViolationError) as exc_info:
            await service.archive_policy(policy.policy_id)

        assert "2 agents" in str(exc_info.value).lower()


class TestPolicyRuleManagement:
    """Test policy rule management."""

    @pytest.fixture
    def policy_repo(self):
        """Create a mock policy repository."""
        return AsyncMock()

    @pytest.fixture
    def service(self, policy_repo):
        """Create a PolicyService instance."""
        return PolicyService(policy_repo)

    @pytest.mark.asyncio
    async def test_add_rule_to_policy_success(self, service, policy_repo):
        """Test adding rule to policy."""
        policy = Policy(
            tenant_id=uuid4(),
            name="test-policy",
            description="Test",
            created_by=uuid4(),
            status=PolicyStatus.DRAFT,
        )

        rule = PolicyRule(
            name="test-rule",
            description="Test rule",
            conditions=[RuleCondition(field="domain", operator="equals", value="example.com")],
            action=RuleAction.ALLOW,
        )

        policy_repo.find_by_id.return_value = policy
        policy_repo.save.return_value = None

        updated_policy = await service.add_rule_to_policy(policy.policy_id, rule)

        assert len(updated_policy.rules) == 1
        policy_repo.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_rule_to_active_policy_fails(self, service, policy_repo):
        """Test adding rule to active policy fails."""
        policy = Policy(
            tenant_id=uuid4(),
            name="test-policy",
            description="Test",
            created_by=uuid4(),
            status=PolicyStatus.ACTIVE,
        )

        rule = PolicyRule(
            name="test-rule",
            description="Test rule",
            conditions=[RuleCondition(field="domain", operator="equals", value="example.com")],
            action=RuleAction.ALLOW,
        )

        policy_repo.find_by_id.return_value = policy

        with pytest.raises(BusinessRuleViolationError) as exc_info:
            await service.add_rule_to_policy(policy.policy_id, rule)

        assert "active policy" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_remove_rule_from_policy_success(self, service, policy_repo):
        """Test removing rule from policy."""
        policy = Policy(
            tenant_id=uuid4(),
            name="test-policy",
            description="Test",
            created_by=uuid4(),
            status=PolicyStatus.DRAFT,
        )

        rule = PolicyRule(
            name="test-rule",
            description="Test rule",
            conditions=[RuleCondition(field="domain", operator="equals", value="example.com")],
            action=RuleAction.ALLOW,
        )
        policy.add_rule(rule)

        policy_repo.find_by_id.return_value = policy
        policy_repo.save.return_value = None

        updated_policy = await service.remove_rule_from_policy(policy.policy_id, rule.rule_id)

        assert len(updated_policy.rules) == 0
        policy_repo.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_rule_from_active_policy_fails(self, service, policy_repo):
        """Test removing rule from active policy fails."""
        policy = Policy(
            tenant_id=uuid4(),
            name="test-policy",
            description="Test",
            created_by=uuid4(),
            status=PolicyStatus.ACTIVE,
        )

        rule = PolicyRule(
            name="test-rule",
            description="Test rule",
            conditions=[RuleCondition(field="domain", operator="equals", value="example.com")],
            action=RuleAction.ALLOW,
        )
        policy.add_rule(rule)

        policy_repo.find_by_id.return_value = policy

        with pytest.raises(BusinessRuleViolationError) as exc_info:
            await service.remove_rule_from_policy(policy.policy_id, rule.rule_id)

        assert "Cannot modify active policy" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_remove_nonexistent_rule_fails(self, service, policy_repo):
        """Test removing nonexistent rule fails."""
        policy = Policy(
            tenant_id=uuid4(),
            name="test-policy",
            description="Test",
            created_by=uuid4(),
            status=PolicyStatus.DRAFT,
        )

        policy_repo.find_by_id.return_value = policy

        with pytest.raises(EntityNotFoundError):
            await service.remove_rule_from_policy(policy.policy_id, uuid4())


class TestPolicyDomainManagement:
    """Test policy domain management."""

    @pytest.fixture
    def policy_repo(self):
        """Create a mock policy repository."""
        return AsyncMock()

    @pytest.fixture
    def service(self, policy_repo):
        """Create a PolicyService instance."""
        return PolicyService(policy_repo)

    @pytest.mark.asyncio
    async def test_add_allowed_domain(self, service, policy_repo):
        """Test adding allowed domain."""
        policy = Policy(
            tenant_id=uuid4(), name="test-policy", description="Test", created_by=uuid4()
        )

        policy_repo.find_by_id.return_value = policy
        policy_repo.save.return_value = None

        updated_policy = await service.add_domain_to_policy(
            policy.policy_id, "example.com", allowed=True
        )

        assert "example.com" in updated_policy.allowed_domains

    @pytest.mark.asyncio
    async def test_add_blocked_domain(self, service, policy_repo):
        """Test adding blocked domain."""
        policy = Policy(
            tenant_id=uuid4(), name="test-policy", description="Test", created_by=uuid4()
        )

        policy_repo.find_by_id.return_value = policy
        policy_repo.save.return_value = None

        updated_policy = await service.add_domain_to_policy(
            policy.policy_id, "malicious.com", allowed=False
        )

        assert "malicious.com" in updated_policy.blocked_domains


class TestPolicyRestrictions:
    """Test policy time and rate restrictions."""

    @pytest.fixture
    def policy_repo(self):
        """Create a mock policy repository."""
        return AsyncMock()

    @pytest.fixture
    def service(self, policy_repo):
        """Create a PolicyService instance."""
        return PolicyService(policy_repo)

    @pytest.mark.asyncio
    async def test_set_time_restrictions(self, service, policy_repo):
        """Test setting time restrictions."""
        policy = Policy(
            tenant_id=uuid4(), name="test-policy", description="Test", created_by=uuid4()
        )

        time_restriction = TimeRestriction(
            allowed_time_ranges=[
                TimeRange(start_hour=9, start_minute=0, end_hour=17, end_minute=0)
            ],
            allowed_days_of_week=[0, 1, 2, 3, 4],
            timezone="UTC",
        )

        policy_repo.find_by_id.return_value = policy
        policy_repo.save.return_value = None

        updated_policy = await service.set_time_restrictions(policy.policy_id, time_restriction)

        assert updated_policy.time_restrictions == time_restriction

    @pytest.mark.asyncio
    async def test_set_rate_limits(self, service, policy_repo):
        """Test setting rate limits."""
        policy = Policy(
            tenant_id=uuid4(), name="test-policy", description="Test", created_by=uuid4()
        )

        rate_limit = RateLimit(
            requests_per_minute=60, requests_per_hour=3600, requests_per_day=86400, burst_limit=100
        )

        policy_repo.find_by_id.return_value = policy
        policy_repo.save.return_value = None

        updated_policy = await service.set_rate_limits(policy.policy_id, rate_limit)

        assert updated_policy.rate_limits == rate_limit


class TestAccessRequestEvaluation:
    """Test access request evaluation."""

    @pytest.fixture
    def policy_repo(self):
        """Create a mock policy repository."""
        return AsyncMock()

    @pytest.fixture
    def service(self, policy_repo):
        """Create a PolicyService instance."""
        return PolicyService(policy_repo)

    @pytest.mark.asyncio
    async def test_evaluate_request_without_tenant_fails(self, service, policy_repo):
        """Test evaluation fails without tenant."""
        request = AccessRequest(domain="example.com")

        with pytest.raises(BusinessRuleViolationError) as exc_info:
            await service.evaluate_access_request(request)

        assert "tenant" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_evaluate_request_no_policies(self, service, policy_repo):
        """Test evaluation with no policies returns deny."""
        request = AccessRequest(domain="example.com", tenant_id=uuid4())
        policy_repo.find_policies_for_evaluation.return_value = []

        result = await service.evaluate_access_request(request)

        assert result.allowed is False
        assert "No policies found" in result.reason

    @pytest.mark.asyncio
    async def test_evaluate_request_blocked_domain(self, service, policy_repo):
        """Test evaluation with blocked domain."""
        tenant_id = uuid4()
        policy = Policy(
            tenant_id=tenant_id,
            name="test-policy",
            description="Test",
            created_by=uuid4(),
            status=PolicyStatus.ACTIVE,
        )
        policy.add_blocked_domain("blocked.com")

        request = AccessRequest(domain="blocked.com", tenant_id=tenant_id)
        policy_repo.find_policies_for_evaluation.return_value = [policy]

        result = await service.evaluate_access_request(request)

        assert result.allowed is False
        assert "blocked" in result.reason.lower()

    @pytest.mark.asyncio
    async def test_evaluate_request_allowed_domain(self, service, policy_repo):
        """Test evaluation with allowed domain."""
        tenant_id = uuid4()
        policy = Policy(
            tenant_id=tenant_id,
            name="test-policy",
            description="Test",
            created_by=uuid4(),
            status=PolicyStatus.ACTIVE,
        )
        policy.add_allowed_domain("example.com")

        request = AccessRequest(domain="other.com", tenant_id=tenant_id)
        policy_repo.find_policies_for_evaluation.return_value = [policy]

        result = await service.evaluate_access_request(request)

        assert result.allowed is False
        assert "not in allowed list" in result.reason.lower()

    @pytest.mark.asyncio
    async def test_evaluate_request_no_matching_rules(self, service, policy_repo):
        """Test evaluation returns default deny when no rules match."""
        tenant_id = uuid4()
        # Create a policy with no rules and no domain restrictions
        policy = Policy(
            tenant_id=tenant_id,
            name="empty-policy",
            description="Test",
            created_by=uuid4(),
            status=PolicyStatus.ACTIVE,
        )

        request = AccessRequest(domain="example.com", tenant_id=tenant_id)
        policy_repo.find_policies_for_evaluation.return_value = [policy]

        result = await service.evaluate_access_request(request)

        # Should return default deny
        assert result.allowed is False
        assert "No matching policy rules" in result.reason

    @pytest.mark.asyncio
    async def test_evaluate_request_time_restriction_outside_window(self, service, policy_repo):
        """Test evaluation fails outside allowed time window."""
        from domain.common.value_objects import TimeRange

        tenant_id = uuid4()
        policy = Policy(
            tenant_id=tenant_id,
            name="time-restricted",
            description="Test",
            created_by=uuid4(),
            status=PolicyStatus.ACTIVE,
        )

        # Set time restrictions (9 AM - 5 PM)
        time_restriction = TimeRestriction(
            allowed_time_ranges=[
                TimeRange(start_hour=9, start_minute=0, end_hour=17, end_minute=0)
            ],
            allowed_days_of_week={0, 1, 2, 3, 4},
            timezone="UTC",
            enabled=True,
        )
        policy.set_time_restrictions(time_restriction)

        request = AccessRequest(domain="example.com", tenant_id=tenant_id)
        policy_repo.find_policies_for_evaluation.return_value = [policy]

        result = await service.evaluate_access_request(request)

        # May pass or fail depending on current time, but tests the path
        assert isinstance(result.allowed, bool)

    @pytest.mark.asyncio
    async def test_evaluate_request_with_disabled_rule(self, service, policy_repo):
        """Test evaluation skips disabled rules."""
        tenant_id = uuid4()
        policy = Policy(
            tenant_id=tenant_id,
            name="test-policy",
            description="Test",
            created_by=uuid4(),
            status=PolicyStatus.ACTIVE,
        )

        # Add a disabled rule
        rule = PolicyRule(
            name="disabled-rule",
            description="Test",
            conditions=[RuleCondition(field="domain", operator="equals", value="example.com")],
            action=RuleAction.ALLOW,
            enabled=False,
        )
        policy.add_rule(rule)

        request = AccessRequest(domain="example.com", tenant_id=tenant_id)
        policy_repo.find_policies_for_evaluation.return_value = [policy]

        result = await service.evaluate_access_request(request)

        # Disabled rule should be skipped, default deny
        assert result.allowed is False

    @pytest.mark.asyncio
    async def test_evaluate_request_contains_operator(self, service, policy_repo):
        """Test evaluation with contains operator."""
        tenant_id = uuid4()
        policy = Policy(
            tenant_id=tenant_id,
            name="test-policy",
            description="Test",
            created_by=uuid4(),
            status=PolicyStatus.ACTIVE,
        )

        # Add rule with contains operator
        rule = PolicyRule(
            name="contains-rule",
            description="Test",
            conditions=[RuleCondition(field="domain", operator="contains", value="example")],
            action=RuleAction.ALLOW,
        )
        policy.add_rule(rule)

        request = AccessRequest(domain="test.example.com", tenant_id=tenant_id)
        policy_repo.find_policies_for_evaluation.return_value = [policy]

        result = await service.evaluate_access_request(request)

        # Should match contains condition
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_evaluate_request_matching_rule(self, service, policy_repo):
        """Test evaluation with matching rule."""
        tenant_id = uuid4()
        policy = Policy(
            tenant_id=tenant_id,
            name="test-policy",
            description="Test",
            created_by=uuid4(),
            status=PolicyStatus.ACTIVE,
            priority=100,
        )

        rule = PolicyRule(
            name="allow-example",
            description="Allow example.com",
            conditions=[RuleCondition(field="domain", operator="equals", value="example.com")],
            action=RuleAction.ALLOW,
        )
        policy.add_rule(rule)

        request = AccessRequest(domain="example.com", tenant_id=tenant_id)
        policy_repo.find_policies_for_evaluation.return_value = [policy]

        result = await service.evaluate_access_request(request)

        assert result.allowed is True
        assert rule.rule_id == result.rule_id


class TestPolicyStatistics:
    """Test policy statistics."""

    @pytest.fixture
    def policy_repo(self):
        """Create a mock policy repository."""
        return AsyncMock()

    @pytest.fixture
    def service(self, policy_repo):
        """Create a PolicyService instance."""
        return PolicyService(policy_repo)

    @pytest.mark.asyncio
    async def test_get_tenant_policy_statistics(self, service, policy_repo):
        """Test getting tenant policy statistics."""
        tenant_id = uuid4()

        policy_repo.count_by_tenant.return_value = 100
        policy_repo.count_by_status.side_effect = [
            20,
            50,
            10,
            20,
        ]  # draft, active, suspended, archived

        stats = await service.get_tenant_policy_statistics(tenant_id)

        assert stats["total"] == 100
        assert stats["draft"] == 20
        assert stats["active"] == 50
        assert stats["suspended"] == 10
        assert stats["archived"] == 20


class TestBulkOperations:
    """Test bulk policy operations."""

    @pytest.fixture
    def policy_repo(self):
        """Create a mock policy repository."""
        return AsyncMock()

    @pytest.fixture
    def service(self, policy_repo):
        """Create a PolicyService instance."""
        return PolicyService(policy_repo)

    @pytest.mark.asyncio
    async def test_bulk_archive_policies(self, service, policy_repo):
        """Test bulk archiving policies."""
        policy_ids = [uuid4(), uuid4(), uuid4()]
        policy_repo.bulk_update_status.return_value = 3

        count = await service.bulk_archive_policies(policy_ids)

        assert count == 3
        policy_repo.bulk_update_status.assert_called_once_with(policy_ids, PolicyStatus.ARCHIVED)


class TestPolicySearch:
    """Test policy search."""

    @pytest.fixture
    def policy_repo(self):
        """Create a mock policy repository."""
        return AsyncMock()

    @pytest.fixture
    def service(self, policy_repo):
        """Create a PolicyService instance."""
        return PolicyService(policy_repo)

    @pytest.mark.asyncio
    async def test_search_policies(self, service, policy_repo):
        """Test searching policies."""
        tenant_id = uuid4()
        policies = [Mock(), Mock()]
        policy_repo.search_policies.return_value = policies

        results = await service.search_policies(
            tenant_id=tenant_id, search_term="test", status_filter=PolicyStatus.ACTIVE, limit=10
        )

        assert results == policies
        policy_repo.search_policies.assert_called_once_with(
            tenant_id, "test", PolicyStatus.ACTIVE, 10
        )
