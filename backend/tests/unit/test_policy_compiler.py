"""Unit tests for OPA Policy Compiler."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, create_autospec, patch
from uuid import uuid4

import aiohttp
import pytest

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
from domain.policy.exceptions import PolicyCompilationError
from infrastructure.opa.policy_compiler import PolicyCompiler


@pytest.fixture
def template_dir(tmp_path: Path) -> Path:
    """Create temporary template directory."""
    template_path = tmp_path / "templates"
    template_path.mkdir()

    # Create basic template
    template_file = template_path / "base_policy.rego.j2"
    template_file.write_text(
        """# Policy: {{ policy_name }}
package chronoguard.policies.{{ policy_name }}

policy_id := "{{ policy_id }}"
tenant_id := "{{ tenant_id }}"
allowed_domains := {{ allowed_domains | tojson }}
blocked_domains := {{ blocked_domains | tojson }}

default allow := false
allow {
    input.tenant_id == tenant_id
}
"""
    )

    return template_path


@pytest.fixture
def compiler(template_dir: Path) -> PolicyCompiler:
    """Create test policy compiler."""
    return PolicyCompiler(template_dir=template_dir, opa_url="http://localhost:8181")


@pytest.fixture
def sample_policy() -> Policy:
    """Create sample policy for testing."""
    return Policy(
        policy_id=uuid4(),
        tenant_id=uuid4(),
        name="Test Policy",
        description="Test policy description",
        created_by=uuid4(),
        status=PolicyStatus.ACTIVE,
        allowed_domains={"example.com", "test.com"},
        blocked_domains={"evil.com"},
    )


@pytest.fixture
def policy_with_rules() -> Policy:
    """Create policy with rules."""
    rule = PolicyRule(
        name="allow_get_requests",
        description="Allow GET requests",
        conditions=[
            RuleCondition(field="method", operator="equals", value="GET"),
            RuleCondition(field="domain", operator="contains", value="example"),
        ],
        action=RuleAction.ALLOW,
        priority=100,
    )

    return Policy(
        policy_id=uuid4(),
        tenant_id=uuid4(),
        name="Policy With Rules",
        description="Test policy with rules",
        created_by=uuid4(),
        status=PolicyStatus.ACTIVE,
        rules=[rule],
    )


@pytest.fixture
def policy_with_time_restrictions() -> Policy:
    """Create policy with time restrictions."""
    time_restriction = TimeRestriction(
        allowed_time_ranges=[TimeRange(start_hour=9, start_minute=0, end_hour=17, end_minute=0)],
        allowed_days_of_week={0, 1, 2, 3, 4},  # Monday-Friday
        timezone="UTC",
        enabled=True,
    )

    return Policy(
        policy_id=uuid4(),
        tenant_id=uuid4(),
        name="Time Restricted Policy",
        description="Policy with time restrictions",
        created_by=uuid4(),
        status=PolicyStatus.ACTIVE,
        time_restrictions=time_restriction,
    )


@pytest.fixture
def policy_with_rate_limits() -> Policy:
    """Create policy with rate limits."""
    rate_limit = RateLimit(
        requests_per_minute=60,
        requests_per_hour=1000,
        requests_per_day=10000,
        burst_limit=100,
        enabled=True,
    )

    return Policy(
        policy_id=uuid4(),
        tenant_id=uuid4(),
        name="Rate Limited Policy",
        description="Policy with rate limits",
        created_by=uuid4(),
        status=PolicyStatus.ACTIVE,
        rate_limits=rate_limit,
    )


class TestPolicyCompiler:
    """Test PolicyCompiler class."""

    def test_initialization(self, template_dir: Path) -> None:
        """Test compiler initialization."""
        compiler = PolicyCompiler(template_dir=template_dir, opa_url="http://localhost:8181")

        assert compiler.opa_url == "http://localhost:8181"
        assert compiler.session is None

    def test_initialization_nonexistent_template_dir(self) -> None:
        """Test initialization with non-existent template directory raises error."""
        with pytest.raises(ValueError, match="does not exist"):
            PolicyCompiler(template_dir=Path("/nonexistent"), opa_url="http://localhost:8181")

    @pytest.mark.asyncio
    async def test_compile_policy_basic(
        self, compiler: PolicyCompiler, sample_policy: Policy
    ) -> None:
        """Test basic policy compilation."""
        with patch.object(compiler, "_validate_rego", new_callable=AsyncMock):
            rego = await compiler.compile_policy(sample_policy)

            assert isinstance(rego, str)
            assert "Test Policy" in rego or "test_policy" in rego
            assert str(sample_policy.policy_id) in rego
            assert str(sample_policy.tenant_id) in rego

    @pytest.mark.asyncio
    async def test_compile_policy_with_domains(
        self, compiler: PolicyCompiler, sample_policy: Policy
    ) -> None:
        """Test policy compilation includes domains."""
        with patch.object(compiler, "_validate_rego", new_callable=AsyncMock):
            rego = await compiler.compile_policy(sample_policy)

            assert "example.com" in rego
            assert "test.com" in rego
            assert "evil.com" in rego

    @pytest.mark.asyncio
    async def test_compile_policy_validation_failure(
        self, compiler: PolicyCompiler, sample_policy: Policy
    ) -> None:
        """Test compilation fails if Rego validation fails."""
        with (
            patch.object(
                compiler,
                "_validate_rego",
                new_callable=AsyncMock,
                side_effect=PolicyCompilationError("Invalid Rego"),
            ),
            pytest.raises(PolicyCompilationError),
        ):
            await compiler.compile_policy(sample_policy)

    @pytest.mark.asyncio
    async def test_deploy_policy(self, compiler: PolicyCompiler, sample_policy: Policy) -> None:
        """Test deploying policy to OPA."""
        mock_response = AsyncMock()
        mock_response.status = 200

        with patch.object(compiler, "compile_policy", new_callable=AsyncMock) as mock_compile:
            mock_compile.return_value = "compiled rego"

            mock_session = MagicMock()
            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)
            mock_session.put = MagicMock(return_value=mock_cm)

            compiler.session = mock_session

            await compiler.deploy_policy(sample_policy)

            mock_compile.assert_awaited_once_with(sample_policy)
            mock_session.put.assert_called_once()

    @pytest.mark.asyncio
    async def test_deploy_policy_failure(
        self, compiler: PolicyCompiler, sample_policy: Policy
    ) -> None:
        """Test deployment failure handling."""
        mock_response = AsyncMock()
        mock_response.status = 500
        mock_response.text = AsyncMock(return_value="Server error")

        with patch.object(compiler, "compile_policy", new_callable=AsyncMock) as mock_compile:
            mock_compile.return_value = "compiled rego"

            mock_session = MagicMock()
            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)
            mock_session.put = MagicMock(return_value=mock_cm)

            compiler.session = mock_session

            with pytest.raises(PolicyCompilationError, match="Failed to deploy"):
                await compiler.deploy_policy(sample_policy)

    @pytest.mark.asyncio
    async def test_generate_bundle(self, compiler: PolicyCompiler, sample_policy: Policy) -> None:
        """Test OPA bundle generation."""
        with patch.object(compiler, "compile_policy", new_callable=AsyncMock) as mock_compile:
            mock_compile.return_value = "compiled rego"

            bundle = await compiler.generate_bundle([sample_policy])

            assert "manifest" in bundle
            assert "data" in bundle
            assert "policies" in bundle

            assert bundle["manifest"]["roots"] == ["chronoguard"]
            assert "revision" in bundle["manifest"]
            assert len(bundle["policies"]) == 1

    @pytest.mark.asyncio
    async def test_generate_bundle_multiple_policies(
        self, compiler: PolicyCompiler, sample_policy: Policy
    ) -> None:
        """Test bundle generation with multiple policies."""
        policy2 = Policy(
            policy_id=uuid4(),
            tenant_id=uuid4(),
            name="Second Policy",
            description="Another policy",
            created_by=uuid4(),
            status=PolicyStatus.ACTIVE,
        )

        with patch.object(compiler, "compile_policy", new_callable=AsyncMock) as mock_compile:
            mock_compile.return_value = "compiled rego"

            bundle = await compiler.generate_bundle([sample_policy, policy2])

            assert len(bundle["policies"]) == 2
            assert "test_policy" in bundle["data"]["chronoguard"]["policies"]
            assert "second_policy" in bundle["data"]["chronoguard"]["policies"]

    @pytest.mark.asyncio
    async def test_evaluate_policy(self, compiler: PolicyCompiler) -> None:
        """Test policy evaluation via OPA."""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"result": True})

        mock_session = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_session.post = MagicMock(return_value=mock_cm)

        compiler.session = mock_session

        result = await compiler.evaluate_policy({"tenant_id": "test"})

        assert result is True
        mock_session.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_evaluate_policy_deny(self, compiler: PolicyCompiler) -> None:
        """Test policy evaluation returns deny."""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"result": False})

        mock_session = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_session.post = MagicMock(return_value=mock_cm)

        compiler.session = mock_session

        result = await compiler.evaluate_policy({"tenant_id": "test"})

        assert result is False

    @pytest.mark.asyncio
    async def test_evaluate_policy_failure(self, compiler: PolicyCompiler) -> None:
        """Test policy evaluation failure handling."""
        mock_response = AsyncMock()
        mock_response.status = 500
        mock_response.text = AsyncMock(return_value="Server error")

        mock_session = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_session.post = MagicMock(return_value=mock_cm)

        compiler.session = mock_session

        with pytest.raises(PolicyCompilationError, match="evaluation failed"):
            await compiler.evaluate_policy({"tenant_id": "test"})

    def test_format_time_restrictions_enabled(
        self, compiler: PolicyCompiler, policy_with_time_restrictions: Policy
    ) -> None:
        """Test formatting enabled time restrictions."""
        formatted = compiler._format_time_restrictions(
            policy_with_time_restrictions.time_restrictions
        )

        assert formatted["enabled"] is True
        assert formatted["timezone"] == "UTC"
        assert formatted["allowed_days"] == [0, 1, 2, 3, 4]
        assert len(formatted["time_ranges"]) == 1
        assert formatted["time_ranges"][0]["start_hour"] == 9
        assert formatted["time_ranges"][0]["end_hour"] == 17

    def test_format_time_restrictions_disabled(self, compiler: PolicyCompiler) -> None:
        """Test formatting disabled time restrictions."""
        restriction = TimeRestriction(
            allowed_time_ranges=[
                TimeRange(start_hour=9, start_minute=0, end_hour=17, end_minute=0)
            ],
            enabled=False,
        )

        formatted = compiler._format_time_restrictions(restriction)

        assert formatted["enabled"] is False

    def test_format_time_restrictions_none(self, compiler: PolicyCompiler) -> None:
        """Test formatting None time restrictions."""
        formatted = compiler._format_time_restrictions(None)

        assert formatted["enabled"] is False

    def test_format_rate_limits_enabled(
        self, compiler: PolicyCompiler, policy_with_rate_limits: Policy
    ) -> None:
        """Test formatting enabled rate limits."""
        formatted = compiler._format_rate_limits(policy_with_rate_limits.rate_limits)

        assert formatted["enabled"] is True
        assert formatted["requests_per_minute"] == 60
        assert formatted["requests_per_hour"] == 1000
        assert formatted["requests_per_day"] == 10000
        assert formatted["burst_limit"] == 100

    def test_format_rate_limits_disabled(self, compiler: PolicyCompiler) -> None:
        """Test formatting disabled rate limits."""
        limit = RateLimit(
            requests_per_minute=60,
            requests_per_hour=1000,
            requests_per_day=10000,
            enabled=False,
        )

        formatted = compiler._format_rate_limits(limit)

        assert formatted["enabled"] is False

    def test_format_rate_limits_none(self, compiler: PolicyCompiler) -> None:
        """Test formatting None rate limits."""
        formatted = compiler._format_rate_limits(None)

        assert formatted["enabled"] is False

    def test_format_rules(self, compiler: PolicyCompiler, policy_with_rules: Policy) -> None:
        """Test formatting policy rules."""
        formatted = compiler._format_rules(policy_with_rules)

        assert len(formatted) == 1
        rule = formatted[0]

        assert rule["name"] == "allow_get_requests"
        assert rule["action"] == "allow"
        assert rule["priority"] == 100
        assert len(rule["conditions"]) == 2

    def test_format_rules_disabled(self, compiler: PolicyCompiler) -> None:
        """Test disabled rules are not included."""
        rule1 = PolicyRule(
            name="enabled_rule",
            description="Enabled",
            conditions=[RuleCondition(field="method", operator="equals", value="GET")],
            action=RuleAction.ALLOW,
            enabled=True,
        )

        rule2 = PolicyRule(
            name="disabled_rule",
            description="Disabled",
            conditions=[RuleCondition(field="method", operator="equals", value="POST")],
            action=RuleAction.DENY,
            enabled=False,
        )

        policy = Policy(
            policy_id=uuid4(),
            tenant_id=uuid4(),
            name="Test",
            description="Test",
            created_by=uuid4(),
            rules=[rule1, rule2],
        )

        formatted = compiler._format_rules(policy)

        assert len(formatted) == 1
        assert formatted[0]["name"] == "enabled_rule"

    def test_format_rules_priority_sorting(self, compiler: PolicyCompiler) -> None:
        """Test rules are sorted by priority."""
        rule1 = PolicyRule(
            name="low_priority",
            description="Low",
            conditions=[RuleCondition(field="method", operator="equals", value="GET")],
            action=RuleAction.ALLOW,
            priority=200,
        )

        rule2 = PolicyRule(
            name="high_priority",
            description="High",
            conditions=[RuleCondition(field="method", operator="equals", value="POST")],
            action=RuleAction.ALLOW,
            priority=100,
        )

        policy = Policy(
            policy_id=uuid4(),
            tenant_id=uuid4(),
            name="Test",
            description="Test",
            created_by=uuid4(),
            rules=[rule1, rule2],
        )

        formatted = compiler._format_rules(policy)

        assert formatted[0]["name"] == "high_priority"
        assert formatted[1]["name"] == "low_priority"

    def test_sanitize_name(self, compiler: PolicyCompiler) -> None:
        """Test policy name sanitization."""
        assert compiler._sanitize_name("Simple Policy") == "simple_policy"
        assert compiler._sanitize_name("Policy-With-Dashes") == "policy_with_dashes"
        assert compiler._sanitize_name("Policy!@#$%^&*()Name") == "policy_name"
        assert compiler._sanitize_name("___Leading___") == "leading"
        assert compiler._sanitize_name("Multiple   Spaces") == "multiple_spaces"

    def test_generate_revision(self, compiler: PolicyCompiler) -> None:
        """Test revision ID generation."""
        revision1 = compiler._generate_revision()
        revision2 = compiler._generate_revision()

        assert isinstance(revision1, str)
        assert len(revision1) == 12
        assert revision1 != revision2  # Should be unique

    @pytest.mark.asyncio
    async def test_close_session(self, compiler: PolicyCompiler) -> None:
        """Test closing HTTP session."""
        mock_session = AsyncMock()
        compiler.session = mock_session

        await compiler.close()

        mock_session.close.assert_awaited_once()
        assert compiler.session is None

    @pytest.mark.asyncio
    async def test_close_no_session(self, compiler: PolicyCompiler) -> None:
        """Test closing when no session exists."""
        await compiler.close()

        assert compiler.session is None

    @pytest.mark.asyncio
    async def test_context_manager(self, template_dir: Path) -> None:
        """Test async context manager."""
        async with PolicyCompiler(template_dir=template_dir) as compiler:
            assert compiler is not None

        # Session should be closed
        assert compiler.session is None

    @pytest.mark.asyncio
    async def test_push_policies(self, compiler: PolicyCompiler, sample_policy: Policy) -> None:
        """Test pushing multiple policies to OPA."""
        policy2 = Policy(
            policy_id=uuid4(),
            tenant_id=uuid4(),
            name="Second Policy",
            description="Another policy",
            created_by=uuid4(),
            status=PolicyStatus.ACTIVE,
        )

        with patch.object(compiler, "deploy_policy", new_callable=AsyncMock) as mock_deploy:
            await compiler.push_policies([sample_policy, policy2])

            assert mock_deploy.await_count == 2
            mock_deploy.assert_any_await(sample_policy)
            mock_deploy.assert_any_await(policy2)

    @pytest.mark.asyncio
    async def test_push_policies_failure(
        self, compiler: PolicyCompiler, sample_policy: Policy
    ) -> None:
        """Test push_policies handles deployment failures."""
        with (
            patch.object(
                compiler,
                "deploy_policy",
                new_callable=AsyncMock,
                side_effect=PolicyCompilationError("Deployment failed"),
            ),
            pytest.raises(PolicyCompilationError, match="Failed to push policies"),
        ):
            await compiler.push_policies([sample_policy])

    @pytest.mark.asyncio
    async def test_validate_rego_success(self, compiler: PolicyCompiler) -> None:
        """Test successful Rego validation."""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"result": {}})

        mock_session = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_session.post = MagicMock(return_value=mock_cm)

        compiler.session = mock_session

        await compiler._validate_rego("package test\nallow = true")

        mock_session.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_validate_rego_failure(self, compiler: PolicyCompiler) -> None:
        """Test Rego validation failure."""
        mock_response = AsyncMock()
        mock_response.status = 400
        mock_response.text = AsyncMock(return_value="Syntax error")

        mock_session = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_session.post = MagicMock(return_value=mock_cm)

        compiler.session = mock_session

        with pytest.raises(PolicyCompilationError, match="syntax validation failed"):
            await compiler._validate_rego("invalid rego")
