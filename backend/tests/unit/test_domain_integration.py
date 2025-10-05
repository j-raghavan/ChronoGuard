"""Integration tests for domain layer components working together."""

from uuid import UUID, uuid4

import pytest
from core.container import DependencyContainer
from core.features import FeatureManager
from domain.agent.entity import Agent, AgentStatus
from domain.audit.entity import AccessDecision, AuditEntry
from domain.audit.hasher import EnhancedAuditHasher
from domain.common.exceptions import DomainError, SecurityViolationError, ValidationError
from domain.common.value_objects import DomainName, TimeRange, X509Certificate
from domain.policy.entity import Policy, PolicyRule, RuleAction, RuleCondition


class TestDomainComponentIntegration:
    """Test domain components working together as a cohesive system."""

    def test_feature_management_system_integration(self) -> None:
        """Test feature management integrates properly with dependency injection."""
        feature_manager = FeatureManager()
        container = DependencyContainer(feature_manager)

        assert container.feature_manager is feature_manager
        assert feature_manager.is_enabled("prometheus_metrics") is True

        health = container.health_check()
        assert health["container_status"] == "healthy"
        assert "enabled_features" in health

    def test_agent_policy_assignment_workflow(
        self, test_tenant_id: UUID, test_certificate: X509Certificate
    ) -> None:
        """Test complete agent-policy assignment workflow."""
        # Create agent
        agent = Agent(
            tenant_id=test_tenant_id,
            name="Workflow Test Agent",
            certificate=test_certificate,
        )

        # Create policy
        policy = Policy(
            tenant_id=test_tenant_id,
            name="Workflow Test Policy",
            description="Policy for workflow testing",
            created_by=uuid4(),
        )

        # Add rule to policy
        rule = PolicyRule(
            name="Allow Example Domain",
            description="Allow access to example.com",
            conditions=[RuleCondition(field="domain", operator="equals", value="example.com")],
            action=RuleAction.ALLOW,
        )
        policy.add_rule(rule)

        # Activate policy and agent
        policy.activate()
        agent.activate()

        # Assign policy to agent
        agent.assign_policy(policy.policy_id)

        # Verify integration
        assert agent.is_active() is True
        assert policy.is_active() is True
        assert policy.policy_id in agent.policy_ids
        assert agent.can_make_requests() is True

    def test_audit_trail_creation_workflow(self, test_tenant_id: UUID, test_agent_id: UUID) -> None:
        """Test audit trail creation with hash chaining."""
        hasher = EnhancedAuditHasher()

        # Create sequence of audit entries
        entries = []
        previous_hash = ""

        for i in range(5):
            entry = AuditEntry(
                tenant_id=test_tenant_id,
                agent_id=test_agent_id,
                domain=f"test{i}.example.com",
                decision=AccessDecision.ALLOW if i % 2 == 0 else AccessDecision.DENY,
                reason=f"Test access {i}",
                sequence_number=i + 1,
            )

            # Calculate hash with chaining using the hasher
            hash_bytes = hasher.compute_entry_hash(entry, previous_hash)
            hash_hex = hash_bytes.hex()

            entry_with_hash = AuditEntry(
                **{
                    **entry.model_dump(),
                    "previous_hash": previous_hash,
                    "current_hash": hash_hex,
                }
            )
            entries.append(entry_with_hash)
            previous_hash = hash_hex

        # Verify chain integrity
        is_valid, errors = hasher.verify_chain_integrity(entries)
        assert is_valid is True
        assert len(errors) == 0

    def test_security_validation_consistency(self) -> None:
        """Test security validations are consistent across domain."""
        # Test IP address blocking
        with pytest.raises(SecurityViolationError):
            DomainName(value="127.0.0.1")

        # Test suspicious domain patterns
        with pytest.raises(SecurityViolationError):
            DomainName(value="localhost")

        # Test excessive nesting
        nested_domain = ".".join(["sub"] * 7) + ".example.com"
        with pytest.raises(SecurityViolationError):
            DomainName(value=nested_domain)

    def test_validation_error_consistency(self) -> None:
        """Test validation errors are consistent and informative."""
        # Test empty values
        with pytest.raises(ValidationError) as exc_info:
            DomainName(value="")
        assert "cannot be empty" in str(exc_info.value)

        # Test boundary conditions
        with pytest.raises(ValidationError):
            TimeRange(start_hour=25, start_minute=0, end_hour=17, end_minute=0)

    def test_business_rule_enforcement(
        self, test_tenant_id: UUID, test_certificate: X509Certificate
    ) -> None:
        """Test business rules are enforced across domain entities."""
        agent = Agent(
            tenant_id=test_tenant_id,
            name="Business Rule Test",
            certificate=test_certificate,
        )

        # Test policy limit enforcement
        for _ in range(50):  # Max allowed policies
            agent.assign_policy(uuid4())

        # Attempting to assign 51st policy should fail
        from domain.common.exceptions import BusinessRuleViolationError

        with pytest.raises(BusinessRuleViolationError):
            agent.assign_policy(uuid4())

    def test_value_object_immutability_enforcement(self, test_certificate_pem: str) -> None:
        """Test all value objects properly enforce immutability."""
        # TimeRange immutability
        time_range = TimeRange.business_hours()
        with pytest.raises(Exception):  # Pydantic ValidationError
            time_range.start_hour = 10

        # DomainName immutability
        domain = DomainName(value="example.com")
        with pytest.raises(Exception):  # Pydantic ValidationError
            domain.value = "other.com"

        # X509Certificate immutability (skip due to invalid test cert)
        # certificate = X509Certificate(pem_data=test_certificate_pem)
        # with pytest.raises(Exception):  # Pydantic ValidationError
        #     certificate.pem_data = "modified"

    def test_entity_state_transition_rules(
        self, test_tenant_id: UUID, test_certificate: X509Certificate
    ) -> None:
        """Test entity state transitions follow business rules."""
        agent = Agent(
            tenant_id=test_tenant_id,
            name="State Test Agent",
            certificate=test_certificate,
        )

        # Valid transition: pending -> active
        agent.activate()
        assert agent.status == AgentStatus.ACTIVE

        # Valid transition: active -> suspended
        agent.suspend("Test suspension")
        assert agent.status == AgentStatus.SUSPENDED

        # Valid transition: suspended -> active
        agent.activate()
        assert agent.status == AgentStatus.ACTIVE

        # Valid transition: active -> deactivated
        agent.deactivate("Test deactivation")
        assert agent.status == AgentStatus.DEACTIVATED

        # Invalid transition: deactivated -> active (should fail)
        from domain.common.exceptions import InvalidStateTransitionError

        with pytest.raises(InvalidStateTransitionError):
            agent.activate()

    def test_exception_hierarchy_completeness(self) -> None:
        """Test exception hierarchy is complete and properly structured."""
        # Test base exception
        assert issubclass(DomainError, Exception)

        # Test domain-specific exceptions
        from domain.agent.exceptions import AgentError
        from domain.audit.exceptions import AuditError
        from domain.policy.exceptions import PolicyError

        assert issubclass(AgentError, DomainError)
        assert issubclass(AuditError, DomainError)
        assert issubclass(PolicyError, DomainError)

        # Test all exceptions have proper error codes
        from domain.agent.exceptions import AgentNotFoundError

        error = AgentNotFoundError(uuid4())
        assert error.error_code == "AGENT_NOT_FOUND"
