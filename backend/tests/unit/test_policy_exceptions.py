"""Comprehensive tests for policy domain exceptions."""

from uuid import uuid4

from domain.common.exceptions import DomainError
from domain.policy.exceptions import (
    PolicyActivationError,
    PolicyDomainConflictError,
    PolicyError,
    PolicyEvaluationError,
    PolicyLimitExceededError,
    PolicyNameExistsError,
    PolicyNotFoundError,
    PolicyPriorityConflictError,
    PolicyReferencedByAgentsError,
    PolicyRuleLimitExceededError,
    PolicyRuleNotFoundError,
    PolicyStatusTransitionError,
)


class TestPolicyError:
    """Test base PolicyError class."""

    def test_policy_error_inheritance(self):
        """Test PolicyError inherits from DomainError."""
        error = PolicyError("Test policy error")
        assert isinstance(error, DomainError)
        assert str(error) == "Test policy error"


class TestPolicyNotFoundError:
    """Test PolicyNotFoundError exception."""

    def test_policy_not_found_error_creation(self):
        """Test creating PolicyNotFoundError."""
        policy_id = uuid4()
        error = PolicyNotFoundError(policy_id)

        assert isinstance(error, PolicyError)
        assert error.policy_id == policy_id
        assert str(policy_id) in str(error)
        assert error.error_code == "POLICY_NOT_FOUND"
        assert "not found" in str(error)

    def test_policy_not_found_error_attributes(self):
        """Test PolicyNotFoundError attributes are accessible."""
        policy_id = uuid4()
        error = PolicyNotFoundError(policy_id)

        # Test that attributes are properly set
        assert hasattr(error, "policy_id")
        assert hasattr(error, "error_code")
        assert error.policy_id == policy_id


class TestPolicyNameExistsError:
    """Test PolicyNameExistsError exception."""

    def test_policy_name_exists_error_creation(self):
        """Test creating PolicyNameExistsError."""
        tenant_id = uuid4()
        name = "Existing Policy"
        error = PolicyNameExistsError(tenant_id, name)

        assert isinstance(error, PolicyError)
        assert error.tenant_id == tenant_id
        assert error.name == name
        assert error.error_code == "POLICY_NAME_EXISTS"
        assert "already exists" in str(error)
        assert name in str(error)
        assert str(tenant_id) in str(error)

    def test_policy_name_exists_error_attributes(self):
        """Test PolicyNameExistsError attributes."""
        tenant_id = uuid4()
        name = "Test Policy"
        error = PolicyNameExistsError(tenant_id, name)

        assert error.tenant_id == tenant_id
        assert error.name == name


class TestPolicyPriorityConflictError:
    """Test PolicyPriorityConflictError exception."""

    def test_policy_priority_conflict_error_creation(self):
        """Test creating PolicyPriorityConflictError."""
        tenant_id = uuid4()
        priority = 100
        existing_policy_ids = [uuid4(), uuid4()]
        error = PolicyPriorityConflictError(tenant_id, priority, existing_policy_ids)

        assert isinstance(error, PolicyError)
        assert error.tenant_id == tenant_id
        assert error.priority == priority
        assert error.existing_policy_ids == existing_policy_ids
        assert error.error_code == "POLICY_PRIORITY_CONFLICT"
        assert "already in use" in str(error)
        assert str(priority) in str(error)
        assert str(len(existing_policy_ids)) in str(error)

    def test_policy_priority_conflict_single_existing(self):
        """Test priority conflict with single existing policy."""
        tenant_id = uuid4()
        existing_policy_ids = [uuid4()]
        error = PolicyPriorityConflictError(tenant_id, 50, existing_policy_ids)

        assert len(error.existing_policy_ids) == 1
        assert "1 policies" in str(error)


class TestPolicyLimitExceededError:
    """Test PolicyLimitExceededError exception."""

    def test_policy_limit_exceeded_error_creation(self):
        """Test creating PolicyLimitExceededError."""
        tenant_id = uuid4()
        current_count = 25
        max_allowed = 20
        error = PolicyLimitExceededError(tenant_id, current_count, max_allowed)

        assert isinstance(error, PolicyError)
        assert error.tenant_id == tenant_id
        assert error.current_count == current_count
        assert error.max_allowed == max_allowed
        assert error.error_code == "POLICY_LIMIT_EXCEEDED"
        assert "limit exceeded" in str(error)
        assert f"{current_count}/{max_allowed}" in str(error)

    def test_policy_limit_exceeded_at_exact_limit(self):
        """Test limit exceeded when at exact limit."""
        tenant_id = uuid4()
        error = PolicyLimitExceededError(tenant_id, 10, 10)

        assert error.current_count == error.max_allowed
        assert "10/10" in str(error)


class TestPolicyRuleLimitExceededError:
    """Test PolicyRuleLimitExceededError exception."""

    def test_policy_rule_limit_exceeded_error_creation(self):
        """Test creating PolicyRuleLimitExceededError."""
        policy_id = uuid4()
        current_count = 15
        max_allowed = 10
        error = PolicyRuleLimitExceededError(policy_id, current_count, max_allowed)

        assert isinstance(error, PolicyError)
        assert error.policy_id == policy_id
        assert error.current_count == current_count
        assert error.max_allowed == max_allowed
        assert error.error_code == "POLICY_RULE_LIMIT_EXCEEDED"
        assert "Rule limit exceeded" in str(error)
        assert f"{current_count}/{max_allowed}" in str(error)


class TestPolicyStatusTransitionError:
    """Test PolicyStatusTransitionError exception."""

    def test_policy_status_transition_error_creation(self):
        """Test creating PolicyStatusTransitionError."""
        policy_id = uuid4()
        current_status = "ACTIVE"
        requested_status = "DELETED"
        error = PolicyStatusTransitionError(policy_id, current_status, requested_status)

        assert isinstance(error, PolicyError)
        assert error.policy_id == policy_id
        assert error.current_status == current_status
        assert error.requested_status == requested_status
        assert error.error_code == "POLICY_INVALID_STATUS_TRANSITION"
        assert "Invalid status transition" in str(error)
        assert f"{current_status} -> {requested_status}" in str(error)

    def test_policy_status_transition_error_attributes(self):
        """Test PolicyStatusTransitionError attributes."""
        policy_id = uuid4()
        error = PolicyStatusTransitionError(policy_id, "DRAFT", "ACTIVE")

        assert error.current_status == "DRAFT"
        assert error.requested_status == "ACTIVE"


class TestPolicyEvaluationError:
    """Test PolicyEvaluationError exception."""

    def test_policy_evaluation_error_creation(self):
        """Test creating PolicyEvaluationError."""
        policy_id = uuid4()
        reason = "Missing required rule conditions"
        error = PolicyEvaluationError(policy_id, reason)

        assert isinstance(error, PolicyError)
        assert error.policy_id == policy_id
        assert error.reason == reason
        assert error.error_code == "POLICY_EVALUATION_FAILED"
        assert "evaluation failed" in str(error)
        assert reason in str(error)

    def test_policy_evaluation_error_with_complex_reason(self):
        """Test evaluation error with complex reason."""
        policy_id = uuid4()
        reason = "Rule #3 has invalid operator 'unknown_op' for field 'domain'"
        error = PolicyEvaluationError(policy_id, reason)

        assert error.reason == reason
        assert "unknown_op" in str(error)


class TestPolicyRuleNotFoundError:
    """Test PolicyRuleNotFoundError exception."""

    def test_policy_rule_not_found_error_creation(self):
        """Test creating PolicyRuleNotFoundError."""
        policy_id = uuid4()
        rule_id = uuid4()
        error = PolicyRuleNotFoundError(policy_id, rule_id)

        assert isinstance(error, PolicyError)
        assert error.policy_id == policy_id
        assert error.rule_id == rule_id
        assert error.error_code == "POLICY_RULE_NOT_FOUND"
        assert "not found" in str(error)
        assert str(rule_id) in str(error)
        assert str(policy_id) in str(error)


class TestPolicyDomainConflictError:
    """Test PolicyDomainConflictError exception."""

    def test_policy_domain_conflict_error_creation(self):
        """Test creating PolicyDomainConflictError."""
        policy_id = uuid4()
        domain = "example.com"
        conflict_type = "already_allowed"
        error = PolicyDomainConflictError(policy_id, domain, conflict_type)

        assert isinstance(error, PolicyError)
        assert error.policy_id == policy_id
        assert error.domain == domain
        assert error.conflict_type == conflict_type
        assert error.error_code == "POLICY_DOMAIN_CONFLICT"
        assert "Domain conflict" in str(error)
        assert domain in str(error)
        assert conflict_type in str(error)

    def test_policy_domain_conflict_blocked_type(self):
        """Test domain conflict with blocked type."""
        policy_id = uuid4()
        error = PolicyDomainConflictError(policy_id, "blocked.com", "already_blocked")

        assert error.conflict_type == "already_blocked"
        assert "already_blocked" in str(error)


class TestPolicyReferencedByAgentsError:
    """Test PolicyReferencedByAgentsError exception."""

    def test_policy_referenced_by_agents_error_creation(self):
        """Test creating PolicyReferencedByAgentsError."""
        policy_id = uuid4()
        referencing_agent_count = 5
        error = PolicyReferencedByAgentsError(policy_id, referencing_agent_count)

        assert isinstance(error, PolicyError)
        assert error.policy_id == policy_id
        assert error.referencing_agent_count == referencing_agent_count
        assert error.error_code == "POLICY_REFERENCED_BY_AGENTS"
        assert "referenced by" in str(error)
        assert "5 agents" in str(error)
        assert "cannot be deleted" in str(error)

    def test_policy_referenced_by_single_agent(self):
        """Test policy referenced by single agent."""
        policy_id = uuid4()
        error = PolicyReferencedByAgentsError(policy_id, 1)

        assert error.referencing_agent_count == 1
        assert "1 agents" in str(error)


class TestPolicyActivationError:
    """Test PolicyActivationError exception."""

    def test_policy_activation_error_creation(self):
        """Test creating PolicyActivationError."""
        policy_id = uuid4()
        reason = "Policy has no rules defined"
        error = PolicyActivationError(policy_id, reason)

        assert isinstance(error, PolicyError)
        assert error.policy_id == policy_id
        assert error.reason == reason
        assert error.error_code == "POLICY_ACTIVATION_FAILED"
        assert "Cannot activate" in str(error)
        assert reason in str(error)

    def test_policy_activation_error_complex_reason(self):
        """Test activation error with complex reason."""
        policy_id = uuid4()
        reason = "Policy contains invalid time restrictions and conflicting domain rules"
        error = PolicyActivationError(policy_id, reason)

        assert error.reason == reason
        assert "time restrictions" in str(error)
        assert "domain rules" in str(error)


class TestExceptionIntegration:
    """Test exception integration and inheritance."""

    def test_all_exceptions_inherit_from_policy_error(self):
        """Test all policy exceptions inherit from PolicyError."""
        policy_id = uuid4()
        tenant_id = uuid4()
        rule_id = uuid4()

        exceptions = [
            PolicyNotFoundError(policy_id),
            PolicyNameExistsError(tenant_id, "test"),
            PolicyPriorityConflictError(tenant_id, 100, []),
            PolicyLimitExceededError(tenant_id, 5, 3),
            PolicyRuleLimitExceededError(policy_id, 15, 10),
            PolicyStatusTransitionError(policy_id, "ACTIVE", "DELETED"),
            PolicyEvaluationError(policy_id, "test"),
            PolicyRuleNotFoundError(policy_id, rule_id),
            PolicyDomainConflictError(policy_id, "test.com", "conflict"),
            PolicyReferencedByAgentsError(policy_id, 3),
            PolicyActivationError(policy_id, "test"),
        ]

        for exception in exceptions:
            assert isinstance(exception, PolicyError)
            assert isinstance(exception, DomainError)

    def test_all_exceptions_have_error_codes(self):
        """Test all policy exceptions have unique error codes."""
        policy_id = uuid4()
        tenant_id = uuid4()
        rule_id = uuid4()

        exceptions = [
            PolicyNotFoundError(policy_id),
            PolicyNameExistsError(tenant_id, "test"),
            PolicyPriorityConflictError(tenant_id, 100, []),
            PolicyLimitExceededError(tenant_id, 5, 3),
            PolicyRuleLimitExceededError(policy_id, 15, 10),
            PolicyStatusTransitionError(policy_id, "ACTIVE", "DELETED"),
            PolicyEvaluationError(policy_id, "test"),
            PolicyRuleNotFoundError(policy_id, rule_id),
            PolicyDomainConflictError(policy_id, "test.com", "conflict"),
            PolicyReferencedByAgentsError(policy_id, 3),
            PolicyActivationError(policy_id, "test"),
        ]

        error_codes = [exc.error_code for exc in exceptions]
        # Check all error codes are unique
        assert len(error_codes) == len(set(error_codes))

        # Check all have proper error code format
        for code in error_codes:
            assert isinstance(code, str)
            assert len(code) > 0
            assert "POLICY" in code

    def test_exception_string_representations(self):
        """Test exception string representations are informative."""
        policy_id = uuid4()
        tenant_id = uuid4()

        # Test that all exceptions have meaningful string representations
        error1 = PolicyNotFoundError(policy_id)
        assert len(str(error1)) > 10
        assert str(policy_id) in str(error1)

        error2 = PolicyNameExistsError(tenant_id, "My Policy")
        assert "My Policy" in str(error2)
        assert str(tenant_id) in str(error2)

        error3 = PolicyLimitExceededError(tenant_id, 25, 20)
        assert "25/20" in str(error3)

    def test_exception_repr_functionality(self):
        """Test exception repr provides useful debugging info."""
        policy_id = uuid4()
        error = PolicyNotFoundError(policy_id)

        repr_str = repr(error)
        assert "PolicyNotFoundError" in repr_str

    def test_exception_context_preservation(self):
        """Test exceptions preserve context information."""
        policy_id = uuid4()
        tenant_id = uuid4()
        rule_id = uuid4()

        # Test that context is preserved across exception creation
        error = PolicyRuleNotFoundError(policy_id, rule_id)
        assert error.policy_id == policy_id
        assert error.rule_id == rule_id

        # Test attributes don't get modified
        original_policy_id = error.policy_id
        original_rule_id = error.rule_id

        # Simulate passing exception around
        def process_error(exc):
            return exc.policy_id, exc.rule_id

        processed_policy_id, processed_rule_id = process_error(error)
        assert processed_policy_id == original_policy_id
        assert processed_rule_id == original_rule_id

    def test_exception_chaining_compatibility(self):
        """Test exceptions work with exception chaining."""
        policy_id = uuid4()

        try:
            # Simulate a chain of errors
            try:
                raise ValueError("Underlying validation error")
            except ValueError as e:
                raise PolicyEvaluationError(policy_id, "Policy validation failed") from e
        except PolicyEvaluationError as policy_error:
            assert isinstance(policy_error, PolicyError)
            assert policy_error.__cause__ is not None
            assert isinstance(policy_error.__cause__, ValueError)
            assert "Underlying validation error" in str(policy_error.__cause__)
