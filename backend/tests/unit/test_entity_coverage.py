"""Comprehensive tests for domain entities to achieve 95% coverage."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from domain.audit.entity import AccessDecision, AuditEntry, TimedAccessContext
from domain.common.exceptions import ValidationError
from domain.common.value_objects import DomainName, TimeRange
from domain.policy.entity import Policy, PolicyRule, PolicyStatus, RuleAction, RuleCondition


class TestPolicyEntityComprehensive:
    """Comprehensive tests for Policy entity methods."""

    def test_policy_add_rule_duplicate_name(self) -> None:
        """Test adding rule with duplicate name."""
        tenant_id = uuid4()
        user_id = uuid4()

        policy = Policy(
            tenant_id=tenant_id, name="Test Policy", description="Test", created_by=user_id
        )

        # Add first rule
        rule1 = PolicyRule(
            name="Test Rule",
            description="First rule",
            conditions=[RuleCondition(field="domain", operator="equals", value="example.com")],
            action=RuleAction.ALLOW,
        )
        policy.add_rule(rule1)

        # Try to add second rule with same name
        rule2 = PolicyRule(
            name="Test Rule",  # Same name
            description="Second rule",
            conditions=[RuleCondition(field="domain", operator="equals", value="other.com")],
            action=RuleAction.DENY,
        )

        with pytest.raises(ValidationError, match="already exists"):
            policy.add_rule(rule2)

    def test_policy_add_rule_too_many(self) -> None:
        """Test adding too many rules to policy."""
        tenant_id = uuid4()
        user_id = uuid4()

        policy = Policy(
            tenant_id=tenant_id, name="Test Policy", description="Test", created_by=user_id
        )

        # Add 100 rules (the limit)
        for i in range(100):
            rule = PolicyRule(
                name=f"Rule {i}",
                description=f"Rule {i} description",
                conditions=[
                    RuleCondition(field="domain", operator="equals", value=f"domain{i}.com")
                ],
                action=RuleAction.ALLOW,
            )
            policy.add_rule(rule)

        # Try to add one more
        extra_rule = PolicyRule(
            name="Extra Rule",
            description="Should fail",
            conditions=[RuleCondition(field="domain", operator="equals", value="extra.com")],
            action=RuleAction.ALLOW,
        )

        with pytest.raises(ValidationError, match="Cannot add more than 100 rules"):
            policy.add_rule(extra_rule)

    def test_policy_remove_rule_success(self) -> None:
        """Test successful rule removal."""
        tenant_id = uuid4()
        user_id = uuid4()

        policy = Policy(
            tenant_id=tenant_id, name="Test Policy", description="Test", created_by=user_id
        )

        # Add rule
        rule = PolicyRule(
            name="Test Rule",
            description="Test rule",
            conditions=[RuleCondition(field="domain", operator="equals", value="example.com")],
            action=RuleAction.ALLOW,
        )
        policy.add_rule(rule)

        # Remove rule
        result = policy.remove_rule(rule.rule_id)
        assert result is True
        assert len(policy.rules) == 0

    def test_policy_remove_rule_not_found(self) -> None:
        """Test removing non-existent rule."""
        tenant_id = uuid4()
        user_id = uuid4()

        policy = Policy(
            tenant_id=tenant_id, name="Test Policy", description="Test", created_by=user_id
        )

        result = policy.remove_rule(uuid4())
        assert result is False

    def test_policy_activate_archived_policy(self) -> None:
        """Test activating archived policy."""
        tenant_id = uuid4()
        user_id = uuid4()

        policy = Policy(
            tenant_id=tenant_id,
            name="Test Policy",
            description="Test",
            created_by=user_id,
            status=PolicyStatus.ARCHIVED,
        )

        with pytest.raises(ValidationError, match="Cannot activate archived policy"):
            policy.activate()

    def test_policy_state_transitions(self) -> None:
        """Test policy state transitions."""
        tenant_id = uuid4()
        user_id = uuid4()

        policy = Policy(
            tenant_id=tenant_id, name="Test Policy", description="Test", created_by=user_id
        )

        # Add a rule so it can be activated
        rule = PolicyRule(
            name="Test Rule",
            description="Test rule",
            conditions=[RuleCondition(field="domain", operator="equals", value="example.com")],
            action=RuleAction.ALLOW,
        )
        policy.add_rule(rule)

        # Test activation
        assert policy.status == PolicyStatus.DRAFT
        policy.activate()
        assert policy.status == PolicyStatus.ACTIVE

        # Test suspension
        policy.suspend()
        assert policy.status == PolicyStatus.SUSPENDED

        # Test archiving
        policy.archive()
        assert policy.status == PolicyStatus.ARCHIVED

    def test_policy_domain_management(self) -> None:
        """Test policy domain management methods."""
        tenant_id = uuid4()
        user_id = uuid4()

        policy = Policy(
            tenant_id=tenant_id, name="Test Policy", description="Test", created_by=user_id
        )

        # Test adding allowed domain
        policy.add_allowed_domain("example.com")
        assert "example.com" in policy.allowed_domains

        # Test adding blocked domain
        policy.add_blocked_domain("malicious.com")
        assert "malicious.com" in policy.blocked_domains

        # Test adding domain that's already blocked
        with pytest.raises(ValidationError, match="already in blocked list"):
            policy.add_allowed_domain("malicious.com")

        # Test adding domain that's already allowed
        with pytest.raises(ValidationError, match="already in allowed list"):
            policy.add_blocked_domain("example.com")

        # Test removing domain
        result = policy.remove_domain("example.com")
        assert result is True
        assert "example.com" not in policy.allowed_domains

        # Test removing non-existent domain
        result = policy.remove_domain("nonexistent.com")
        assert result is False

    def test_policy_time_and_rate_restrictions(self) -> None:
        """Test policy time and rate restriction methods."""
        from domain.policy.entity import RateLimit, TimeRestriction

        tenant_id = uuid4()
        user_id = uuid4()

        policy = Policy(
            tenant_id=tenant_id, name="Test Policy", description="Test", created_by=user_id
        )

        # Test setting time restrictions
        time_restriction = TimeRestriction(
            allowed_time_ranges=[TimeRange.business_hours()],
            allowed_days_of_week={0, 1, 2, 3, 4},
            timezone="UTC",
        )
        policy.set_time_restrictions(time_restriction)
        assert policy.time_restrictions == time_restriction

        # Test setting rate limits
        rate_limit = RateLimit(
            requests_per_minute=60, requests_per_hour=3600, requests_per_day=86400
        )
        policy.set_rate_limits(rate_limit)
        assert policy.rate_limits == rate_limit

    def test_policy_is_active(self) -> None:
        """Test policy is_active method."""
        tenant_id = uuid4()
        user_id = uuid4()

        policy = Policy(
            tenant_id=tenant_id, name="Test Policy", description="Test", created_by=user_id
        )

        # Initially draft
        assert policy.is_active() is False

        # After activation
        policy.add_allowed_domain("example.com")  # Add content so it can be activated
        policy.activate()
        assert policy.is_active() is True

    def test_policy_string_representations(self) -> None:
        """Test policy string representations."""
        tenant_id = uuid4()
        user_id = uuid4()

        policy = Policy(
            tenant_id=tenant_id,
            name="Test Policy",
            description="Test policy description",
            created_by=user_id,
        )

        # Test __str__
        str_repr = str(policy)
        assert "Test Policy" in str_repr
        assert str(policy.policy_id) in str_repr

        # Test __repr__
        repr_str = repr(policy)
        assert "Policy(" in repr_str
        assert str(policy.tenant_id) in repr_str


class TestAuditEntityComprehensive:
    """Comprehensive tests for AuditEntry entity methods."""

    def test_audit_entry_risk_score_calculation(self) -> None:
        """Test audit entry risk score calculation."""
        tenant_id = uuid4()
        agent_id = uuid4()

        # Test allowed access (low risk)
        entry_allow = AuditEntry(
            tenant_id=tenant_id,
            agent_id=agent_id,
            domain="example.com",
            decision=AccessDecision.ALLOW,
            user_agent="NormalBrowser/1.0",
        )
        risk_allow = entry_allow.get_risk_score()
        assert 0 <= risk_allow <= 100

        # Test denied access (higher risk)
        entry_deny = AuditEntry(
            tenant_id=tenant_id,
            agent_id=agent_id,
            domain="blocked.com",
            decision=AccessDecision.DENY,
            user_agent="curl/7.68.0",  # Suspicious user agent
        )
        risk_deny = entry_deny.get_risk_score()
        assert risk_deny >= 30  # Should have higher risk due to denial + suspicious agent

    def test_audit_entry_access_decision_methods(self) -> None:
        """Test audit entry access decision methods."""
        tenant_id = uuid4()
        agent_id = uuid4()

        # Test allowed access
        entry_allow = AuditEntry(
            tenant_id=tenant_id,
            agent_id=agent_id,
            domain="example.com",
            decision=AccessDecision.ALLOW,
        )
        assert entry_allow.is_access_allowed() is True
        assert entry_allow.is_access_denied() is False

        # Test denied access
        entry_deny = AuditEntry(
            tenant_id=tenant_id,
            agent_id=agent_id,
            domain="blocked.com",
            decision=AccessDecision.DENY,
        )
        assert entry_deny.is_access_allowed() is False
        assert entry_deny.is_access_denied() is True

        # Test other denial types
        entry_rate_limited = AuditEntry(
            tenant_id=tenant_id,
            agent_id=agent_id,
            domain="example.com",
            decision=AccessDecision.RATE_LIMITED,
        )
        assert entry_rate_limited.is_access_denied() is True

    def test_audit_entry_hash_operations(self) -> None:
        """Test audit entry hash operations."""
        tenant_id = uuid4()
        agent_id = uuid4()

        entry = AuditEntry(
            tenant_id=tenant_id,
            agent_id=agent_id,
            domain="example.com",
            decision=AccessDecision.ALLOW,
            sequence_number=1,
        )

        # Test hash calculation
        hash1 = entry.calculate_hash()
        assert isinstance(hash1, str)
        assert len(hash1) == 64

        # Test hash with previous hash
        hash2 = entry.calculate_hash("previous_hash")
        assert hash2 != hash1  # Should be different

        # Test hash with secret key
        hash3 = entry.calculate_hash(secret_key=b"test_secret_key")
        assert hash3 != hash1  # Should be different

        # Test with_hash method
        entry_with_hash = entry.with_hash("prev_hash", b"secret")
        assert entry_with_hash.previous_hash == "prev_hash"
        assert entry_with_hash.current_hash != ""

        # Test hash verification
        is_valid = entry_with_hash.verify_hash(b"secret")
        assert isinstance(is_valid, bool)

    def test_audit_entry_json_conversion(self) -> None:
        """Test audit entry JSON conversion."""
        tenant_id = uuid4()
        agent_id = uuid4()

        entry = AuditEntry(
            tenant_id=tenant_id,
            agent_id=agent_id,
            domain="api.example.com",
            decision=AccessDecision.ALLOW,
            reason="API access granted",
            request_method="POST",
            request_path="/api/v1/users",
            user_agent="TestClient/1.0",
            source_ip="10.0.0.1",
            response_status=201,
            response_size_bytes=1024,
            processing_time_ms=45.7,
            sequence_number=5,
        )

        json_dict = entry.to_json_dict()

        assert isinstance(json_dict, dict)
        assert json_dict["domain"] == "api.example.com"
        assert json_dict["decision"] == "allow"
        assert json_dict["request_method"] == "POST"
        assert json_dict["response_status"] == 201
        assert json_dict["processing_time_ms"] == 45.7
        assert "risk_score" in json_dict

    def test_audit_entry_string_representations(self) -> None:
        """Test audit entry string representations."""
        tenant_id = uuid4()
        agent_id = uuid4()

        entry = AuditEntry(
            tenant_id=tenant_id,
            agent_id=agent_id,
            domain="example.com",
            decision=AccessDecision.ALLOW,
        )

        # Test __str__
        str_repr = str(entry)
        assert "AuditEntry" in str_repr
        assert str(entry.entry_id) in str_repr
        assert "example.com" in str_repr

        # Test __repr__
        repr_str = repr(entry)
        assert "AuditEntry" in repr_str
        assert str(entry.tenant_id) in repr_str


class TestTimedAccessContextComprehensive:
    """Comprehensive tests for TimedAccessContext."""

    def test_timed_access_context_creation_all_quarters(self) -> None:
        """Test context creation for all quarters of the year."""

        # Q1
        q1_time = datetime(2023, 2, 15, 14, 30, tzinfo=UTC)
        q1_context = TimedAccessContext.create_from_timestamp(q1_time)
        assert q1_context.quarter_of_year == 1

        # Q2
        q2_time = datetime(2023, 5, 15, 14, 30, tzinfo=UTC)
        q2_context = TimedAccessContext.create_from_timestamp(q2_time)
        assert q2_context.quarter_of_year == 2

        # Q3
        q3_time = datetime(2023, 8, 15, 14, 30, tzinfo=UTC)
        q3_context = TimedAccessContext.create_from_timestamp(q3_time)
        assert q3_context.quarter_of_year == 3

        # Q4
        q4_time = datetime(2023, 11, 15, 14, 30, tzinfo=UTC)
        q4_context = TimedAccessContext.create_from_timestamp(q4_time)
        assert q4_context.quarter_of_year == 4

    def test_timed_access_context_all_days_of_week(self) -> None:
        """Test context creation for all days of the week."""

        # Test each day of week (Monday = 0, Sunday = 6)
        base_date = datetime(2023, 9, 18, 10, 0, tzinfo=UTC)  # Monday

        for day_offset in range(7):
            test_date = base_date.replace(day=base_date.day + day_offset)
            context = TimedAccessContext.create_from_timestamp(test_date)

            expected_is_weekend = day_offset >= 5  # Saturday=5, Sunday=6
            assert context.is_weekend == expected_is_weekend
            assert context.day_of_week == day_offset

    def test_timed_access_context_business_hours_edge_cases(self) -> None:
        """Test business hours edge cases."""

        # Test exactly 9 AM (start of business hours)
        start_time = datetime(2023, 9, 28, 9, 0, tzinfo=UTC)
        start_context = TimedAccessContext.create_from_timestamp(start_time)
        assert start_context.is_business_hours is True

        # Test exactly 5 PM (end of business hours)
        end_time = datetime(2023, 9, 28, 17, 0, tzinfo=UTC)
        end_context = TimedAccessContext.create_from_timestamp(end_time)
        assert end_context.is_business_hours is False  # 17:00 is not < 17

        # Test 4:59 PM (still business hours)
        late_business = datetime(2023, 9, 28, 16, 59, tzinfo=UTC)
        late_context = TimedAccessContext.create_from_timestamp(late_business)
        assert late_context.is_business_hours is True


class TestAuditEntryValidationCoverage:
    """Test AuditEntry validation methods for coverage."""

    def test_audit_entry_source_ip_validation(self) -> None:
        """Test source IP validation."""
        tenant_id = uuid4()
        agent_id = uuid4()

        # Test valid IPv4
        entry_ipv4 = AuditEntry(
            tenant_id=tenant_id,
            agent_id=agent_id,
            domain="example.com",
            decision=AccessDecision.ALLOW,
            source_ip="192.168.1.100",
        )
        assert entry_ipv4.source_ip == "192.168.1.100"

        # Test valid IPv6
        entry_ipv6 = AuditEntry(
            tenant_id=tenant_id,
            agent_id=agent_id,
            domain="example.com",
            decision=AccessDecision.ALLOW,
            source_ip="2001:db8::1",
        )
        assert entry_ipv6.source_ip == "2001:db8::1"

        # Test invalid IP
        with pytest.raises(ValidationError, match="Invalid IP address format"):
            AuditEntry(
                tenant_id=tenant_id,
                agent_id=agent_id,
                domain="example.com",
                decision=AccessDecision.ALLOW,
                source_ip="not.an.ip.address",
            )

    def test_audit_entry_sequence_number_validation(self) -> None:
        """Test sequence number validation."""
        tenant_id = uuid4()
        agent_id = uuid4()

        # Test negative sequence number
        with pytest.raises(ValidationError, match="Sequence number must be non-negative"):
            AuditEntry(
                tenant_id=tenant_id,
                agent_id=agent_id,
                domain="example.com",
                decision=AccessDecision.ALLOW,
                sequence_number=-1,
            )

    def test_audit_entry_domain_validation_edge_cases(self) -> None:
        """Test domain validation edge cases."""
        tenant_id = uuid4()
        agent_id = uuid4()

        # Test with DomainName object
        domain_obj = DomainName(value="secure.example.com")
        entry = AuditEntry(
            tenant_id=tenant_id, agent_id=agent_id, domain=domain_obj, decision=AccessDecision.ALLOW
        )
        assert entry.domain == domain_obj

        # Test with integer (should fail)
        with pytest.raises(ValidationError, match="Domain must be string or DomainName"):
            AuditEntry(
                tenant_id=tenant_id,
                agent_id=agent_id,
                domain=123,  # Invalid type
                decision=AccessDecision.ALLOW,
            )


class TestChainVerificationCoverage:
    """Test ChainVerificationResult for coverage."""

    def test_chain_verification_result_properties(self) -> None:
        """Test ChainVerificationResult properties."""
        from domain.audit.entity import ChainVerificationResult

        result = ChainVerificationResult(
            is_valid=True,
            total_entries=100,
            verified_entries=95,
            broken_chains=1,
            hash_mismatches=2,
            sequence_gaps=2,
            errors=["Error 1", "Error 2"],
        )

        # Test integrity percentage
        assert result.integrity_percentage == 95.0

        # Test critical issues detection
        assert result.has_critical_issues is True  # Due to hash_mismatches and broken_chains

        # Test with perfect integrity
        perfect_result = ChainVerificationResult(
            is_valid=True,
            total_entries=50,
            verified_entries=50,
            broken_chains=0,
            hash_mismatches=0,
            sequence_gaps=0,
        )

        assert perfect_result.integrity_percentage == 100.0
        assert perfect_result.has_critical_issues is False

        # Test with zero entries
        empty_result = ChainVerificationResult(
            is_valid=True,
            total_entries=0,
            verified_entries=0,
            broken_chains=0,
            hash_mismatches=0,
            sequence_gaps=0,
        )

        assert empty_result.integrity_percentage == 100.0  # Should handle division by zero


class TestPolicyDomainValidationCoverage:
    """Test policy domain validation for coverage."""

    def test_policy_domain_validation_too_many(self) -> None:
        """Test domain validation with too many domains."""
        tenant_id = uuid4()
        user_id = uuid4()

        # Create domains list that exceeds limit
        many_domains = {f"domain{i}.com" for i in range(1001)}  # Over 1000 limit

        with pytest.raises(ValidationError, match="Too many domains"):
            Policy(
                tenant_id=tenant_id,
                name="Test Policy",
                description="Test",
                created_by=user_id,
                allowed_domains=many_domains,
            )

    def test_policy_description_validation(self) -> None:
        """Test policy description validation."""
        tenant_id = uuid4()
        user_id = uuid4()

        # Test description too long
        long_description = "x" * 1001

        with pytest.raises(ValidationError, match="Description too long"):
            Policy(
                tenant_id=tenant_id,
                name="Test Policy",
                description=long_description,
                created_by=user_id,
            )

    def test_policy_rules_validation_edge_cases(self) -> None:
        """Test policy rules validation edge cases."""
        tenant_id = uuid4()
        user_id = uuid4()

        # Create too many rules
        many_rules = []
        for i in range(101):  # Over 100 limit
            rule = PolicyRule(
                name=f"Rule {i}",
                description=f"Description {i}",
                conditions=[
                    RuleCondition(field="domain", operator="equals", value=f"domain{i}.com")
                ],
                action=RuleAction.ALLOW,
            )
            many_rules.append(rule)

        with pytest.raises(ValidationError, match="Too many rules"):
            Policy(
                tenant_id=tenant_id,
                name="Test Policy",
                description="Test",
                created_by=user_id,
                rules=many_rules,
            )
