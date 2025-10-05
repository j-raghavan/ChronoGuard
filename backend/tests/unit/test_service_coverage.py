"""Tests for domain services to dramatically improve coverage."""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from domain.agent.service import AgentService
from domain.audit.service import AuditService
from domain.common.exceptions import (
    BusinessRuleViolationError,
    EntityNotFoundError,
    ValidationError,
)
from domain.policy.service import AccessRequest, PolicyEvaluationResult, PolicyService


class TestAgentServiceCoverage:
    """Test AgentService methods for coverage."""

    @pytest.fixture
    def mock_repository(self) -> AsyncMock:
        """Mock agent repository."""
        return AsyncMock()

    @pytest.fixture
    def agent_service(self, mock_repository: AsyncMock) -> AgentService:
        """AgentService with mock repository."""
        return AgentService(mock_repository)

    async def test_create_agent_expired_certificate(
        self, agent_service: AgentService, mock_repository: AsyncMock
    ) -> None:
        """Test creating agent with expired certificate."""
        from domain.common.value_objects import X509Certificate

        # Mock certificate that appears expired
        mock_cert = MagicMock(spec=X509Certificate)
        mock_cert.is_valid_now = False
        mock_cert.not_valid_after.isoformat.return_value = "2023-01-01T00:00:00Z"
        mock_cert.fingerprint_sha256 = "test_fingerprint"

        mock_repository.exists_by_name.return_value = False
        mock_repository.exists_by_certificate_fingerprint.return_value = False
        mock_repository.count_by_tenant.return_value = 10

        with pytest.raises(
            BusinessRuleViolationError, match="Cannot create agent with expired certificate"
        ):
            await agent_service.create_agent(
                tenant_id=uuid4(), name="Test Agent", certificate=mock_cert
            )

    async def test_activate_agent_expired_certificate(
        self, agent_service: AgentService, mock_repository: AsyncMock
    ) -> None:
        """Test activating agent with expired certificate."""
        # Mock agent with expired certificate
        mock_agent = MagicMock()
        mock_agent.agent_id = uuid4()
        mock_agent.is_certificate_expired.return_value = True
        mock_agent.certificate.not_valid_after.isoformat.return_value = "2023-01-01T00:00:00Z"

        mock_repository.find_by_id.return_value = mock_agent

        with pytest.raises(
            BusinessRuleViolationError, match="Cannot activate agent with expired certificate"
        ):
            await agent_service.activate_agent(mock_agent.agent_id)

    async def test_check_and_expire_certificates(
        self, agent_service: AgentService, mock_repository: AsyncMock
    ) -> None:
        """Test certificate expiry checking process."""
        from domain.agent.entity import AgentStatus

        # Mock agents with expired certificates
        mock_agent1 = MagicMock()
        mock_agent1.status = AgentStatus.ACTIVE
        mock_agent1.mark_expired = MagicMock()

        mock_agent2 = MagicMock()
        mock_agent2.status = AgentStatus.SUSPENDED
        mock_agent2.mark_expired = MagicMock()

        mock_agent3 = MagicMock()
        mock_agent3.status = AgentStatus.DEACTIVATED  # Should not be expired

        mock_repository.find_expired_certificates.return_value = [
            mock_agent1,
            mock_agent2,
            mock_agent3,
        ]
        mock_repository.save.return_value = None

        result = await agent_service.check_and_expire_certificates()

        # Should expire active and suspended agents only
        assert len(result) == 2
        mock_agent1.mark_expired.assert_called_once()
        mock_agent2.mark_expired.assert_called_once()
        assert not mock_agent3.mark_expired.called


class TestPolicyServiceCoverage:
    """Test PolicyService methods for coverage."""

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
        """PolicyService with mock repositories."""
        return PolicyService(mock_policy_repository, mock_agent_repository)

    async def test_create_policy_priority_conflict(
        self,
        policy_service: PolicyService,
        mock_policy_repository: AsyncMock,
    ) -> None:
        """Test creating policy with priority conflict."""
        tenant_id = uuid4()

        mock_policy_repository.exists_by_name.return_value = False
        mock_policy_repository.count_by_tenant.return_value = 10

        # Mock existing policies with same priority
        mock_existing_policy = MagicMock()
        mock_existing_policy.policy_id = uuid4()
        mock_policy_repository.find_duplicate_priority.return_value = [mock_existing_policy]

        with pytest.raises(BusinessRuleViolationError, match="Policy priority .* already in use"):
            await policy_service.create_policy(
                tenant_id=tenant_id,
                name="Test Policy",
                description="Test",
                created_by=uuid4(),
                priority=500,
            )

    async def test_archive_policy_with_agent_references(
        self,
        policy_service: PolicyService,
        mock_policy_repository: AsyncMock,
        mock_agent_repository: AsyncMock,
    ) -> None:
        """Test archiving policy that's referenced by agents."""
        policy_id = uuid4()
        tenant_id = uuid4()

        mock_policy = MagicMock()
        mock_policy.policy_id = policy_id
        mock_policy.tenant_id = tenant_id

        mock_policy_repository.find_by_id.return_value = mock_policy

        # Mock agents referencing this policy
        mock_agent = MagicMock()
        mock_agent_repository.find_with_policy.return_value = [mock_agent]

        with pytest.raises(
            BusinessRuleViolationError, match="Cannot archive policy referenced by .* agents"
        ):
            await policy_service.archive_policy(policy_id)

    async def test_evaluate_access_request_no_tenant(self, policy_service: PolicyService) -> None:
        """Test access request evaluation without tenant."""
        request = AccessRequest(
            domain="example.com",
            method="GET",
            tenant_id=None,  # Missing tenant
        )

        with pytest.raises(
            BusinessRuleViolationError, match="Cannot evaluate request without tenant context"
        ):
            await policy_service.evaluate_access_request(request)

    async def test_evaluate_access_request_default_deny(
        self,
        policy_service: PolicyService,
        mock_policy_repository: AsyncMock,
    ) -> None:
        """Test access request evaluation with no policies (default deny)."""
        request = AccessRequest(domain="example.com", method="GET", tenant_id=uuid4())

        mock_policy_repository.find_policies_for_evaluation.return_value = []

        result = await policy_service.evaluate_access_request(request)

        assert isinstance(result, PolicyEvaluationResult)
        assert result.allowed is False
        assert "No policies found" in result.reason

    async def test_add_rule_to_active_policy(
        self,
        policy_service: PolicyService,
        mock_policy_repository: AsyncMock,
    ) -> None:
        """Test adding rule to active policy (should fail)."""
        from domain.policy.entity import PolicyRule, PolicyStatus, RuleAction, RuleCondition

        policy_id = uuid4()
        mock_policy = MagicMock()
        mock_policy.policy_id = policy_id
        mock_policy.status = PolicyStatus.ACTIVE

        mock_policy_repository.find_by_id.return_value = mock_policy

        rule = PolicyRule(
            name="Test Rule",
            description="Test",
            conditions=[RuleCondition(field="domain", operator="equals", value="example.com")],
            action=RuleAction.ALLOW,
        )

        with pytest.raises(BusinessRuleViolationError, match="Cannot modify active policy rules"):
            await policy_service.add_rule_to_policy(policy_id, rule)

    async def test_bulk_archive_policies(
        self,
        policy_service: PolicyService,
        mock_policy_repository: AsyncMock,
    ) -> None:
        """Test bulk archiving policies."""
        policy_ids = [uuid4(), uuid4(), uuid4()]
        mock_policy_repository.bulk_update_status.return_value = 3

        result = await policy_service.bulk_archive_policies(policy_ids)

        assert result == 3
        mock_policy_repository.bulk_update_status.assert_called_once()

    async def test_search_policies(
        self,
        policy_service: PolicyService,
        mock_policy_repository: AsyncMock,
    ) -> None:
        """Test searching policies."""
        tenant_id = uuid4()
        mock_policies = [MagicMock(), MagicMock()]
        mock_policy_repository.search_policies.return_value = mock_policies

        result = await policy_service.search_policies(
            tenant_id=tenant_id, search_term="test", status_filter=None, limit=50
        )

        assert result == mock_policies
        mock_policy_repository.search_policies.assert_called_once_with(tenant_id, "test", None, 50)


class TestAuditServiceCoverage:
    """Test AuditService methods for coverage."""

    @pytest.fixture
    def mock_repository(self) -> AsyncMock:
        """Mock audit repository."""
        return AsyncMock()

    @pytest.fixture
    def audit_service(self, mock_repository: AsyncMock) -> AuditService:
        """AuditService with mock repository."""
        return AuditService(mock_repository, b"test_secret_key")

    async def test_record_access_with_previous_entry(
        self,
        audit_service: AuditService,
        mock_repository: AsyncMock,
    ) -> None:
        """Test recording access with previous entry for chaining."""
        from domain.audit.entity import AccessDecision, AuditEntry
        from domain.audit.service import AccessRequest

        # Mock previous entry
        mock_previous_entry = MagicMock(spec=AuditEntry)
        mock_previous_entry.current_hash = "previous_hash_123"

        mock_repository.get_latest_entry_for_agent.return_value = mock_previous_entry
        mock_repository.get_next_sequence_number.return_value = 2
        mock_repository.save.return_value = None

        request = AccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="example.com",
            decision=AccessDecision.ALLOW,
            reason="Test access",
        )

        result = await audit_service.record_access(request)

        assert result.sequence_number == 2
        assert result.previous_hash == "previous_hash_123"

    async def test_detect_chain_tampering(
        self,
        audit_service: AuditService,
        mock_repository: AsyncMock,
    ) -> None:
        """Test chain tampering detection."""
        tenant_id = uuid4()
        agent_id = uuid4()

        # Mock sequence gaps
        mock_repository.find_chain_gaps.return_value = [(5, 7), (10, 12)]

        # Mock invalid verification
        mock_verification = MagicMock()
        mock_verification.is_valid = False
        mock_verification.errors = ["Hash mismatch at sequence 15"]
        mock_repository.verify_chain_integrity.return_value = mock_verification

        # Mock time anomalies
        audit_service._detect_time_anomalies = AsyncMock(return_value=["Large time gap detected"])

        indicators = await audit_service.detect_chain_tampering(tenant_id, agent_id)

        assert len(indicators) >= 3  # Gaps + verification errors + time anomalies
        assert any("gaps detected" in indicator for indicator in indicators)
        assert any("Hash mismatch" in indicator for indicator in indicators)

    async def test_cleanup_old_audit_logs_retention_violation(
        self, audit_service: AuditService
    ) -> None:
        """Test cleanup with insufficient retention period."""
        tenant_id = uuid4()

        with pytest.raises(BusinessRuleViolationError, match="Minimum retention period is 30 days"):
            await audit_service.cleanup_old_audit_logs(
                tenant_id=tenant_id,
                retention_days=15,  # Below minimum
            )

    async def test_export_audit_logs_invalid_format(self, audit_service: AuditService) -> None:
        """Test export with invalid format."""
        from domain.common.exceptions import ValidationError

        tenant_id = uuid4()
        start_time = datetime.now()
        end_time = datetime.now()

        with pytest.raises(ValidationError, match="Unsupported export format"):
            await audit_service.export_audit_logs(
                tenant_id=tenant_id,
                start_time=start_time,
                end_time=end_time,
                export_format="xml",  # Invalid format
            )

    async def test_find_security_incidents(
        self,
        audit_service: AuditService,
        mock_repository: AsyncMock,
    ) -> None:
        """Test finding security incidents."""
        tenant_id = uuid4()

        # Mock suspicious patterns
        mock_patterns = [
            {
                "failed_attempts": 25,
                "unique_domains": 15,
                "off_hours_percentage": 60,
                "description": "Suspicious access pattern",
            }
        ]
        mock_repository.find_suspicious_patterns.return_value = mock_patterns

        incidents = await audit_service.find_security_incidents(tenant_id, 24, "medium")

        assert len(incidents) >= 1
        incident = incidents[0]
        assert incident["type"] == "suspicious_access_pattern"
        assert incident["severity"] in ["low", "medium", "high", "critical"]

    def test_calculate_incident_severity(self, audit_service: AuditService) -> None:
        """Test incident severity calculation."""
        # Test high severity pattern
        high_pattern = {"failed_attempts": 60, "unique_domains": 25, "off_hours_percentage": 85}
        severity = audit_service._calculate_incident_severity(high_pattern)
        assert severity in ["critical", "high"]

        # Test low severity pattern
        low_pattern = {"failed_attempts": 5, "unique_domains": 2, "off_hours_percentage": 10}
        severity = audit_service._calculate_incident_severity(low_pattern)
        assert severity in ["low", "medium"]

    def test_meets_severity_threshold(self, audit_service: AuditService) -> None:
        """Test severity threshold checking."""
        assert audit_service._meets_severity_threshold("high", "medium") is True
        assert audit_service._meets_severity_threshold("low", "high") is False
        assert audit_service._meets_severity_threshold("critical", "critical") is True

    def test_entry_to_csv_dict(self, audit_service: AuditService) -> None:
        """Test audit entry CSV conversion."""
        from domain.audit.entity import AuditEntry

        # Create a minimal audit entry for testing
        entry = MagicMock(spec=AuditEntry)
        entry.entry_id = uuid4()
        entry.tenant_id = uuid4()
        entry.agent_id = uuid4()

        # Mock timestamp with isoformat method
        mock_timestamp = MagicMock()
        mock_timestamp.isoformat.return_value = "2023-09-28T10:00:00Z"
        entry.timestamp = mock_timestamp

        # Mock domain with value attribute
        mock_domain = MagicMock()
        mock_domain.value = "example.com"
        entry.domain = mock_domain

        # Mock decision with value attribute
        mock_decision = MagicMock()
        mock_decision.value = "allow"
        entry.decision = mock_decision

        entry.reason = "Test access"
        entry.request_method = "GET"
        entry.request_path = "/"
        entry.source_ip = "192.168.1.100"
        entry.user_agent = "TestAgent/1.0"
        entry.response_status = 200
        entry.processing_time_ms = 50.5
        entry.sequence_number = 1
        entry.get_risk_score.return_value = 10

        csv_dict = audit_service._entry_to_csv_dict(entry)

        assert isinstance(csv_dict, dict)
        assert csv_dict["domain"] == "example.com"
        assert csv_dict["decision"] == "allow"
        assert csv_dict["risk_score"] == "10"


class TestPolicyEvaluationCoverage:
    """Test policy evaluation logic for coverage."""

    def test_policy_evaluation_result_creation(self) -> None:
        """Test PolicyEvaluationResult creation."""
        policy_id = uuid4()
        rule_id = uuid4()

        result = PolicyEvaluationResult(
            allowed=True,
            policy_id=policy_id,
            rule_id=rule_id,
            reason="Policy matched",
            rate_limit_info={"requests_remaining": 50},
        )

        assert result.allowed is True
        assert result.policy_id == policy_id
        assert result.rule_id == rule_id
        assert result.reason == "Policy matched"
        assert result.rate_limit_info["requests_remaining"] == 50

    def test_access_request_creation(self) -> None:
        """Test AccessRequest creation with all parameters."""
        tenant_id = uuid4()
        agent_id = uuid4()
        timestamp = datetime.now()

        request = AccessRequest(
            domain="api.example.com",
            method="POST",
            path="/api/v1/users",
            user_agent="TestClient/1.0",
            source_ip="10.0.0.1",
            timestamp=timestamp,
            agent_id=agent_id,
            tenant_id=tenant_id,
            additional_context={"version": "1.0"},
        )

        assert request.domain == "api.example.com"
        assert request.method == "POST"
        assert request.path == "/api/v1/users"
        assert request.user_agent == "TestClient/1.0"
        assert request.source_ip == "10.0.0.1"
        assert request.timestamp == timestamp
        assert request.agent_id == agent_id
        assert request.tenant_id == tenant_id
        assert request.additional_context == {"version": "1.0"}


class TestServiceErrorHandling:
    """Test service error handling for coverage."""

    async def test_agent_service_get_agent_or_raise(self) -> None:
        """Test _get_agent_or_raise method."""
        mock_repository = AsyncMock()
        mock_repository.find_by_id.return_value = None

        service = AgentService(mock_repository)
        agent_id = uuid4()

        with pytest.raises(EntityNotFoundError):
            await service._get_agent_or_raise(agent_id)

    async def test_policy_service_get_policy_or_raise(self) -> None:
        """Test _get_policy_or_raise method."""
        mock_repository = AsyncMock()
        mock_repository.find_by_id.return_value = None

        service = PolicyService(mock_repository)
        policy_id = uuid4()

        with pytest.raises(EntityNotFoundError):
            await service._get_policy_or_raise(policy_id)

    def test_audit_service_validate_access_request_errors(self) -> None:
        """Test audit service request validation errors."""
        from domain.audit.entity import AccessDecision
        from domain.audit.service import AccessRequest

        service = AuditService(AsyncMock(), b"secret")

        # Test empty domain
        request = AccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="",  # Empty domain
            decision=AccessDecision.ALLOW,
        )

        with pytest.raises(ValidationError, match="Domain is required"):
            service._validate_access_request(request)

        # Test reason too long
        request2 = AccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="example.com",
            decision=AccessDecision.ALLOW,
            reason="x" * 501,  # Too long
        )

        with pytest.raises(ValidationError, match="Reason too long"):
            service._validate_access_request(request2)

        # Test future timestamp
        from datetime import UTC

        future_time = datetime.now(UTC).replace(hour=23, minute=59)  # Far future
        request3 = AccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="example.com",
            decision=AccessDecision.ALLOW,
            timestamp=datetime(2030, 1, 1, tzinfo=UTC),  # Far future
        )

        with pytest.raises(
            ValidationError, match="Timestamp cannot be more than 5 minutes in the future"
        ):
            service._validate_access_request(request3)
