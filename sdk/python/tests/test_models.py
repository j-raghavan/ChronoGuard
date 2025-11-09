"""Tests for SDK models."""

from datetime import datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from chronoguard_sdk.models import (
    AuditExportRequest,
    AuditQueryRequest,
    CreateAgentRequest,
    CreatePolicyRequest,
    UpdateAgentRequest,
    UpdatePolicyRequest,
)


class TestAgentModels:
    """Tests for agent-related models."""

    def test_create_agent_request_valid(self):
        """Test creating valid agent request."""
        request = CreateAgentRequest(
            name="test-agent",
            certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            metadata={"env": "test"},
        )

        assert request.name == "test-agent"
        assert request.metadata["env"] == "test"

    def test_create_agent_request_strips_whitespace(self):
        """Test agent name whitespace is stripped."""
        request = CreateAgentRequest(
            name="  test-agent  ",
            certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        )

        assert request.name == "test-agent"

    def test_create_agent_request_invalid_name(self):
        """Test validation fails for empty name."""
        with pytest.raises(ValidationError):
            CreateAgentRequest(
                name="",
                certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            )

    def test_create_agent_request_invalid_certificate(self):
        """Test validation fails for invalid certificate."""
        with pytest.raises(ValidationError):
            CreateAgentRequest(
                name="test-agent",
                certificate_pem="invalid-cert",
            )

    def test_update_agent_request_partial(self):
        """Test updating agent with partial data."""
        request = UpdateAgentRequest(name="updated-name")

        assert request.name == "updated-name"
        assert request.certificate_pem is None
        assert request.metadata is None


class TestPolicyModels:
    """Tests for policy-related models."""

    def test_create_policy_request_valid(self):
        """Test creating valid policy request."""
        request = CreatePolicyRequest(
            name="test-policy",
            description="Test description",
            priority=500,
            allowed_domains=["example.com"],
            blocked_domains=["bad.com"],
            metadata={"env": "prod"},
        )

        assert request.name == "test-policy"
        assert request.priority == 500
        assert len(request.allowed_domains) == 1

    def test_create_policy_request_strips_whitespace(self):
        """Test policy name/description whitespace is stripped."""
        request = CreatePolicyRequest(
            name="  test-policy  ",
            description="  test desc  ",
        )

        assert request.name == "test-policy"
        assert request.description == "test desc"

    def test_create_policy_request_invalid_name(self):
        """Test validation fails for empty name."""
        with pytest.raises(ValidationError):
            CreatePolicyRequest(name="", description="Test")

    def test_create_policy_request_invalid_description(self):
        """Test validation fails for empty description."""
        with pytest.raises(ValidationError):
            CreatePolicyRequest(name="test", description="")

    def test_create_policy_request_invalid_priority(self):
        """Test validation fails for invalid priority."""
        with pytest.raises(ValidationError):
            CreatePolicyRequest(
                name="test",
                description="Test",
                priority=1001,  # Over max
            )

    def test_create_policy_request_too_many_domains(self):
        """Test validation fails for too many domains."""
        with pytest.raises(ValidationError):
            CreatePolicyRequest(
                name="test",
                description="Test",
                allowed_domains=[f"domain{i}.com" for i in range(1001)],  # Over limit
            )

    def test_update_policy_request_partial(self):
        """Test updating policy with partial data."""
        request = UpdatePolicyRequest(
            name="updated",
            priority=700,
        )

        assert request.name == "updated"
        assert request.priority == 700
        assert request.description is None


class TestAuditModels:
    """Tests for audit-related models."""

    def test_audit_query_request_valid(self):
        """Test creating valid audit query request."""
        from datetime import timedelta

        tenant_id = uuid4()
        now = datetime.utcnow()
        start_time = now - timedelta(hours=1)

        request = AuditQueryRequest(
            tenant_id=tenant_id,
            decision="allow",
            start_time=start_time,
            end_time=now,
            page=1,
            page_size=50,
        )

        assert request.tenant_id == tenant_id
        assert request.decision == "allow"

    def test_audit_query_request_normalizes_decision(self):
        """Test decision is normalized to lowercase."""
        request = AuditQueryRequest(
            tenant_id=uuid4(),
            decision="ALLOW",
        )

        assert request.decision == "allow"

    def test_audit_query_request_invalid_decision(self):
        """Test validation fails for invalid decision."""
        with pytest.raises(ValidationError):
            AuditQueryRequest(
                tenant_id=uuid4(),
                decision="invalid_decision",
            )

    def test_audit_export_request_valid(self):
        """Test creating valid export request."""
        from datetime import timedelta

        tenant_id = uuid4()
        now = datetime.utcnow()
        start = now - timedelta(days=7)

        request = AuditExportRequest(
            tenant_id=tenant_id,
            start_time=start,
            end_time=now,
            format="csv",
        )

        assert request.tenant_id == tenant_id
        assert request.format == "csv"

    def test_audit_export_request_invalid_format(self):
        """Test validation fails for invalid format."""
        now = datetime.utcnow()

        with pytest.raises(ValidationError):
            AuditExportRequest(
                tenant_id=uuid4(),
                start_time=now,
                end_time=now,
                format="xml",  # Invalid format
            )
