"""Comprehensive tests for agent domain exceptions."""

from uuid import uuid4

from domain.agent.exceptions import (
    AgentCertificateExistsError,
    AgentCertificateExpiredError,
    AgentError,
    AgentLimitExceededError,
    AgentNameExistsError,
    AgentNotFoundError,
    AgentPolicyLimitExceededError,
    RepositoryError,
)


class TestAgentError:
    """Test base AgentError class."""

    def test_agent_error_is_base_class(self) -> None:
        """Test that AgentError can be instantiated."""
        error = AgentError("Test agent error")
        assert str(error) == "Test agent error"


class TestAgentNotFoundError:
    """Test AgentNotFoundError exception."""

    def test_agent_not_found_error_creation(self) -> None:
        """Test creation of AgentNotFoundError."""
        agent_id = uuid4()
        error = AgentNotFoundError(agent_id)

        assert str(agent_id) in str(error)
        assert "not found" in str(error).lower()
        assert error.agent_id == agent_id
        assert error.error_code == "AGENT_NOT_FOUND"

    def test_agent_not_found_error_attributes(self) -> None:
        """Test AgentNotFoundError has correct attributes."""
        agent_id = uuid4()
        error = AgentNotFoundError(agent_id)

        assert hasattr(error, "agent_id")
        assert hasattr(error, "error_code")
        assert error.agent_id == agent_id


class TestAgentNameExistsError:
    """Test AgentNameExistsError exception."""

    def test_agent_name_exists_error_creation(self) -> None:
        """Test creation of AgentNameExistsError."""
        tenant_id = uuid4()
        name = "test-agent"
        error = AgentNameExistsError(tenant_id, name)

        assert str(tenant_id) in str(error)
        assert name in str(error)
        assert "already exists" in str(error).lower()
        assert error.tenant_id == tenant_id
        assert error.name == name
        assert error.error_code == "AGENT_NAME_EXISTS"

    def test_agent_name_exists_error_attributes(self) -> None:
        """Test AgentNameExistsError has correct attributes."""
        tenant_id = uuid4()
        error = AgentNameExistsError(tenant_id, "duplicate-agent")

        assert hasattr(error, "tenant_id")
        assert hasattr(error, "name")
        assert hasattr(error, "error_code")


class TestAgentCertificateExistsError:
    """Test AgentCertificateExistsError exception."""

    def test_agent_certificate_exists_error_creation(self) -> None:
        """Test creation of AgentCertificateExistsError."""
        fingerprint = "AA:BB:CC:DD:EE:FF"
        error = AgentCertificateExistsError(fingerprint)

        assert fingerprint in str(error)
        assert "already exists" in str(error).lower()
        assert error.fingerprint == fingerprint
        assert error.error_code == "AGENT_CERTIFICATE_EXISTS"

    def test_agent_certificate_exists_error_attributes(self) -> None:
        """Test AgentCertificateExistsError has correct attributes."""
        error = AgentCertificateExistsError("11:22:33:44:55:66")

        assert hasattr(error, "fingerprint")
        assert hasattr(error, "error_code")


class TestAgentCertificateExpiredError:
    """Test AgentCertificateExpiredError exception."""

    def test_agent_certificate_expired_error_creation(self) -> None:
        """Test creation of AgentCertificateExpiredError."""
        agent_id = uuid4()
        expiry_date = "2023-01-01"
        error = AgentCertificateExpiredError(agent_id, expiry_date)

        assert str(agent_id) in str(error)
        assert expiry_date in str(error)
        assert "expired" in str(error).lower()
        assert error.agent_id == agent_id
        assert error.expiry_date == expiry_date
        assert error.error_code == "AGENT_CERTIFICATE_EXPIRED"

    def test_agent_certificate_expired_error_attributes(self) -> None:
        """Test AgentCertificateExpiredError has correct attributes."""
        agent_id = uuid4()
        error = AgentCertificateExpiredError(agent_id, "2024-12-31")

        assert hasattr(error, "agent_id")
        assert hasattr(error, "expiry_date")
        assert hasattr(error, "error_code")


class TestAgentLimitExceededError:
    """Test AgentLimitExceededError exception."""

    def test_agent_limit_exceeded_error_creation(self) -> None:
        """Test creation of AgentLimitExceededError."""
        tenant_id = uuid4()
        current_count = 105
        max_allowed = 100
        error = AgentLimitExceededError(tenant_id, current_count, max_allowed)

        assert str(tenant_id) in str(error)
        assert str(current_count) in str(error)
        assert str(max_allowed) in str(error)
        assert "limit exceeded" in str(error).lower()
        assert error.tenant_id == tenant_id
        assert error.current_count == current_count
        assert error.max_allowed == max_allowed
        assert error.error_code == "AGENT_LIMIT_EXCEEDED"

    def test_agent_limit_exceeded_error_attributes(self) -> None:
        """Test AgentLimitExceededError has correct attributes."""
        tenant_id = uuid4()
        error = AgentLimitExceededError(tenant_id, 50, 25)

        assert hasattr(error, "tenant_id")
        assert hasattr(error, "current_count")
        assert hasattr(error, "max_allowed")
        assert hasattr(error, "error_code")


class TestAgentPolicyLimitExceededError:
    """Test AgentPolicyLimitExceededError exception."""

    def test_agent_policy_limit_exceeded_error_creation(self) -> None:
        """Test creation of AgentPolicyLimitExceededError."""
        agent_id = uuid4()
        current_count = 15
        max_allowed = 10
        error = AgentPolicyLimitExceededError(agent_id, current_count, max_allowed)

        assert str(agent_id) in str(error)
        assert str(current_count) in str(error)
        assert str(max_allowed) in str(error)
        assert "policy limit exceeded" in str(error).lower()
        assert error.agent_id == agent_id
        assert error.current_count == current_count
        assert error.max_allowed == max_allowed
        assert error.error_code == "AGENT_POLICY_LIMIT_EXCEEDED"

    def test_agent_policy_limit_exceeded_error_attributes(self) -> None:
        """Test AgentPolicyLimitExceededError has correct attributes."""
        agent_id = uuid4()
        error = AgentPolicyLimitExceededError(agent_id, 8, 5)

        assert hasattr(error, "agent_id")
        assert hasattr(error, "current_count")
        assert hasattr(error, "max_allowed")
        assert hasattr(error, "error_code")


class TestRepositoryError:
    """Test RepositoryError exception."""

    def test_repository_error_creation(self) -> None:
        """Test creation of RepositoryError."""
        message = "Database connection failed"
        operation = "save"
        error = RepositoryError(message, operation)

        assert message in str(error)
        assert error.operation == operation
        assert error.error_code == "REPOSITORY_ERROR"

    def test_repository_error_attributes(self) -> None:
        """Test RepositoryError has correct attributes."""
        error = RepositoryError("Test error", "delete")

        assert hasattr(error, "operation")
        assert hasattr(error, "error_code")
        assert error.operation == "delete"
