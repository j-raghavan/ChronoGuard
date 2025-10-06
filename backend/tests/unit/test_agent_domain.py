"""Unit tests for agent domain components."""

from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from domain.agent.entity import Agent, AgentStatus
from domain.agent.service import AgentService
from domain.common.exceptions import (
    BusinessRuleViolationError,
    DuplicateEntityError,
    EntityNotFoundError,
    InvalidStateTransitionError,
    ValidationError,
)
from domain.common.value_objects import X509Certificate


class TestAgent:
    """Unit tests for Agent entity."""

    def test_create_agent_with_valid_data(
        self, test_tenant_id: UUID, test_certificate: X509Certificate
    ) -> None:
        """Test creating an agent with valid data."""
        agent = Agent(
            tenant_id=test_tenant_id,
            name="Test Agent",
            certificate=test_certificate,
        )

        assert agent.tenant_id == test_tenant_id
        assert agent.name == "Test Agent"
        assert agent.certificate == test_certificate
        assert agent.status == AgentStatus.PENDING
        assert agent.policy_ids == []
        assert agent.version == 1

    def test_agent_name_validation_empty(
        self, test_tenant_id: UUID, test_certificate: X509Certificate
    ) -> None:
        """Test agent name validation with empty name."""
        with pytest.raises(ValidationError) as exc_info:
            Agent(
                tenant_id=test_tenant_id,
                name="",
                certificate=test_certificate,
            )

        assert "Agent name cannot be empty" in str(exc_info.value)

    def test_agent_name_validation_too_short(
        self, test_tenant_id: UUID, test_certificate: X509Certificate
    ) -> None:
        """Test agent name validation with too short name."""
        with pytest.raises(ValidationError) as exc_info:
            Agent(
                tenant_id=test_tenant_id,
                name="ab",
                certificate=test_certificate,
            )

        assert "Agent name too short" in str(exc_info.value)

    def test_agent_name_validation_too_long(
        self, test_tenant_id: UUID, test_certificate: X509Certificate
    ) -> None:
        """Test agent name validation with too long name."""
        long_name = "a" * 101

        with pytest.raises(ValidationError) as exc_info:
            Agent(
                tenant_id=test_tenant_id,
                name=long_name,
                certificate=test_certificate,
            )

        assert "Agent name too long" in str(exc_info.value)

    def test_agent_name_validation_invalid_characters(
        self, test_tenant_id: UUID, test_certificate: X509Certificate
    ) -> None:
        """Test agent name validation with invalid characters."""
        with pytest.raises(ValidationError) as exc_info:
            Agent(
                tenant_id=test_tenant_id,
                name="Agent@#$%",
                certificate=test_certificate,
            )

        assert "Agent name contains invalid characters" in str(exc_info.value)

    def test_agent_activate_from_pending(self, test_agent: Agent) -> None:
        """Test activating agent from pending status."""
        test_agent.activate()

        assert test_agent.status == AgentStatus.ACTIVE
        assert test_agent.version == 2

    def test_agent_activate_invalid_transition(self, test_agent: Agent) -> None:
        """Test invalid activation transition."""
        # First activate the agent so we can deactivate it
        test_agent.activate()
        # Then deactivate it
        test_agent.deactivate()

        # Now try to activate from deactivated state (should fail)
        with pytest.raises(InvalidStateTransitionError) as exc_info:
            test_agent.activate()

        assert "Invalid state transition" in str(exc_info.value)
        assert "deactivated" in str(exc_info.value).lower()
        assert "active" in str(exc_info.value).lower()

    def test_agent_suspend(self, test_agent: Agent) -> None:
        """Test suspending an active agent."""
        test_agent.activate()
        test_agent.suspend("Security violation")

        assert test_agent.status == AgentStatus.SUSPENDED
        assert test_agent.metadata["suspension_reason"] == "Security violation"
        assert "suspended_at" in test_agent.metadata

    def test_agent_suspend_with_invalid_status(self, test_agent: Agent) -> None:
        """Test suspending agent with invalid status."""
        with pytest.raises(InvalidStateTransitionError):
            test_agent.suspend()

    def test_agent_deactivate(self, test_agent: Agent) -> None:
        """Test deactivating an agent."""
        test_agent.activate()
        test_agent.deactivate("No longer needed")

        assert test_agent.status == AgentStatus.DEACTIVATED
        assert test_agent.metadata["deactivation_reason"] == "No longer needed"
        assert "deactivated_at" in test_agent.metadata

    def test_agent_mark_expired(self, test_agent: Agent) -> None:
        """Test marking agent as expired."""
        test_agent.activate()
        test_agent.mark_expired()

        assert test_agent.status == AgentStatus.EXPIRED
        assert test_agent.metadata["expiry_reason"] == "certificate_expired"
        assert "expired_at" in test_agent.metadata

    def test_agent_update_last_seen(self, test_agent: Agent) -> None:
        """Test updating last seen timestamp."""
        initial_version = test_agent.version
        test_agent.update_last_seen()

        assert test_agent.last_seen_at is not None
        assert test_agent.version == initial_version + 1

    def test_agent_assign_policy(self, test_agent: Agent) -> None:
        """Test assigning policy to agent."""
        policy_id = uuid4()
        test_agent.assign_policy(policy_id)

        assert policy_id in test_agent.policy_ids
        assert test_agent.version == 2

    def test_agent_assign_duplicate_policy(self, test_agent: Agent) -> None:
        """Test assigning duplicate policy to agent."""
        policy_id = uuid4()
        test_agent.assign_policy(policy_id)

        with pytest.raises(BusinessRuleViolationError) as exc_info:
            test_agent.assign_policy(policy_id)

        assert "already assigned" in str(exc_info.value)

    def test_agent_assign_too_many_policies(self, test_agent: Agent) -> None:
        """Test assigning too many policies to agent."""
        # Assign 50 policies (the limit)
        for _i in range(50):
            test_agent.assign_policy(uuid4())

        # Try to assign one more
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            test_agent.assign_policy(uuid4())

        assert "Cannot assign more than 50 policies" in str(exc_info.value)

    def test_agent_creation_with_duplicate_policy_ids(
        self, test_tenant_id: UUID, test_certificate: X509Certificate
    ) -> None:
        """Test agent creation removes duplicate policy IDs."""
        policy_id = uuid4()
        duplicate_policies = [policy_id, policy_id, uuid4()]

        agent = Agent(
            tenant_id=test_tenant_id,
            name="test-agent",
            certificate=test_certificate,
            policy_ids=duplicate_policies,
        )

        # Duplicates should be removed by validator
        assert len(agent.policy_ids) == 2
        assert agent.policy_ids.count(policy_id) == 1

    def test_agent_creation_with_too_many_policy_ids(
        self, test_tenant_id: UUID, test_certificate: X509Certificate
    ) -> None:
        """Test agent creation with too many policy IDs fails."""
        # Create 51 policies (exceeds 50 limit)
        too_many_policies = [uuid4() for _ in range(51)]

        with pytest.raises(ValidationError) as exc_info:
            Agent(
                tenant_id=test_tenant_id,
                name="test-agent",
                certificate=test_certificate,
                policy_ids=too_many_policies,
            )

        assert "Too many policies assigned" in str(exc_info.value)

    def test_agent_creation_with_invalid_version(
        self, test_tenant_id: UUID, test_certificate: X509Certificate
    ) -> None:
        """Test agent creation with invalid version."""
        with pytest.raises(ValidationError) as exc_info:
            Agent(
                tenant_id=test_tenant_id,
                name="test-agent",
                certificate=test_certificate,
                version=0,  # Invalid - must be >= 1
            )

        assert "Version must be positive" in str(exc_info.value)

    def test_agent_deactivate_invalid_state(
        self, test_tenant_id: UUID, test_certificate: X509Certificate
    ) -> None:
        """Test deactivating agent from invalid state."""
        agent = Agent(
            tenant_id=test_tenant_id,
            name="test-agent",
            certificate=test_certificate,
            status=AgentStatus.PENDING,
        )

        with pytest.raises(InvalidStateTransitionError) as exc_info:
            agent.deactivate()

        assert "Agent" in str(exc_info.value)

    def test_agent_mark_expired_invalid_state(
        self, test_tenant_id: UUID, test_certificate: X509Certificate
    ) -> None:
        """Test marking agent expired from invalid state."""
        agent = Agent(
            tenant_id=test_tenant_id,
            name="test-agent",
            certificate=test_certificate,
            status=AgentStatus.PENDING,
        )

        with pytest.raises(InvalidStateTransitionError) as exc_info:
            agent.mark_expired()

        assert "Agent" in str(exc_info.value)

    def test_agent_remove_policy(self, test_agent: Agent) -> None:
        """Test removing policy from agent."""
        policy_id = uuid4()
        test_agent.assign_policy(policy_id)
        test_agent.remove_policy(policy_id)

        assert policy_id not in test_agent.policy_ids

    def test_agent_remove_nonexistent_policy(self, test_agent: Agent) -> None:
        """Test removing non-existent policy from agent."""
        policy_id = uuid4()

        with pytest.raises(BusinessRuleViolationError) as exc_info:
            test_agent.remove_policy(policy_id)

        assert "not assigned" in str(exc_info.value)

    def test_agent_update_certificate(
        self, test_agent: Agent, test_certificate: X509Certificate
    ) -> None:
        """Test updating agent certificate."""
        old_fingerprint = test_agent.certificate.fingerprint_sha256
        test_agent.update_certificate(test_certificate)

        assert test_agent.certificate == test_certificate
        assert test_agent.metadata["previous_certificate_sha256"] == old_fingerprint
        assert "certificate_updated_at" in test_agent.metadata

    def test_agent_is_active(self, test_agent: Agent) -> None:
        """Test checking if agent is active."""
        assert test_agent.is_active() is False

        test_agent.activate()
        assert test_agent.is_active() is True

    def test_agent_can_make_requests(self, test_agent: Agent) -> None:
        """Test checking if agent can make requests."""
        # Pending agent cannot make requests
        assert test_agent.can_make_requests() is False

        # Active agent can make requests (if certificate is valid)
        test_agent.activate()
        assert test_agent.can_make_requests() is True

    def test_agent_string_representation(self, test_agent: Agent) -> None:
        """Test string representation of agent."""
        str_repr = str(test_agent)
        assert "Agent" in str_repr
        assert str(test_agent.agent_id) in str_repr
        assert test_agent.name in str_repr
        assert test_agent.status in str_repr

    def test_agent_detailed_representation(self, test_agent: Agent) -> None:
        """Test detailed representation of agent."""
        repr_str = repr(test_agent)
        assert "Agent" in repr_str
        assert str(test_agent.agent_id) in repr_str
        assert str(test_agent.tenant_id) in repr_str
        assert test_agent.name in repr_str


class TestAgentService:
    """Unit tests for AgentService."""

    @pytest.fixture
    def mock_repository(self) -> AsyncMock:
        """Mock agent repository."""
        return AsyncMock()

    @pytest.fixture
    def agent_service(self, mock_repository: AsyncMock) -> AgentService:
        """Agent service with mock repository."""
        return AgentService(mock_repository)

    async def test_create_agent_success(
        self,
        agent_service: AgentService,
        mock_repository: AsyncMock,
        test_tenant_id: UUID,
        test_certificate: X509Certificate,
    ) -> None:
        """Test successful agent creation."""
        # Setup mocks
        mock_repository.exists_by_name.return_value = False
        mock_repository.exists_by_certificate_fingerprint.return_value = False
        mock_repository.count_by_tenant.return_value = 10
        mock_repository.save.return_value = None

        # Create agent
        agent = await agent_service.create_agent(
            tenant_id=test_tenant_id,
            name="Test Agent",
            certificate=test_certificate,
        )

        # Verify agent properties
        assert agent.tenant_id == test_tenant_id
        assert agent.name == "Test Agent"
        assert agent.certificate == test_certificate
        assert agent.status == AgentStatus.PENDING

        # Verify repository calls
        mock_repository.exists_by_name.assert_called_once_with(test_tenant_id, "Test Agent")
        mock_repository.save.assert_called_once()

    async def test_create_agent_duplicate_name(
        self,
        agent_service: AgentService,
        mock_repository: AsyncMock,
        test_tenant_id: UUID,
        test_certificate: X509Certificate,
    ) -> None:
        """Test agent creation with duplicate name."""
        mock_repository.exists_by_name.return_value = True

        with pytest.raises(DuplicateEntityError) as exc_info:
            await agent_service.create_agent(
                tenant_id=test_tenant_id,
                name="Test Agent",
                certificate=test_certificate,
            )

        assert "Agent" in str(exc_info.value)
        assert "name" in str(exc_info.value)

    async def test_create_agent_duplicate_certificate(
        self,
        agent_service: AgentService,
        mock_repository: AsyncMock,
        test_tenant_id: UUID,
        test_certificate: X509Certificate,
    ) -> None:
        """Test agent creation with duplicate certificate."""
        mock_repository.exists_by_name.return_value = False
        mock_repository.exists_by_certificate_fingerprint.return_value = True

        with pytest.raises(DuplicateEntityError) as exc_info:
            await agent_service.create_agent(
                tenant_id=test_tenant_id,
                name="Test Agent",
                certificate=test_certificate,
            )

        assert "certificate_fingerprint" in str(exc_info.value)

    async def test_create_agent_tenant_limit_exceeded(
        self,
        agent_service: AgentService,
        mock_repository: AsyncMock,
        test_tenant_id: UUID,
        test_certificate: X509Certificate,
    ) -> None:
        """Test agent creation when tenant limit is exceeded."""
        mock_repository.exists_by_name.return_value = False
        mock_repository.exists_by_certificate_fingerprint.return_value = False
        mock_repository.count_by_tenant.return_value = 1000  # At limit

        with pytest.raises(BusinessRuleViolationError) as exc_info:
            await agent_service.create_agent(
                tenant_id=test_tenant_id,
                name="Test Agent",
                certificate=test_certificate,
            )

        assert "maximum agent limit" in str(exc_info.value)

    async def test_activate_agent_success(
        self,
        agent_service: AgentService,
        mock_repository: AsyncMock,
        test_agent: Agent,
    ) -> None:
        """Test successful agent activation."""
        mock_repository.find_by_id.return_value = test_agent
        mock_repository.save.return_value = None

        activated_agent = await agent_service.activate_agent(test_agent.agent_id)

        assert activated_agent.status == AgentStatus.ACTIVE
        mock_repository.save.assert_called_once()

    async def test_activate_agent_not_found(
        self,
        agent_service: AgentService,
        mock_repository: AsyncMock,
    ) -> None:
        """Test activating non-existent agent."""
        mock_repository.find_by_id.return_value = None

        with pytest.raises(EntityNotFoundError):
            await agent_service.activate_agent(uuid4())

    async def test_suspend_agent_success(
        self,
        agent_service: AgentService,
        mock_repository: AsyncMock,
        test_agent: Agent,
    ) -> None:
        """Test successful agent suspension."""
        test_agent.activate()  # Must be active to suspend
        mock_repository.find_by_id.return_value = test_agent
        mock_repository.save.return_value = None

        suspended_agent = await agent_service.suspend_agent(
            test_agent.agent_id, "Security violation"
        )

        assert suspended_agent.status == AgentStatus.SUSPENDED
        assert suspended_agent.metadata["suspension_reason"] == "Security violation"

    async def test_deactivate_agent_success(
        self,
        agent_service: AgentService,
        mock_repository: AsyncMock,
        test_agent: Agent,
    ) -> None:
        """Test successful agent deactivation."""
        test_agent.activate()  # Must be active to deactivate
        mock_repository.find_by_id.return_value = test_agent
        mock_repository.save.return_value = None

        deactivated_agent = await agent_service.deactivate_agent(
            test_agent.agent_id, "End of service"
        )

        assert deactivated_agent.status == AgentStatus.DEACTIVATED

    async def test_update_agent_certificate_success(
        self,
        agent_service: AgentService,
        mock_repository: AsyncMock,
        test_agent: Agent,
        test_certificate: X509Certificate,
    ) -> None:
        """Test updating agent certificate."""
        mock_repository.find_by_id.return_value = test_agent
        mock_repository.exists_by_certificate_fingerprint.return_value = False
        mock_repository.save.return_value = None

        updated_agent = await agent_service.update_agent_certificate(
            test_agent.agent_id, test_certificate
        )

        assert updated_agent.certificate == test_certificate

    async def test_update_agent_certificate_duplicate(
        self,
        agent_service: AgentService,
        mock_repository: AsyncMock,
        test_agent: Agent,
    ) -> None:
        """Test updating with duplicate certificate fails."""
        # Create a different certificate than the agent's current one
        from datetime import UTC, datetime, timedelta

        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.x509.oid import NameOID

        # Generate a new certificate
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "different.example.com")]
        )
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .sign(key, hashes.SHA256(), default_backend())
        )
        new_cert_pem = cert.public_bytes(Encoding.PEM).decode()
        new_cert = X509Certificate(pem_data=new_cert_pem)

        mock_repository.find_by_id.return_value = test_agent
        # Mock says this new cert fingerprint already exists
        mock_repository.exists_by_certificate_fingerprint.return_value = True

        with pytest.raises(DuplicateEntityError):
            await agent_service.update_agent_certificate(test_agent.agent_id, new_cert)

    async def test_assign_policy_to_agent(
        self,
        agent_service: AgentService,
        mock_repository: AsyncMock,
        test_agent: Agent,
    ) -> None:
        """Test assigning policy to agent."""
        policy_id = uuid4()
        mock_repository.find_by_id.return_value = test_agent
        mock_repository.save.return_value = None

        updated_agent = await agent_service.assign_policy_to_agent(test_agent.agent_id, policy_id)

        assert policy_id in updated_agent.policy_ids

    async def test_remove_policy_from_agent(
        self,
        agent_service: AgentService,
        mock_repository: AsyncMock,
        test_agent: Agent,
    ) -> None:
        """Test removing policy from agent."""
        policy_id = uuid4()
        test_agent.assign_policy(policy_id)

        mock_repository.find_by_id.return_value = test_agent
        mock_repository.save.return_value = None

        updated_agent = await agent_service.remove_policy_from_agent(test_agent.agent_id, policy_id)

        assert policy_id not in updated_agent.policy_ids

    async def test_update_agent_last_seen(
        self,
        agent_service: AgentService,
        mock_repository: AsyncMock,
        test_agent: Agent,
    ) -> None:
        """Test updating agent last seen timestamp."""
        mock_repository.find_by_id.return_value = test_agent
        mock_repository.save.return_value = None

        updated_agent = await agent_service.update_agent_last_seen(test_agent.agent_id)

        assert updated_agent.last_seen_at is not None

    async def test_get_tenant_agent_statistics(
        self,
        agent_service: AgentService,
        mock_repository: AsyncMock,
        test_tenant_id: UUID,
    ) -> None:
        """Test getting tenant agent statistics."""
        # Setup mock returns
        mock_repository.count_by_tenant.return_value = 10
        mock_repository.count_by_status.side_effect = [
            5,
            2,
            2,
            1,
            0,
        ]  # active, pending, suspended, deactivated, expired

        stats = await agent_service.get_tenant_agent_statistics(test_tenant_id)

        assert stats["total"] == 10
        assert stats["active"] == 5
        assert stats["pending"] == 2
        assert stats["suspended"] == 2
        assert stats["deactivated"] == 1
        assert stats["expired"] == 0

    async def test_find_inactive_agents_for_cleanup(
        self,
        agent_service: AgentService,
        mock_repository: AsyncMock,
    ) -> None:
        """Test finding inactive agents for cleanup."""
        # Create mock inactive agent instead of real certificate
        mock_inactive_agent = MagicMock()
        mock_inactive_agent.agent_id = uuid4()
        mock_inactive_agent.name = "Inactive"
        inactive_agents = [mock_inactive_agent]
        mock_repository.find_inactive_agents.return_value = inactive_agents

        result = await agent_service.find_inactive_agents_for_cleanup(30)

        assert len(result) == 1
        mock_repository.find_inactive_agents.assert_called_once()

    async def test_bulk_deactivate_agents(
        self,
        agent_service: AgentService,
        mock_repository: AsyncMock,
    ) -> None:
        """Test bulk deactivating agents."""
        agent_ids = [uuid4(), uuid4(), uuid4()]
        mock_repository.bulk_update_status.return_value = 3

        count = await agent_service.bulk_deactivate_agents(agent_ids, "Cleanup")

        assert count == 3
        mock_repository.bulk_update_status.assert_called_once_with(
            agent_ids, AgentStatus.DEACTIVATED
        )
