"""Tests for Command Audit Side Effects."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, call
from uuid import UUID, uuid4

import pytest
from application.commands import (
    CreateAgentCommand,
    CreatePolicyCommand,
    DeletePolicyCommand,
    UpdateAgentCommand,
    UpdatePolicyCommand,
)
from application.dto import (
    CreateAgentRequest,
    CreatePolicyRequest,
    UpdateAgentRequest,
    UpdatePolicyRequest,
)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID
from domain.agent.entity import Agent, AgentStatus
from domain.agent.service import AgentService
from domain.audit.entity import AccessDecision
from domain.audit.service import AuditService
from domain.common.value_objects import X509Certificate
from domain.policy.entity import Policy, PolicyStatus
from domain.policy.service import PolicyService


class TestCreateAgentAuditSideEffects:
    """Test CreateAgentCommand audit side effects."""

    @pytest.fixture
    def agent_service(self) -> AsyncMock:
        """Mock agent service."""
        return AsyncMock(spec=AgentService)

    @pytest.fixture
    def audit_service(self) -> AsyncMock:
        """Mock audit service."""
        from unittest.mock import MagicMock

        mock = MagicMock(spec=AuditService)
        mock.record_access = AsyncMock()
        return mock

    @pytest.fixture
    def command(self, agent_service: AsyncMock, audit_service: AsyncMock) -> CreateAgentCommand:
        """Create command instance with audit service."""
        return CreateAgentCommand(agent_service, audit_service=audit_service)

    @pytest.fixture
    def rsa_private_key(self) -> RSAPrivateKey:
        """Generate RSA private key."""
        return rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    @pytest.fixture
    def valid_cert_pem(self, rsa_private_key: RSAPrivateKey) -> str:
        """Generate valid certificate PEM."""
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ChronoGuard"),
                x509.NameAttribute(NameOID.COMMON_NAME, "test-agent"),
            ]
        )

        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(rsa_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .sign(rsa_private_key, hashes.SHA256(), default_backend())
        )

        return cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")

    @pytest.mark.asyncio
    async def test_create_agent_creates_audit_entry(
        self,
        command: CreateAgentCommand,
        agent_service: AsyncMock,
        audit_service: AsyncMock,
        valid_cert_pem: str,
    ) -> None:
        """Test that agent creation creates audit entry."""
        tenant_id = uuid4()
        request = CreateAgentRequest(name="test-agent", certificate_pem=valid_cert_pem)

        # Mock service response
        created_agent = Agent(
            agent_id=uuid4(),
            tenant_id=tenant_id,
            name="test-agent",
            certificate=X509Certificate(pem_data=valid_cert_pem),
            status=AgentStatus.PENDING,
        )
        agent_service.create_agent.return_value = created_agent

        # Execute command
        result = await command.execute(request, tenant_id)

        # Verify audit entry was created
        audit_service.record_access.assert_called_once()
        audit_call = audit_service.record_access.call_args[0][0]

        assert audit_call.tenant_id == created_agent.tenant_id
        assert audit_call.agent_id == created_agent.agent_id
        assert audit_call.domain == "system"
        assert audit_call.decision == AccessDecision.ALLOW
        assert "Agent created" in audit_call.reason
        assert audit_call.request_method == "SYSTEM"
        assert audit_call.request_path == "/agents/create"
        assert audit_call.metadata["operation"] == "create_agent"
        assert audit_call.metadata["agent_name"] == "test-agent"

    @pytest.mark.asyncio
    async def test_create_agent_audit_failure_does_not_fail_command(
        self,
        command: CreateAgentCommand,
        agent_service: AsyncMock,
        audit_service: AsyncMock,
        valid_cert_pem: str,
    ) -> None:
        """Test that audit failure doesn't fail the command."""
        tenant_id = uuid4()
        request = CreateAgentRequest(name="test-agent", certificate_pem=valid_cert_pem)

        # Mock service response
        created_agent = Agent(
            agent_id=uuid4(),
            tenant_id=tenant_id,
            name="test-agent",
            certificate=X509Certificate(pem_data=valid_cert_pem),
            status=AgentStatus.PENDING,
        )
        agent_service.create_agent.return_value = created_agent

        # Mock audit service to fail
        audit_service.record_access.side_effect = Exception("Audit database error")

        # Execute command - should succeed despite audit failure
        result = await command.execute(request, tenant_id)

        # Verify command succeeded
        assert result.name == "test-agent"
        audit_service.record_access.assert_called_once()


class TestUpdateAgentAuditSideEffects:
    """Test UpdateAgentCommand audit side effects."""

    @pytest.fixture
    def agent_repository(self) -> AsyncMock:
        """Mock agent repository."""
        from domain.agent.repository import AgentRepository

        return AsyncMock(spec=AgentRepository)

    @pytest.fixture
    def audit_service(self) -> AsyncMock:
        """Mock audit service."""
        from unittest.mock import MagicMock

        mock = MagicMock(spec=AuditService)
        mock.record_access = AsyncMock()
        return mock

    @pytest.fixture
    def command(self, agent_repository: AsyncMock, audit_service: AsyncMock) -> UpdateAgentCommand:
        """Create command instance with audit service."""
        return UpdateAgentCommand(agent_repository, audit_service=audit_service)

    @pytest.fixture
    def rsa_private_key(self) -> RSAPrivateKey:
        """Generate RSA private key."""
        return rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    @pytest.fixture
    def valid_cert_pem(self, rsa_private_key: RSAPrivateKey) -> str:
        """Generate valid certificate PEM."""
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ChronoGuard"),
                x509.NameAttribute(NameOID.COMMON_NAME, "test-agent"),
            ]
        )

        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(rsa_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .sign(rsa_private_key, hashes.SHA256(), default_backend())
        )

        return cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")

    @pytest.mark.asyncio
    async def test_update_agent_creates_audit_entry(
        self,
        command: UpdateAgentCommand,
        agent_repository: AsyncMock,
        audit_service: AsyncMock,
        valid_cert_pem: str,
    ) -> None:
        """Test that agent update creates audit entry."""
        agent_id = uuid4()
        tenant_id = uuid4()
        request = UpdateAgentRequest(name="updated-agent")

        # Mock repository
        existing_agent = Agent(
            agent_id=agent_id,
            tenant_id=tenant_id,
            name="old-agent",
            certificate=X509Certificate(pem_data=valid_cert_pem),
        )
        agent_repository.find_by_id.return_value = existing_agent

        # Execute
        result = await command.execute(agent_id, tenant_id, request)

        # Verify audit entry was created
        audit_service.record_access.assert_called_once()
        audit_call = audit_service.record_access.call_args[0][0]

        assert audit_call.tenant_id == tenant_id
        assert audit_call.agent_id == agent_id
        assert audit_call.domain == "system"
        assert audit_call.decision == AccessDecision.ALLOW
        assert "Agent updated" in audit_call.reason
        assert audit_call.request_path == "/agents/update"
        assert audit_call.metadata["operation"] == "update_agent"
        assert "name" in audit_call.metadata["changes"]

    @pytest.mark.asyncio
    async def test_update_agent_audit_failure_does_not_fail_command(
        self,
        command: UpdateAgentCommand,
        agent_repository: AsyncMock,
        audit_service: AsyncMock,
        valid_cert_pem: str,
    ) -> None:
        """Test that audit failure doesn't fail the command."""
        agent_id = uuid4()
        tenant_id = uuid4()
        request = UpdateAgentRequest(name="updated-agent")

        # Mock repository
        existing_agent = Agent(
            agent_id=agent_id,
            tenant_id=tenant_id,
            name="old-agent",
            certificate=X509Certificate(pem_data=valid_cert_pem),
        )
        agent_repository.find_by_id.return_value = existing_agent

        # Mock audit service to fail
        audit_service.record_access.side_effect = Exception("Audit database error")

        # Execute - should succeed despite audit failure
        result = await command.execute(agent_id, tenant_id, request)

        # Verify command succeeded
        assert result.name == "updated-agent"
        audit_service.record_access.assert_called_once()


class TestCreatePolicyAuditSideEffects:
    """Test CreatePolicyCommand audit side effects."""

    @pytest.fixture
    def policy_service(self) -> AsyncMock:
        """Mock policy service."""
        return AsyncMock(spec=PolicyService)

    @pytest.fixture
    def audit_service(self) -> AsyncMock:
        """Mock audit service."""
        from unittest.mock import MagicMock

        mock = MagicMock(spec=AuditService)
        mock.record_access = AsyncMock()
        return mock

    @pytest.fixture
    def command(self, policy_service: AsyncMock, audit_service: AsyncMock) -> CreatePolicyCommand:
        """Create command instance with audit service."""
        return CreatePolicyCommand(
            policy_service, opa_client=None, policy_compiler=None, audit_service=audit_service
        )

    @pytest.mark.asyncio
    async def test_create_policy_creates_audit_entry(
        self,
        command: CreatePolicyCommand,
        policy_service: AsyncMock,
        audit_service: AsyncMock,
    ) -> None:
        """Test that policy creation creates audit entry."""
        tenant_id = uuid4()
        created_by = uuid4()
        request = CreatePolicyRequest(name="test-policy", description="Test")

        # Mock service response
        created_policy = Policy(
            policy_id=uuid4(),
            tenant_id=tenant_id,
            name="test-policy",
            description="Test",
            created_by=created_by,
        )
        policy_service.create_policy.return_value = created_policy
        policy_service._policy_repository = AsyncMock()

        # Execute command
        result = await command.execute(request, tenant_id, created_by)

        # Verify audit entry was created
        audit_service.record_access.assert_called_once()
        audit_call = audit_service.record_access.call_args[0][0]

        assert audit_call.tenant_id == tenant_id
        assert audit_call.agent_id == UUID("00000000-0000-0000-0000-000000000000")
        assert audit_call.domain == "system"
        assert audit_call.decision == AccessDecision.ALLOW
        assert "Policy created" in audit_call.reason
        assert audit_call.request_path == "/policies/create"
        assert audit_call.metadata["operation"] == "create_policy"
        assert audit_call.metadata["policy_name"] == "test-policy"

    @pytest.mark.asyncio
    async def test_create_policy_audit_failure_does_not_fail_command(
        self,
        command: CreatePolicyCommand,
        policy_service: AsyncMock,
        audit_service: AsyncMock,
    ) -> None:
        """Test that audit failure doesn't fail the command."""
        tenant_id = uuid4()
        created_by = uuid4()
        request = CreatePolicyRequest(name="test-policy", description="Test")

        # Mock service response
        created_policy = Policy(
            policy_id=uuid4(),
            tenant_id=tenant_id,
            name="test-policy",
            description="Test",
            created_by=created_by,
        )
        policy_service.create_policy.return_value = created_policy
        policy_service._policy_repository = AsyncMock()

        # Mock audit service to fail
        audit_service.record_access.side_effect = Exception("Audit database error")

        # Execute - should succeed despite audit failure
        result = await command.execute(request, tenant_id, created_by)

        # Verify command succeeded
        assert result.name == "test-policy"
        audit_service.record_access.assert_called_once()


class TestUpdatePolicyAuditSideEffects:
    """Test UpdatePolicyCommand audit side effects."""

    @pytest.fixture
    def policy_repository(self) -> AsyncMock:
        """Mock policy repository."""
        from domain.policy.repository import PolicyRepository

        return AsyncMock(spec=PolicyRepository)

    @pytest.fixture
    def audit_service(self) -> AsyncMock:
        """Mock audit service."""
        from unittest.mock import MagicMock

        mock = MagicMock(spec=AuditService)
        mock.record_access = AsyncMock()
        return mock

    @pytest.fixture
    def command(
        self, policy_repository: AsyncMock, audit_service: AsyncMock
    ) -> UpdatePolicyCommand:
        """Create command instance with audit service."""
        return UpdatePolicyCommand(
            policy_repository,
            opa_client=None,
            policy_compiler=None,
            audit_service=audit_service,
        )

    @pytest.mark.asyncio
    async def test_update_policy_creates_audit_entry(
        self,
        command: UpdatePolicyCommand,
        policy_repository: AsyncMock,
        audit_service: AsyncMock,
    ) -> None:
        """Test that policy update creates audit entry."""
        policy_id = uuid4()
        tenant_id = uuid4()
        request = UpdatePolicyRequest(name="updated-policy")

        # Mock repository
        existing_policy = Policy(
            policy_id=policy_id,
            tenant_id=tenant_id,
            name="old-policy",
            description="Test",
            created_by=uuid4(),
        )
        policy_repository.find_by_id.return_value = existing_policy

        # Execute
        result = await command.execute(policy_id, tenant_id, request)

        # Verify audit entry was created
        audit_service.record_access.assert_called_once()
        audit_call = audit_service.record_access.call_args[0][0]

        assert audit_call.tenant_id == tenant_id
        assert audit_call.agent_id == UUID("00000000-0000-0000-0000-000000000000")
        assert audit_call.domain == "system"
        assert audit_call.decision == AccessDecision.ALLOW
        assert "Policy updated" in audit_call.reason
        assert audit_call.request_path == "/policies/update"
        assert audit_call.metadata["operation"] == "update_policy"
        assert "name" in audit_call.metadata["changes"]

    @pytest.mark.asyncio
    async def test_update_policy_audit_failure_does_not_fail_command(
        self,
        command: UpdatePolicyCommand,
        policy_repository: AsyncMock,
        audit_service: AsyncMock,
    ) -> None:
        """Test that audit failure doesn't fail the command."""
        policy_id = uuid4()
        tenant_id = uuid4()
        request = UpdatePolicyRequest(name="updated-policy")

        # Mock repository
        existing_policy = Policy(
            policy_id=policy_id,
            tenant_id=tenant_id,
            name="old-policy",
            description="Test",
            created_by=uuid4(),
        )
        policy_repository.find_by_id.return_value = existing_policy

        # Mock audit service to fail
        audit_service.record_access.side_effect = Exception("Audit database error")

        # Execute - should succeed despite audit failure
        result = await command.execute(policy_id, tenant_id, request)

        # Verify command succeeded
        assert result.name == "updated-policy"
        audit_service.record_access.assert_called_once()


class TestDeletePolicyAuditSideEffects:
    """Test DeletePolicyCommand audit side effects."""

    @pytest.fixture
    def policy_repository(self) -> AsyncMock:
        """Mock policy repository."""
        from domain.policy.repository import PolicyRepository

        return AsyncMock(spec=PolicyRepository)

    @pytest.fixture
    def audit_service(self) -> AsyncMock:
        """Mock audit service."""
        from unittest.mock import MagicMock

        mock = MagicMock(spec=AuditService)
        mock.record_access = AsyncMock()
        return mock

    @pytest.fixture
    def command(
        self, policy_repository: AsyncMock, audit_service: AsyncMock
    ) -> DeletePolicyCommand:
        """Create command instance with audit service."""
        return DeletePolicyCommand(policy_repository, opa_client=None, audit_service=audit_service)

    @pytest.mark.asyncio
    async def test_delete_policy_creates_audit_entry(
        self,
        command: DeletePolicyCommand,
        policy_repository: AsyncMock,
        audit_service: AsyncMock,
    ) -> None:
        """Test that policy deletion creates audit entry."""
        policy_id = uuid4()
        tenant_id = uuid4()

        # Mock repository
        existing_policy = Policy(
            policy_id=policy_id,
            tenant_id=tenant_id,
            name="to-delete",
            description="Test",
            created_by=uuid4(),
        )
        policy_repository.find_by_id.return_value = existing_policy
        policy_repository.delete.return_value = True

        # Execute
        result = await command.execute(policy_id, tenant_id)

        # Verify audit entry was created
        audit_service.record_access.assert_called_once()
        audit_call = audit_service.record_access.call_args[0][0]

        assert audit_call.tenant_id == tenant_id
        assert audit_call.agent_id == UUID("00000000-0000-0000-0000-000000000000")
        assert audit_call.domain == "system"
        assert audit_call.decision == AccessDecision.ALLOW
        assert "Policy deleted" in audit_call.reason
        assert audit_call.request_path == "/policies/delete"
        assert audit_call.metadata["operation"] == "delete_policy"
        assert audit_call.metadata["policy_name"] == "to-delete"

    @pytest.mark.asyncio
    async def test_delete_policy_audit_failure_does_not_fail_command(
        self,
        command: DeletePolicyCommand,
        policy_repository: AsyncMock,
        audit_service: AsyncMock,
    ) -> None:
        """Test that audit failure doesn't fail the command."""
        policy_id = uuid4()
        tenant_id = uuid4()

        # Mock repository
        existing_policy = Policy(
            policy_id=policy_id,
            tenant_id=tenant_id,
            name="to-delete",
            description="Test",
            created_by=uuid4(),
        )
        policy_repository.find_by_id.return_value = existing_policy
        policy_repository.delete.return_value = True

        # Mock audit service to fail
        audit_service.record_access.side_effect = Exception("Audit database error")

        # Execute - should succeed despite audit failure
        result = await command.execute(policy_id, tenant_id)

        # Verify command succeeded
        assert result is True
        audit_service.record_access.assert_called_once()
