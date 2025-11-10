"""Tests for Application Command handlers."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID

from application.commands import (
    CreateAgentCommand,
    CreatePolicyCommand,
    DeletePolicyCommand,
    UpdateAgentCommand,
    UpdatePolicyCommand,
)
from application.dto import (
    AgentDTO,
    CreateAgentRequest,
    CreatePolicyRequest,
    PolicyDTO,
    UpdateAgentRequest,
    UpdatePolicyRequest,
)
from domain.agent.entity import Agent, AgentStatus
from domain.agent.service import AgentService
from domain.common.exceptions import DuplicateEntityError, EntityNotFoundError
from domain.common.value_objects import X509Certificate
from domain.policy.entity import Policy, PolicyStatus
from domain.policy.service import PolicyService


class TestCreateAgentCommand:
    """Test CreateAgentCommand handler."""

    @pytest.fixture
    def agent_service(self) -> AsyncMock:
        """Mock agent service."""
        return AsyncMock(spec=AgentService)

    @pytest.fixture
    def command(self, agent_service: AsyncMock) -> CreateAgentCommand:
        """Create command instance."""
        return CreateAgentCommand(agent_service)

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
    async def test_create_agent_command_success(
        self, command: CreateAgentCommand, agent_service: AsyncMock, valid_cert_pem: str
    ) -> None:
        """Test successful agent creation."""
        tenant_id = uuid4()
        request = CreateAgentRequest(
            name="test-agent", certificate_pem=valid_cert_pem, metadata={"env": "test"}
        )

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

        # Verify
        assert isinstance(result, AgentDTO)
        assert result.name == "test-agent"
        assert result.tenant_id == tenant_id
        agent_service.create_agent.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_agent_command_propagates_errors(
        self, command: CreateAgentCommand, agent_service: AsyncMock, valid_cert_pem: str
    ) -> None:
        """Test command propagates domain service errors."""
        tenant_id = uuid4()
        request = CreateAgentRequest(name="duplicate-agent", certificate_pem=valid_cert_pem)

        # Mock service to raise error
        agent_service.create_agent.side_effect = DuplicateEntityError(
            "Agent", "name", "duplicate-agent"
        )

        # Execute and verify error propagation
        with pytest.raises(DuplicateEntityError):
            await command.execute(request, tenant_id)


class TestUpdateAgentCommand:
    """Test UpdateAgentCommand handler."""

    @pytest.fixture
    def agent_repository(self) -> AsyncMock:
        """Mock agent repository."""
        from domain.agent.repository import AgentRepository

        return AsyncMock(spec=AgentRepository)

    @pytest.fixture
    def command(self, agent_repository: AsyncMock) -> UpdateAgentCommand:
        """Create command instance."""
        return UpdateAgentCommand(agent_repository)

    @pytest.fixture
    def valid_cert_pem(self, rsa_private_key: RSAPrivateKey) -> str:
        """Generate valid certificate PEM."""
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "updated-agent")])

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

    @pytest.fixture
    def rsa_private_key(self) -> RSAPrivateKey:
        """Generate RSA private key."""
        return rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    @pytest.mark.asyncio
    async def test_update_agent_name_only(
        self, command: UpdateAgentCommand, agent_repository: AsyncMock, valid_cert_pem: str
    ) -> None:
        """Test updating only agent name."""
        agent_id = uuid4()
        tenant_id = uuid4()
        request = UpdateAgentRequest(name="new-name")

        # Mock repository responses
        existing_agent = Agent(
            agent_id=agent_id,
            tenant_id=tenant_id,
            name="old-name",
            certificate=X509Certificate(pem_data=valid_cert_pem),
        )
        agent_repository.find_by_id.return_value = existing_agent

        # Execute command
        result = await command.execute(agent_id, tenant_id, request)

        # Verify
        assert isinstance(result, AgentDTO)
        assert result.name == "new-name"
        agent_repository.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_agent_no_fields_provided(
        self, command: UpdateAgentCommand, agent_repository: AsyncMock, valid_cert_pem: str
    ) -> None:
        """Test update with no fields provided."""
        agent_id = uuid4()
        tenant_id = uuid4()
        request = UpdateAgentRequest()  # All None

        # Mock repository response
        agent = Agent(
            agent_id=agent_id,
            tenant_id=tenant_id,
            name="unchanged",
            certificate=X509Certificate(pem_data=valid_cert_pem),
        )
        agent_repository.find_by_id.return_value = agent

        # Execute command
        result = await command.execute(agent_id, tenant_id, request)

        # Verify no save called when no fields provided
        agent_repository.save.assert_not_called()
        assert result.name == "unchanged"

    @pytest.mark.asyncio
    async def test_update_agent_not_found(
        self, command: UpdateAgentCommand, agent_repository: AsyncMock
    ) -> None:
        """Test updating non-existent agent."""
        agent_id = uuid4()
        tenant_id = uuid4()
        request = UpdateAgentRequest(name="new-name")

        # Mock repository to return None
        agent_repository.find_by_id.return_value = None

        # Execute and verify error
        with pytest.raises(EntityNotFoundError):
            await command.execute(agent_id, tenant_id, request)


class TestCreatePolicyCommand:
    """Test CreatePolicyCommand handler."""

    @pytest.fixture
    def policy_service(self) -> AsyncMock:
        """Mock policy service."""
        service = AsyncMock(spec=PolicyService)
        # Add mock repository to policy service
        service._policy_repository = AsyncMock()
        service._policy_repository.save = AsyncMock()
        return service

    @pytest.fixture
    def opa_client(self) -> AsyncMock:
        """Mock OPA client."""
        from infrastructure.opa.client import OPAClient

        return AsyncMock(spec=OPAClient)

    @pytest.fixture
    def policy_compiler(self) -> AsyncMock:
        """Mock policy compiler."""
        from infrastructure.opa.policy_compiler import PolicyCompiler

        return AsyncMock(spec=PolicyCompiler)

    @pytest.fixture
    def command(self, policy_service: AsyncMock) -> CreatePolicyCommand:
        """Create command instance without OPA integration."""
        return CreatePolicyCommand(policy_service)

    @pytest.fixture
    def command_with_opa(
        self, policy_service: AsyncMock, opa_client: AsyncMock, policy_compiler: AsyncMock
    ) -> CreatePolicyCommand:
        """Create command instance with OPA integration."""
        return CreatePolicyCommand(policy_service, opa_client, policy_compiler)

    @pytest.mark.asyncio
    async def test_create_policy_command_success(
        self, command: CreatePolicyCommand, policy_service: AsyncMock
    ) -> None:
        """Test successful policy creation."""
        tenant_id = uuid4()
        created_by = uuid4()
        request = CreatePolicyRequest(
            name="test-policy",
            description="Test description",
            priority=500,
            allowed_domains=["example.com"],
            metadata={"env": "test"},
        )

        # Mock service responses
        created_policy = Policy(
            policy_id=uuid4(),
            tenant_id=tenant_id,
            name="test-policy",
            description="Test description",
            created_by=created_by,
            status=PolicyStatus.DRAFT,
        )
        policy_service.create_policy.return_value = created_policy

        # Execute command
        result = await command.execute(request, tenant_id, created_by)

        # Verify
        assert isinstance(result, PolicyDTO)
        assert result.name == "test-policy"
        assert "example.com" in result.allowed_domains
        policy_service.create_policy.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_policy_with_minimal_fields(
        self, command: CreatePolicyCommand, policy_service: AsyncMock
    ) -> None:
        """Test creating policy with only required fields."""
        tenant_id = uuid4()
        created_by = uuid4()
        request = CreatePolicyRequest(name="minimal-policy", description="Test")

        # Mock service
        created_policy = Policy(
            policy_id=uuid4(),
            tenant_id=tenant_id,
            name="minimal-policy",
            description="Test",
            created_by=created_by,
        )
        policy_service.create_policy.return_value = created_policy

        # Execute
        result = await command.execute(request, tenant_id, created_by)

        # Verify policy created with minimal fields
        assert isinstance(result, PolicyDTO)
        assert result.name == "minimal-policy"
        assert result.allowed_domains == []
        assert result.blocked_domains == []

    @pytest.mark.asyncio
    async def test_create_active_policy_deploys_to_opa(
        self,
        command_with_opa: CreatePolicyCommand,
        policy_service: AsyncMock,
        opa_client: AsyncMock,
        policy_compiler: AsyncMock,
    ) -> None:
        """Test that active policy is deployed to OPA."""
        tenant_id = uuid4()
        created_by = uuid4()
        request = CreatePolicyRequest(
            name="active-policy",
            description="Test active policy",
            priority=500,
        )

        # Mock service to return ACTIVE policy
        created_policy = Policy(
            policy_id=uuid4(),
            tenant_id=tenant_id,
            name="active-policy",
            description="Test active policy",
            created_by=created_by,
            status=PolicyStatus.ACTIVE,
        )
        policy_service.create_policy.return_value = created_policy

        # Mock OPA integration
        policy_compiler.compile_policy.return_value = "package chronoguard\nallow = true"
        opa_client.update_policy.return_value = None

        # Execute
        result = await command_with_opa.execute(request, tenant_id, created_by)

        # Verify policy was deployed to OPA
        assert isinstance(result, PolicyDTO)
        policy_compiler.compile_policy.assert_called_once()
        opa_client.update_policy.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_draft_policy_not_deployed_to_opa(
        self,
        command_with_opa: CreatePolicyCommand,
        policy_service: AsyncMock,
        opa_client: AsyncMock,
        policy_compiler: AsyncMock,
    ) -> None:
        """Test that draft policy is NOT deployed to OPA."""
        tenant_id = uuid4()
        created_by = uuid4()
        request = CreatePolicyRequest(
            name="draft-policy",
            description="Test draft policy",
        )

        # Mock service to return DRAFT policy
        created_policy = Policy(
            policy_id=uuid4(),
            tenant_id=tenant_id,
            name="draft-policy",
            description="Test draft policy",
            created_by=created_by,
            status=PolicyStatus.DRAFT,
        )
        policy_service.create_policy.return_value = created_policy

        # Execute
        result = await command_with_opa.execute(request, tenant_id, created_by)

        # Verify policy was NOT deployed to OPA
        assert isinstance(result, PolicyDTO)
        policy_compiler.compile_policy.assert_not_called()
        opa_client.update_policy.assert_not_called()

    @pytest.mark.asyncio
    async def test_create_policy_opa_deployment_failure_does_not_fail_command(
        self,
        command_with_opa: CreatePolicyCommand,
        policy_service: AsyncMock,
        opa_client: AsyncMock,
        policy_compiler: AsyncMock,
    ) -> None:
        """Test that OPA deployment errors are logged but don't fail the command."""
        tenant_id = uuid4()
        created_by = uuid4()
        request = CreatePolicyRequest(
            name="failing-opa-policy",
            description="Test OPA failure handling",
        )

        # Mock service to return ACTIVE policy
        created_policy = Policy(
            policy_id=uuid4(),
            tenant_id=tenant_id,
            name="failing-opa-policy",
            description="Test OPA failure handling",
            created_by=created_by,
            status=PolicyStatus.ACTIVE,
        )
        policy_service.create_policy.return_value = created_policy

        # Mock OPA to fail
        policy_compiler.compile_policy.return_value = "package chronoguard\nallow = true"
        opa_client.update_policy.side_effect = Exception("OPA connection failed")

        # Execute - should succeed despite OPA failure
        result = await command_with_opa.execute(request, tenant_id, created_by)

        # Verify policy was created successfully
        assert isinstance(result, PolicyDTO)
        assert result.name == "failing-opa-policy"
        policy_compiler.compile_policy.assert_called_once()
        opa_client.update_policy.assert_called_once()


class TestUpdatePolicyCommand:
    """Test UpdatePolicyCommand handler."""

    @pytest.fixture
    def policy_repository(self) -> AsyncMock:
        """Mock policy repository."""
        from domain.policy.repository import PolicyRepository

        return AsyncMock(spec=PolicyRepository)

    @pytest.fixture
    def opa_client(self) -> AsyncMock:
        """Mock OPA client."""
        from infrastructure.opa.client import OPAClient

        return AsyncMock(spec=OPAClient)

    @pytest.fixture
    def policy_compiler(self) -> AsyncMock:
        """Mock policy compiler."""
        from infrastructure.opa.policy_compiler import PolicyCompiler

        return AsyncMock(spec=PolicyCompiler)

    @pytest.fixture
    def command(self, policy_repository: AsyncMock) -> UpdatePolicyCommand:
        """Create command instance without OPA integration."""
        return UpdatePolicyCommand(policy_repository)

    @pytest.fixture
    def command_with_opa(
        self, policy_repository: AsyncMock, opa_client: AsyncMock, policy_compiler: AsyncMock
    ) -> UpdatePolicyCommand:
        """Create command instance with OPA integration."""
        return UpdatePolicyCommand(policy_repository, opa_client, policy_compiler)

    @pytest.mark.asyncio
    async def test_update_policy_name_and_priority(
        self, command: UpdatePolicyCommand, policy_repository: AsyncMock
    ) -> None:
        """Test updating policy name and priority."""
        policy_id = uuid4()
        tenant_id = uuid4()
        request = UpdatePolicyRequest(name="new-name", priority=700)

        # Mock repository
        existing_policy = Policy(
            policy_id=policy_id,
            tenant_id=tenant_id,
            name="old-name",
            description="Test",
            created_by=uuid4(),
            priority=500,
        )
        policy_repository.find_by_id.return_value = existing_policy

        # Execute
        result = await command.execute(policy_id, tenant_id, request)

        # Verify
        assert isinstance(result, PolicyDTO)
        assert result.name == "new-name"
        assert result.priority == 700
        policy_repository.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_policy_no_fields(
        self, command: UpdatePolicyCommand, policy_repository: AsyncMock
    ) -> None:
        """Test update with no fields provided."""
        policy_id = uuid4()
        tenant_id = uuid4()
        request = UpdatePolicyRequest()

        # Mock repository
        policy = Policy(
            policy_id=policy_id,
            tenant_id=tenant_id,
            name="unchanged",
            description="Test",
            created_by=uuid4(),
        )
        policy_repository.find_by_id.return_value = policy

        # Execute
        result = await command.execute(policy_id, tenant_id, request)

        # Verify no save called when no updates
        policy_repository.save.assert_not_called()
        assert result.name == "unchanged"

    @pytest.mark.asyncio
    async def test_update_active_policy_redeploys_to_opa(
        self,
        command_with_opa: UpdatePolicyCommand,
        policy_repository: AsyncMock,
        opa_client: AsyncMock,
        policy_compiler: AsyncMock,
    ) -> None:
        """Test that updating active policy redeploys to OPA."""
        policy_id = uuid4()
        tenant_id = uuid4()
        request = UpdatePolicyRequest(name="updated-name", priority=700)

        # Mock repository to return ACTIVE policy
        existing_policy = Policy(
            policy_id=policy_id,
            tenant_id=tenant_id,
            name="old-name",
            description="Test",
            created_by=uuid4(),
            priority=500,
            status=PolicyStatus.ACTIVE,
        )
        policy_repository.find_by_id.return_value = existing_policy

        # Mock OPA integration
        policy_compiler.compile_policy.return_value = "package chronoguard\nallow = true"
        opa_client.update_policy.return_value = None

        # Execute
        result = await command_with_opa.execute(policy_id, tenant_id, request)

        # Verify policy was redeployed to OPA
        assert isinstance(result, PolicyDTO)
        assert result.name == "updated-name"
        policy_compiler.compile_policy.assert_called_once()
        opa_client.update_policy.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_draft_policy_not_redeployed_to_opa(
        self,
        command_with_opa: UpdatePolicyCommand,
        policy_repository: AsyncMock,
        opa_client: AsyncMock,
        policy_compiler: AsyncMock,
    ) -> None:
        """Test that updating draft policy does NOT redeploy to OPA."""
        policy_id = uuid4()
        tenant_id = uuid4()
        request = UpdatePolicyRequest(name="updated-name")

        # Mock repository to return DRAFT policy
        existing_policy = Policy(
            policy_id=policy_id,
            tenant_id=tenant_id,
            name="old-name",
            description="Test",
            created_by=uuid4(),
            status=PolicyStatus.DRAFT,
        )
        policy_repository.find_by_id.return_value = existing_policy

        # Execute
        result = await command_with_opa.execute(policy_id, tenant_id, request)

        # Verify policy was NOT redeployed to OPA
        assert isinstance(result, PolicyDTO)
        policy_compiler.compile_policy.assert_not_called()
        opa_client.update_policy.assert_not_called()


class TestDeletePolicyCommand:
    """Test DeletePolicyCommand handler."""

    @pytest.fixture
    def policy_repository(self) -> AsyncMock:
        """Mock policy repository."""
        from domain.policy.repository import PolicyRepository

        return AsyncMock(spec=PolicyRepository)

    @pytest.fixture
    def opa_client(self) -> AsyncMock:
        """Mock OPA client."""
        from infrastructure.opa.client import OPAClient

        return AsyncMock(spec=OPAClient)

    @pytest.fixture
    def command(self, policy_repository: AsyncMock) -> DeletePolicyCommand:
        """Create command instance without OPA integration."""
        return DeletePolicyCommand(policy_repository)

    @pytest.fixture
    def command_with_opa(
        self, policy_repository: AsyncMock, opa_client: AsyncMock
    ) -> DeletePolicyCommand:
        """Create command instance with OPA integration."""
        return DeletePolicyCommand(policy_repository, opa_client)

    @pytest.mark.asyncio
    async def test_delete_policy_success(
        self, command: DeletePolicyCommand, policy_repository: AsyncMock
    ) -> None:
        """Test successful policy deletion."""
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

        # Verify
        assert result is True
        policy_repository.delete.assert_called_once_with(policy_id)

    @pytest.mark.asyncio
    async def test_delete_policy_not_found(
        self, command: DeletePolicyCommand, policy_repository: AsyncMock
    ) -> None:
        """Test deleting non-existent policy."""
        policy_id = uuid4()
        tenant_id = uuid4()

        # Mock repository to return None
        policy_repository.find_by_id.return_value = None

        # Execute and verify error propagation
        with pytest.raises(EntityNotFoundError):
            await command.execute(policy_id, tenant_id)

    @pytest.mark.asyncio
    async def test_delete_policy_removes_from_opa(
        self,
        command_with_opa: DeletePolicyCommand,
        policy_repository: AsyncMock,
        opa_client: AsyncMock,
    ) -> None:
        """Test that deleting policy also removes it from OPA."""
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

        # Mock OPA
        opa_client.delete_policy.return_value = None

        # Execute
        result = await command_with_opa.execute(policy_id, tenant_id)

        # Verify policy was deleted from OPA
        assert result is True
        policy_repository.delete.assert_called_once_with(policy_id)
        opa_client.delete_policy.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_policy_opa_failure_does_not_fail_command(
        self,
        command_with_opa: DeletePolicyCommand,
        policy_repository: AsyncMock,
        opa_client: AsyncMock,
    ) -> None:
        """Test that OPA deletion errors are logged but don't fail the command."""
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

        # Mock OPA to fail
        opa_client.delete_policy.side_effect = Exception("OPA connection failed")

        # Execute - should succeed despite OPA failure
        result = await command_with_opa.execute(policy_id, tenant_id)

        # Verify policy was deleted from database
        assert result is True
        policy_repository.delete.assert_called_once_with(policy_id)
        opa_client.delete_policy.assert_called_once()
