"""Comprehensive tests for gRPC server."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import grpc
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from domain.agent.entity import Agent, AgentStatus
from domain.common.value_objects import X509Certificate
from presentation.grpc.server import (
    AgentNotFoundError,
    AgentServiceError,
    GRPCAgentService,
    InvalidRequestError,
)


def create_test_certificate(
    common_name: str = "test.example.com",
    organization: str = "Test Organization",
    days_valid: int = 365,
) -> str:
    """Create a valid self-signed test certificate."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture
def mock_command_handler() -> MagicMock:
    """Create a mock command handler."""
    handler = MagicMock()
    handler.create_agent = AsyncMock()
    handler.update_agent = AsyncMock()
    return handler


@pytest.fixture
def mock_query_handler() -> MagicMock:
    """Create a mock query handler."""
    handler = MagicMock()
    handler.get_agent = AsyncMock()
    handler.list_agents = AsyncMock()
    return handler


@pytest.fixture
def grpc_service(
    mock_command_handler: MagicMock,
    mock_query_handler: MagicMock,
) -> GRPCAgentService:
    """Create a gRPC service instance."""
    return GRPCAgentService(mock_command_handler, mock_query_handler)


@pytest.fixture
def sample_agent() -> Agent:
    """Create a sample agent."""
    cert_pem = create_test_certificate(
        common_name="test-agent",
        organization="TestOrg",
    )
    cert = X509Certificate(pem_data=cert_pem)

    return Agent(
        agent_id=uuid4(),
        tenant_id=uuid4(),
        name="test-agent",
        certificate=cert,
        status=AgentStatus.ACTIVE,
    )


@pytest.fixture
def mock_grpc_context() -> MagicMock:
    """Create a mock gRPC context."""
    context = MagicMock(spec=grpc.aio.ServicerContext)
    context.abort = AsyncMock()
    return context


class TestAgentServiceExceptions:
    """Test custom exception classes."""

    def test_agent_service_error(self) -> None:
        """Test base exception."""
        error = AgentServiceError("Test error")
        assert str(error) == "Test error"

    def test_agent_not_found_error(self) -> None:
        """Test agent not found exception."""
        error = AgentNotFoundError("Agent not found")
        assert str(error) == "Agent not found"

    def test_invalid_request_error(self) -> None:
        """Test invalid request exception."""
        error = InvalidRequestError("Invalid request")
        assert str(error) == "Invalid request"


class TestGRPCAgentServiceInit:
    """Test GRPCAgentService initialization."""

    def test_initialization(
        self,
        mock_command_handler: MagicMock,
        mock_query_handler: MagicMock,
    ) -> None:
        """Test service initialization."""
        service = GRPCAgentService(mock_command_handler, mock_query_handler)

        assert service._command_handler == mock_command_handler
        assert service._query_handler == mock_query_handler
        assert service._server is None
        assert service._port == 50051


class TestGetAgent:
    """Test GetAgent method."""

    async def test_get_agent_success(
        self,
        grpc_service: GRPCAgentService,
        sample_agent: Agent,
        mock_query_handler: MagicMock,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test successful agent retrieval."""
        mock_query_handler.get_agent.return_value = sample_agent

        request = {"agent_id": str(sample_agent.agent_id)}
        result = await grpc_service.GetAgent(request, mock_grpc_context)

        assert result["agent_id"] == str(sample_agent.agent_id)
        assert result["name"] == sample_agent.name
        assert result["status"] == sample_agent.status

    async def test_get_agent_missing_agent_id(
        self,
        grpc_service: GRPCAgentService,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test missing agent_id."""
        request: dict[str, Any] = {}
        await grpc_service.GetAgent(request, mock_grpc_context)

        mock_grpc_context.abort.assert_called_once()
        assert mock_grpc_context.abort.call_args[0][0] == grpc.StatusCode.INVALID_ARGUMENT

    async def test_get_agent_invalid_uuid(
        self,
        grpc_service: GRPCAgentService,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test invalid UUID format."""
        request = {"agent_id": "invalid-uuid"}
        await grpc_service.GetAgent(request, mock_grpc_context)

        mock_grpc_context.abort.assert_called_once()
        assert mock_grpc_context.abort.call_args[0][0] == grpc.StatusCode.INVALID_ARGUMENT

    async def test_get_agent_not_found(
        self,
        grpc_service: GRPCAgentService,
        mock_query_handler: MagicMock,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test agent not found."""
        mock_query_handler.get_agent.return_value = None

        request = {"agent_id": str(uuid4())}
        await grpc_service.GetAgent(request, mock_grpc_context)

        mock_grpc_context.abort.assert_called_once()
        assert mock_grpc_context.abort.call_args[0][0] == grpc.StatusCode.NOT_FOUND

    async def test_get_agent_internal_error(
        self,
        grpc_service: GRPCAgentService,
        mock_query_handler: MagicMock,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test internal error handling."""
        mock_query_handler.get_agent.side_effect = Exception("Database error")

        request = {"agent_id": str(uuid4())}
        await grpc_service.GetAgent(request, mock_grpc_context)

        mock_grpc_context.abort.assert_called_once()
        assert mock_grpc_context.abort.call_args[0][0] == grpc.StatusCode.INTERNAL


class TestListAgents:
    """Test ListAgents method."""

    async def test_list_agents_success(
        self,
        grpc_service: GRPCAgentService,
        sample_agent: Agent,
        mock_query_handler: MagicMock,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test successful listing."""
        mock_query_handler.list_agents.return_value = {
            "agents": [sample_agent],
            "total": 1,
        }

        request: dict[str, Any] = {}
        result = await grpc_service.ListAgents(request, mock_grpc_context)

        assert len(result["agents"]) == 1
        assert result["total"] == 1
        assert result["agents"][0]["agent_id"] == str(sample_agent.agent_id)

    async def test_list_agents_with_filters(
        self,
        grpc_service: GRPCAgentService,
        sample_agent: Agent,
        mock_query_handler: MagicMock,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test listing with filters."""
        mock_query_handler.list_agents.return_value = {
            "agents": [sample_agent],
            "total": 1,
        }

        request = {
            "tenant_id": str(sample_agent.tenant_id),
            "status": "active",
            "limit": 50,
            "offset": 10,
        }
        result = await grpc_service.ListAgents(request, mock_grpc_context)

        # Verify query was called with correct parameters
        query_arg = mock_query_handler.list_agents.call_args[0][0]
        assert query_arg["tenant_id"] == sample_agent.tenant_id
        assert query_arg["status"] == "active"
        assert query_arg["limit"] == 50
        assert query_arg["offset"] == 10

    async def test_list_agents_invalid_tenant_id(
        self,
        grpc_service: GRPCAgentService,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test invalid tenant_id format."""
        request = {"tenant_id": "invalid-uuid"}
        await grpc_service.ListAgents(request, mock_grpc_context)

        mock_grpc_context.abort.assert_called_once()
        assert mock_grpc_context.abort.call_args[0][0] == grpc.StatusCode.INVALID_ARGUMENT

    async def test_list_agents_limit_capped(
        self,
        grpc_service: GRPCAgentService,
        mock_query_handler: MagicMock,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test that limit is capped at 1000."""
        mock_query_handler.list_agents.return_value = {
            "agents": [],
            "total": 0,
        }

        request = {"limit": 5000}
        await grpc_service.ListAgents(request, mock_grpc_context)

        # Verify limit was capped
        query_arg = mock_query_handler.list_agents.call_args[0][0]
        assert query_arg["limit"] == 1000

    async def test_list_agents_negative_offset(
        self,
        grpc_service: GRPCAgentService,
        mock_query_handler: MagicMock,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test that negative offset is set to 0."""
        mock_query_handler.list_agents.return_value = {
            "agents": [],
            "total": 0,
        }

        request = {"offset": -10}
        await grpc_service.ListAgents(request, mock_grpc_context)

        # Verify offset was set to 0
        query_arg = mock_query_handler.list_agents.call_args[0][0]
        assert query_arg["offset"] == 0

    async def test_list_agents_internal_error(
        self,
        grpc_service: GRPCAgentService,
        mock_query_handler: MagicMock,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test internal error handling."""
        mock_query_handler.list_agents.side_effect = Exception("Database error")

        request: dict[str, Any] = {}
        await grpc_service.ListAgents(request, mock_grpc_context)

        mock_grpc_context.abort.assert_called_once()
        assert mock_grpc_context.abort.call_args[0][0] == grpc.StatusCode.INTERNAL


class TestCreateAgent:
    """Test CreateAgent method."""

    async def test_create_agent_success(
        self,
        grpc_service: GRPCAgentService,
        sample_agent: Agent,
        mock_command_handler: MagicMock,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test successful agent creation."""
        mock_command_handler.create_agent.return_value = sample_agent

        request = {
            "tenant_id": str(sample_agent.tenant_id),
            "name": "new-agent",
            "certificate_pem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        }
        result = await grpc_service.CreateAgent(request, mock_grpc_context)

        assert result["agent_id"] == str(sample_agent.agent_id)
        assert result["name"] == sample_agent.name

    async def test_create_agent_with_metadata(
        self,
        grpc_service: GRPCAgentService,
        sample_agent: Agent,
        mock_command_handler: MagicMock,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test creating agent with metadata."""
        mock_command_handler.create_agent.return_value = sample_agent

        request = {
            "tenant_id": str(sample_agent.tenant_id),
            "name": "new-agent",
            "certificate_pem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            "metadata": {"key": "value"},
        }
        await grpc_service.CreateAgent(request, mock_grpc_context)

        # Verify metadata was passed
        command_arg = mock_command_handler.create_agent.call_args[0][0]
        assert command_arg["metadata"] == {"key": "value"}

    async def test_create_agent_missing_tenant_id(
        self,
        grpc_service: GRPCAgentService,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test missing tenant_id."""
        request = {
            "name": "new-agent",
            "certificate_pem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        }
        await grpc_service.CreateAgent(request, mock_grpc_context)

        mock_grpc_context.abort.assert_called_once()
        assert mock_grpc_context.abort.call_args[0][0] == grpc.StatusCode.INVALID_ARGUMENT

    async def test_create_agent_missing_name(
        self,
        grpc_service: GRPCAgentService,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test missing name."""
        request = {
            "tenant_id": str(uuid4()),
            "certificate_pem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        }
        await grpc_service.CreateAgent(request, mock_grpc_context)

        mock_grpc_context.abort.assert_called_once()
        assert mock_grpc_context.abort.call_args[0][0] == grpc.StatusCode.INVALID_ARGUMENT

    async def test_create_agent_invalid_tenant_id(
        self,
        grpc_service: GRPCAgentService,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test invalid tenant_id format."""
        request = {
            "tenant_id": "invalid-uuid",
            "name": "new-agent",
            "certificate_pem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        }
        await grpc_service.CreateAgent(request, mock_grpc_context)

        mock_grpc_context.abort.assert_called_once()
        assert mock_grpc_context.abort.call_args[0][0] == grpc.StatusCode.INVALID_ARGUMENT

    async def test_create_agent_validation_error(
        self,
        grpc_service: GRPCAgentService,
        mock_command_handler: MagicMock,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test validation error from command handler."""
        mock_command_handler.create_agent.side_effect = ValueError("Invalid name")

        request = {
            "tenant_id": str(uuid4()),
            "name": "x",  # Too short
            "certificate_pem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        }
        await grpc_service.CreateAgent(request, mock_grpc_context)

        mock_grpc_context.abort.assert_called_once()
        assert mock_grpc_context.abort.call_args[0][0] == grpc.StatusCode.INVALID_ARGUMENT

    async def test_create_agent_internal_error(
        self,
        grpc_service: GRPCAgentService,
        mock_command_handler: MagicMock,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test internal error handling."""
        mock_command_handler.create_agent.side_effect = Exception("Database error")

        request = {
            "tenant_id": str(uuid4()),
            "name": "new-agent",
            "certificate_pem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        }
        await grpc_service.CreateAgent(request, mock_grpc_context)

        mock_grpc_context.abort.assert_called_once()
        assert mock_grpc_context.abort.call_args[0][0] == grpc.StatusCode.INTERNAL


class TestUpdateAgent:
    """Test UpdateAgent method."""

    async def test_update_agent_success(
        self,
        grpc_service: GRPCAgentService,
        sample_agent: Agent,
        mock_command_handler: MagicMock,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test successful agent update."""
        mock_command_handler.update_agent.return_value = sample_agent

        request = {
            "agent_id": str(sample_agent.agent_id),
            "name": "updated-agent",
        }
        result = await grpc_service.UpdateAgent(request, mock_grpc_context)

        assert result["agent_id"] == str(sample_agent.agent_id)

    async def test_update_agent_multiple_fields(
        self,
        grpc_service: GRPCAgentService,
        sample_agent: Agent,
        mock_command_handler: MagicMock,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test updating multiple fields."""
        mock_command_handler.update_agent.return_value = sample_agent

        request = {
            "agent_id": str(sample_agent.agent_id),
            "name": "updated-agent",
            "status": "suspended",
            "metadata": {"updated": True},
        }
        await grpc_service.UpdateAgent(request, mock_grpc_context)

        # Verify all fields were passed
        command_arg = mock_command_handler.update_agent.call_args[0][0]
        assert command_arg["name"] == "updated-agent"
        assert command_arg["status"] == "suspended"
        assert command_arg["metadata"] == {"updated": True}

    async def test_update_agent_missing_agent_id(
        self,
        grpc_service: GRPCAgentService,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test missing agent_id."""
        request = {"name": "updated-agent"}
        await grpc_service.UpdateAgent(request, mock_grpc_context)

        mock_grpc_context.abort.assert_called_once()
        assert mock_grpc_context.abort.call_args[0][0] == grpc.StatusCode.INVALID_ARGUMENT

    async def test_update_agent_invalid_agent_id(
        self,
        grpc_service: GRPCAgentService,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test invalid agent_id format."""
        request = {
            "agent_id": "invalid-uuid",
            "name": "updated-agent",
        }
        await grpc_service.UpdateAgent(request, mock_grpc_context)

        mock_grpc_context.abort.assert_called_once()
        assert mock_grpc_context.abort.call_args[0][0] == grpc.StatusCode.INVALID_ARGUMENT

    async def test_update_agent_not_found(
        self,
        grpc_service: GRPCAgentService,
        mock_command_handler: MagicMock,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test agent not found."""
        mock_command_handler.update_agent.return_value = None

        request = {
            "agent_id": str(uuid4()),
            "name": "updated-agent",
        }
        await grpc_service.UpdateAgent(request, mock_grpc_context)

        mock_grpc_context.abort.assert_called_once()
        assert mock_grpc_context.abort.call_args[0][0] == grpc.StatusCode.NOT_FOUND

    async def test_update_agent_validation_error(
        self,
        grpc_service: GRPCAgentService,
        mock_command_handler: MagicMock,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test validation error."""
        mock_command_handler.update_agent.side_effect = ValueError("Invalid status")

        request = {
            "agent_id": str(uuid4()),
            "status": "invalid",
        }
        await grpc_service.UpdateAgent(request, mock_grpc_context)

        mock_grpc_context.abort.assert_called_once()
        assert mock_grpc_context.abort.call_args[0][0] == grpc.StatusCode.INVALID_ARGUMENT


class TestServerLifecycle:
    """Test server start/stop."""

    async def test_start_server(
        self,
        grpc_service: GRPCAgentService,
    ) -> None:
        """Test starting server."""
        await grpc_service.start(port=50052)

        assert grpc_service.is_running is True
        assert grpc_service.port == 50052

        # Clean up
        await grpc_service.stop()

    async def test_start_server_already_running(
        self,
        grpc_service: GRPCAgentService,
    ) -> None:
        """Test starting already running server."""
        await grpc_service.start()

        with pytest.raises(RuntimeError, match="already running"):
            await grpc_service.start()

        # Clean up
        await grpc_service.stop()

    async def test_stop_server(
        self,
        grpc_service: GRPCAgentService,
    ) -> None:
        """Test stopping server."""
        await grpc_service.start()
        await grpc_service.stop()

        assert grpc_service.is_running is False

    async def test_stop_server_not_running(
        self,
        grpc_service: GRPCAgentService,
    ) -> None:
        """Test stopping server that's not running."""
        # Should not raise
        await grpc_service.stop()


class TestAgentToDict:
    """Test _agent_to_dict conversion."""

    def test_agent_to_dict(
        self,
        grpc_service: GRPCAgentService,
        sample_agent: Agent,
    ) -> None:
        """Test converting agent to dictionary."""
        result = grpc_service._agent_to_dict(sample_agent)

        assert result["agent_id"] == str(sample_agent.agent_id)
        assert result["tenant_id"] == str(sample_agent.tenant_id)
        assert result["name"] == sample_agent.name
        assert result["status"] == sample_agent.status
        assert result["version"] == sample_agent.version
        assert "certificate" in result
        assert result["certificate"]["subject_common_name"] == "test-agent"


class TestProperties:
    """Test service properties."""

    def test_is_running_false(
        self,
        grpc_service: GRPCAgentService,
    ) -> None:
        """Test is_running when not running."""
        assert grpc_service.is_running is False

    async def test_is_running_true(
        self,
        grpc_service: GRPCAgentService,
    ) -> None:
        """Test is_running when running."""
        await grpc_service.start()

        assert grpc_service.is_running is True

        # Clean up
        await grpc_service.stop()

    def test_port_property(
        self,
        grpc_service: GRPCAgentService,
    ) -> None:
        """Test port property."""
        assert grpc_service.port == 50051


class TestEdgeCases:
    """Test edge cases."""

    async def test_list_agents_empty_result(
        self,
        grpc_service: GRPCAgentService,
        mock_query_handler: MagicMock,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test listing with no results."""
        mock_query_handler.list_agents.return_value = {
            "agents": [],
            "total": 0,
        }

        request: dict[str, Any] = {}
        result = await grpc_service.ListAgents(request, mock_grpc_context)

        assert result["agents"] == []
        assert result["total"] == 0

    async def test_create_agent_empty_metadata(
        self,
        grpc_service: GRPCAgentService,
        sample_agent: Agent,
        mock_command_handler: MagicMock,
        mock_grpc_context: MagicMock,
    ) -> None:
        """Test creating agent with empty metadata."""
        mock_command_handler.create_agent.return_value = sample_agent

        request = {
            "tenant_id": str(sample_agent.tenant_id),
            "name": "new-agent",
            "certificate_pem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        }
        await grpc_service.CreateAgent(request, mock_grpc_context)

        # Should use empty dict for metadata
        command_arg = mock_command_handler.create_agent.call_args[0][0]
        assert command_arg["metadata"] == {}
