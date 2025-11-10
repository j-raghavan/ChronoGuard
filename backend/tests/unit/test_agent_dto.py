"""Tests for Agent DTOs and mappers."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from application.dto import AgentDTO, AgentMapper, CreateAgentRequest, UpdateAgentRequest
from domain.agent.entity import Agent, AgentStatus
from domain.common.value_objects import X509Certificate


class TestAgentDTO:
    """Test AgentDTO data transfer object."""

    def test_agent_dto_creation_with_all_fields(self) -> None:
        """Test creating AgentDTO with all fields."""
        agent_id = uuid4()
        tenant_id = uuid4()
        policy_id = uuid4()
        now = datetime.now(UTC)

        dto = AgentDTO(
            agent_id=agent_id,
            tenant_id=tenant_id,
            name="test-agent",
            status="active",
            certificate_fingerprint="sha256:abc123",
            certificate_subject="CN=test-agent",
            certificate_expiry=now,
            policy_ids=[policy_id],
            created_at=now,
            updated_at=now,
            last_seen_at=now,
            metadata={"key": "value"},
            version=1,
        )

        assert dto.agent_id == agent_id
        assert dto.tenant_id == tenant_id
        assert dto.name == "test-agent"
        assert dto.status == "active"
        assert dto.certificate_fingerprint == "sha256:abc123"
        assert dto.policy_ids == [policy_id]
        assert dto.version == 1

    def test_agent_dto_is_immutable(self) -> None:
        """Test that AgentDTO is immutable."""
        dto = AgentDTO(
            agent_id=uuid4(),
            tenant_id=uuid4(),
            name="test-agent",
            status="active",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            version=1,
        )

        with pytest.raises((ValidationError, AttributeError)):
            dto.name = "new-name"

    def test_agent_dto_with_minimal_fields(self) -> None:
        """Test AgentDTO with only required fields."""
        agent_id = uuid4()
        tenant_id = uuid4()
        now = datetime.now(UTC)

        dto = AgentDTO(
            agent_id=agent_id,
            tenant_id=tenant_id,
            name="minimal-agent",
            status="pending",
            created_at=now,
            updated_at=now,
            version=1,
        )

        assert dto.agent_id == agent_id
        assert dto.certificate_fingerprint is None
        assert dto.last_seen_at is None
        assert dto.policy_ids == []
        assert dto.metadata == {}


class TestCreateAgentRequest:
    """Test CreateAgentRequest validation."""

    def test_create_agent_request_with_valid_data(self) -> None:
        """Test creating valid CreateAgentRequest."""
        request = CreateAgentRequest(
            name="test-agent",
            certificate_pem="-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----",
            metadata={"env": "test"},
        )

        assert request.name == "test-agent"
        assert request.metadata == {"env": "test"}

    def test_create_agent_request_validates_name_length(self) -> None:
        """Test name length validation."""
        # Too short
        with pytest.raises(ValidationError) as exc_info:
            CreateAgentRequest(
                name="ab",
                certificate_pem="-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----",
            )
        assert "at least 3 characters" in str(exc_info.value).lower()

        # Too long
        with pytest.raises(ValidationError) as exc_info:
            CreateAgentRequest(
                name="a" * 101,
                certificate_pem="-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----",
            )
        assert "at most 100 characters" in str(exc_info.value).lower()

    def test_create_agent_request_validates_name_not_empty(self) -> None:
        """Test name cannot be empty or whitespace."""
        with pytest.raises(ValidationError) as exc_info:
            CreateAgentRequest(
                name="   ",
                certificate_pem="-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----",
            )
        assert "empty" in str(exc_info.value).lower() or "whitespace" in str(exc_info.value).lower()

    def test_create_agent_request_validates_certificate_pem_format(self) -> None:
        """Test certificate PEM format validation."""
        # Missing BEGIN marker
        with pytest.raises(ValidationError) as exc_info:
            CreateAgentRequest(name="test-agent", certificate_pem="data\n-----END CERTIFICATE-----")
        assert "pem format" in str(exc_info.value).lower()

        # Missing END marker
        with pytest.raises(ValidationError) as exc_info:
            CreateAgentRequest(
                name="test-agent", certificate_pem="-----BEGIN CERTIFICATE-----\ndata"
            )
        assert (
            "pem format" in str(exc_info.value).lower()
            or "incomplete" in str(exc_info.value).lower()
        )

    def test_create_agent_request_trims_whitespace(self) -> None:
        """Test that name whitespace is trimmed."""
        request = CreateAgentRequest(
            name="  test-agent  ",
            certificate_pem="-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----",
        )
        assert request.name == "test-agent"

    def test_create_agent_request_with_default_metadata(self) -> None:
        """Test default metadata is empty dict."""
        request = CreateAgentRequest(
            name="test-agent",
            certificate_pem="-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----",
        )
        assert request.metadata == {}


class TestUpdateAgentRequest:
    """Test UpdateAgentRequest validation."""

    def test_update_agent_request_all_fields_optional(self) -> None:
        """Test all fields are optional in update request."""
        request = UpdateAgentRequest()
        assert request.name is None
        assert request.certificate_pem is None
        assert request.metadata is None

    def test_update_agent_request_with_partial_update(self) -> None:
        """Test update request with only some fields."""
        request = UpdateAgentRequest(name="new-name")
        assert request.name == "new-name"
        assert request.certificate_pem is None
        assert request.metadata is None

    def test_update_agent_request_validates_name_if_provided(self) -> None:
        """Test name validation when provided."""
        # Valid name
        request = UpdateAgentRequest(name="new-agent-name")
        assert request.name == "new-agent-name"

        # Empty name
        with pytest.raises(ValidationError) as exc_info:
            UpdateAgentRequest(name="   ")
        assert "empty" in str(exc_info.value).lower() or "whitespace" in str(exc_info.value).lower()

    def test_update_agent_request_validates_certificate_if_provided(self) -> None:
        """Test certificate validation when provided."""
        # Valid certificate
        request = UpdateAgentRequest(
            certificate_pem="-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----"
        )
        assert request.certificate_pem is not None

        # Invalid certificate
        with pytest.raises(ValidationError) as exc_info:
            UpdateAgentRequest(certificate_pem="invalid-pem")
        assert "pem" in str(exc_info.value).lower()


class TestAgentMapper:
    """Test AgentMapper conversion functions."""

    @pytest.fixture
    def rsa_private_key(self) -> RSAPrivateKey:
        """Generate an RSA private key for testing."""
        return rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    @pytest.fixture
    def valid_cert_pem(self, rsa_private_key: RSAPrivateKey) -> str:
        """Create a valid certificate PEM."""
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

    def test_agent_mapper_to_dto(self, valid_cert_pem: str) -> None:
        """Test mapping Agent entity to AgentDTO."""
        certificate = X509Certificate(pem_data=valid_cert_pem)
        agent = Agent(
            agent_id=uuid4(),
            tenant_id=uuid4(),
            name="test-agent",
            certificate=certificate,
            status=AgentStatus.ACTIVE,
        )

        dto = AgentMapper.to_dto(agent)

        assert isinstance(dto, AgentDTO)
        assert dto.agent_id == agent.agent_id
        assert dto.tenant_id == agent.tenant_id
        assert dto.name == agent.name
        assert dto.status == "active"
        assert dto.certificate_fingerprint == certificate.fingerprint_sha256
        assert dto.certificate_subject == certificate.subject_common_name
        assert dto.certificate_expiry == certificate.not_valid_after
        assert dto.version == agent.version

    def test_agent_mapper_from_create_request(self, valid_cert_pem: str) -> None:
        """Test mapping CreateAgentRequest to Agent entity."""
        tenant_id = uuid4()
        request = CreateAgentRequest(
            name="new-agent",
            certificate_pem=valid_cert_pem,
            metadata={"env": "production"},
        )

        agent = AgentMapper.from_create_request(request, tenant_id)

        assert isinstance(agent, Agent)
        assert agent.tenant_id == tenant_id
        assert agent.name == "new-agent"
        assert isinstance(agent.certificate, X509Certificate)
        assert agent.metadata == {"env": "production"}
        assert agent.status == AgentStatus.PENDING  # Default status

    def test_agent_mapper_handles_invalid_certificate(self) -> None:
        """Test mapper handles invalid certificate gracefully."""
        tenant_id = uuid4()
        request = CreateAgentRequest(
            name="bad-agent",
            certificate_pem="-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----",
        )

        # Should raise validation error from X509Certificate
        with pytest.raises(Exception):  # Could be ValidationError or cryptography error
            AgentMapper.from_create_request(request, tenant_id)

    def test_agent_mapper_preserves_metadata(self, valid_cert_pem: str) -> None:
        """Test mapper preserves metadata correctly."""
        certificate = X509Certificate(pem_data=valid_cert_pem)
        metadata = {"key1": "value1", "key2": "value2"}
        agent = Agent(
            agent_id=uuid4(),
            tenant_id=uuid4(),
            name="test-agent",
            certificate=certificate,
            metadata=metadata,
        )

        dto = AgentMapper.to_dto(agent)

        assert dto.metadata == metadata
        # Ensure it's a copy, not the same reference
        assert dto.metadata is not agent.metadata

    def test_agent_mapper_handles_optional_fields(self, valid_cert_pem: str) -> None:
        """Test mapper handles optional fields correctly."""
        certificate = X509Certificate(pem_data=valid_cert_pem)
        agent = Agent(
            agent_id=uuid4(),
            tenant_id=uuid4(),
            name="test-agent",
            certificate=certificate,
            last_seen_at=None,
        )

        dto = AgentMapper.to_dto(agent)

        assert dto.last_seen_at is None
