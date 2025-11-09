"""Tests for Application Query handlers."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from application.dto import (
    AgentDTO,
    AgentListResponse,
    AuditListResponse,
    AuditQueryRequest,
    PolicyDTO,
    PolicyListResponse,
)
from application.queries import (
    GetAgentQuery,
    GetAuditEntriesQuery,
    GetPolicyQuery,
    ListAgentsQuery,
    ListPoliciesQuery,
)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID
from domain.agent.entity import Agent, AgentStatus
from domain.audit.entity import AccessDecision, AuditEntry, TimedAccessContext
from domain.common.value_objects import DomainName, X509Certificate
from domain.policy.entity import Policy, PolicyStatus


class TestGetAgentQuery:
    """Test GetAgentQuery handler."""

    @pytest.fixture
    def agent_repository(self) -> AsyncMock:
        """Mock agent repository."""
        from domain.agent.repository import AgentRepository

        return AsyncMock(spec=AgentRepository)

    @pytest.fixture
    def query(self, agent_repository: AsyncMock) -> GetAgentQuery:
        """Create query instance."""
        return GetAgentQuery(agent_repository)

    @pytest.fixture
    def rsa_private_key(self) -> RSAPrivateKey:
        """Generate RSA private key."""
        return rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    @pytest.fixture
    def valid_cert_pem(self, rsa_private_key: RSAPrivateKey) -> str:
        """Generate valid certificate PEM."""
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-agent")])
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
    async def test_get_agent_success(
        self, query: GetAgentQuery, agent_repository: AsyncMock, valid_cert_pem: str
    ) -> None:
        """Test successfully retrieving an agent."""
        agent_id = uuid4()
        tenant_id = uuid4()

        # Mock repository
        agent = Agent(
            agent_id=agent_id,
            tenant_id=tenant_id,
            name="test-agent",
            certificate=X509Certificate(pem_data=valid_cert_pem),
        )
        agent_repository.find_by_id.return_value = agent

        # Execute query
        result = await query.execute(agent_id, tenant_id)

        # Verify
        assert isinstance(result, AgentDTO)
        assert result.agent_id == agent_id
        agent_repository.find_by_id.assert_called_once_with(agent_id)

    @pytest.mark.asyncio
    async def test_get_agent_not_found(
        self, query: GetAgentQuery, agent_repository: AsyncMock
    ) -> None:
        """Test retrieving non-existent agent."""
        agent_id = uuid4()
        tenant_id = uuid4()

        # Mock repository to return None
        agent_repository.find_by_id.return_value = None

        # Execute query
        result = await query.execute(agent_id, tenant_id)

        # Verify
        assert result is None

    @pytest.mark.asyncio
    async def test_get_agent_wrong_tenant(
        self, query: GetAgentQuery, agent_repository: AsyncMock, valid_cert_pem: str
    ) -> None:
        """Test retrieving agent from wrong tenant."""
        agent_id = uuid4()
        tenant_id = uuid4()
        wrong_tenant = uuid4()

        # Mock repository
        agent = Agent(
            agent_id=agent_id,
            tenant_id=tenant_id,
            name="test-agent",
            certificate=X509Certificate(pem_data=valid_cert_pem),
        )
        agent_repository.find_by_id.return_value = agent

        # Execute query with wrong tenant
        result = await query.execute(agent_id, wrong_tenant)

        # Verify access denied
        assert result is None


class TestListAgentsQuery:
    """Test ListAgentsQuery handler."""

    @pytest.fixture
    def agent_repository(self) -> AsyncMock:
        """Mock agent repository."""
        from domain.agent.repository import AgentRepository

        return AsyncMock(spec=AgentRepository)

    @pytest.fixture
    def query(self, agent_repository: AsyncMock) -> ListAgentsQuery:
        """Create query instance."""
        return ListAgentsQuery(agent_repository)

    @pytest.fixture
    def valid_cert_pem(self, rsa_private_key: RSAPrivateKey) -> str:
        """Generate valid certificate PEM."""
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
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
    async def test_list_agents_with_defaults(
        self, query: ListAgentsQuery, agent_repository: AsyncMock, valid_cert_pem: str
    ) -> None:
        """Test listing agents with default pagination."""
        tenant_id = uuid4()

        # Mock repository
        agents = [
            Agent(
                agent_id=uuid4(),
                tenant_id=tenant_id,
                name=f"agent-{i}",
                certificate=X509Certificate(pem_data=valid_cert_pem),
            )
            for i in range(3)
        ]
        agent_repository.find_paginated.return_value = agents
        agent_repository.count_by_tenant.return_value = 10

        # Execute query
        result = await query.execute(tenant_id)

        # Verify
        assert isinstance(result, AgentListResponse)
        assert len(result.agents) == 3
        assert result.total_count == 10
        assert result.page == 1
        assert result.page_size == 50

    @pytest.mark.asyncio
    async def test_list_agents_with_pagination(
        self, query: ListAgentsQuery, agent_repository: AsyncMock, valid_cert_pem: str
    ) -> None:
        """Test listing agents with custom pagination."""
        tenant_id = uuid4()

        # Mock repository
        agent_repository.find_paginated.return_value = []
        agent_repository.count_by_tenant.return_value = 100

        # Execute query with page 2, size 20
        result = await query.execute(tenant_id, page=2, page_size=20)

        # Verify
        assert result.page == 2
        assert result.page_size == 20
        agent_repository.find_paginated.assert_called_once_with(
            tenant_id=tenant_id, offset=20, limit=20, status_filter=None
        )

    @pytest.mark.asyncio
    async def test_list_agents_invalid_page(
        self, query: ListAgentsQuery, agent_repository: AsyncMock
    ) -> None:
        """Test validation of page number."""
        with pytest.raises(ValueError) as exc_info:
            await query.execute(uuid4(), page=0)
        assert "page must be >= 1" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_list_agents_invalid_page_size(
        self, query: ListAgentsQuery, agent_repository: AsyncMock
    ) -> None:
        """Test validation of page size."""
        with pytest.raises(ValueError) as exc_info:
            await query.execute(uuid4(), page_size=2000)
        assert "page size" in str(exc_info.value).lower()


class TestGetPolicyQuery:
    """Test GetPolicyQuery handler."""

    @pytest.fixture
    def policy_repository(self) -> AsyncMock:
        """Mock policy repository."""
        from domain.policy.repository import PolicyRepository

        return AsyncMock(spec=PolicyRepository)

    @pytest.fixture
    def query(self, policy_repository: AsyncMock) -> GetPolicyQuery:
        """Create query instance."""
        return GetPolicyQuery(policy_repository)

    @pytest.mark.asyncio
    async def test_get_policy_success(
        self, query: GetPolicyQuery, policy_repository: AsyncMock
    ) -> None:
        """Test successfully retrieving a policy."""
        policy_id = uuid4()
        tenant_id = uuid4()

        # Mock repository
        policy = Policy(
            policy_id=policy_id,
            tenant_id=tenant_id,
            name="test-policy",
            description="Test",
            created_by=uuid4(),
        )
        policy_repository.find_by_id.return_value = policy

        # Execute query
        result = await query.execute(policy_id, tenant_id)

        # Verify
        assert isinstance(result, PolicyDTO)
        assert result.policy_id == policy_id

    @pytest.mark.asyncio
    async def test_get_policy_not_found(
        self, query: GetPolicyQuery, policy_repository: AsyncMock
    ) -> None:
        """Test retrieving non-existent policy."""
        policy_id = uuid4()
        tenant_id = uuid4()

        # Mock repository to return None
        policy_repository.find_by_id.return_value = None

        # Execute query
        result = await query.execute(policy_id, tenant_id)

        # Verify
        assert result is None


class TestListPoliciesQuery:
    """Test ListPoliciesQuery handler."""

    @pytest.fixture
    def policy_repository(self) -> AsyncMock:
        """Mock policy repository."""
        from domain.policy.repository import PolicyRepository

        return AsyncMock(spec=PolicyRepository)

    @pytest.fixture
    def query(self, policy_repository: AsyncMock) -> ListPoliciesQuery:
        """Create query instance."""
        return ListPoliciesQuery(policy_repository)

    @pytest.mark.asyncio
    async def test_list_policies_with_status_filter(
        self, query: ListPoliciesQuery, policy_repository: AsyncMock
    ) -> None:
        """Test listing policies with status filter."""
        tenant_id = uuid4()

        # Mock repository
        policies = [
            Policy(
                policy_id=uuid4(),
                tenant_id=tenant_id,
                name=f"policy-{i}",
                description="Test",
                created_by=uuid4(),
                status=PolicyStatus.ACTIVE,
            )
            for i in range(2)
        ]
        policy_repository.find_paginated.return_value = policies
        policy_repository.count_by_tenant.return_value = 5

        # Execute query with status filter
        result = await query.execute(tenant_id, status_filter=PolicyStatus.ACTIVE)

        # Verify
        assert isinstance(result, PolicyListResponse)
        assert len(result.policies) == 2
        assert all(p.status == "active" for p in result.policies)


class TestGetAuditEntriesQuery:
    """Test GetAuditEntriesQuery handler."""

    @pytest.fixture
    def audit_repository(self) -> AsyncMock:
        """Mock audit repository."""
        from domain.audit.repository import AuditRepository

        return AsyncMock(spec=AuditRepository)

    @pytest.fixture
    def query(self, audit_repository: AsyncMock) -> GetAuditEntriesQuery:
        """Create query instance."""
        return GetAuditEntriesQuery(audit_repository)

    @pytest.mark.asyncio
    async def test_get_audit_entries_with_time_range(
        self, query: GetAuditEntriesQuery, audit_repository: AsyncMock
    ) -> None:
        """Test retrieving audit entries with time range."""
        tenant_id = uuid4()
        start_time = datetime.now(UTC) - timedelta(days=7)
        end_time = datetime.now(UTC)

        request = AuditQueryRequest(
            tenant_id=tenant_id, start_time=start_time, end_time=end_time, page=1, page_size=50
        )

        # Mock repository
        entries = [
            AuditEntry(
                tenant_id=tenant_id,
                agent_id=uuid4(),
                domain=DomainName(value="example.com"),
                decision=AccessDecision.ALLOW,
                timed_access_metadata=TimedAccessContext.create_from_timestamp(datetime.now(UTC)),
            )
            for _ in range(3)
        ]
        audit_repository.find_by_tenant_time_range.return_value = entries
        audit_repository.count_entries_by_tenant.return_value = len(entries)

        # Execute query
        result = await query.execute(request)

        # Verify - count now respects time filters
        assert isinstance(result, AuditListResponse)
        assert len(result.entries) == 3
        assert result.total_count == len(entries)
        assert result.has_more is False
        audit_repository.count_entries_by_tenant.assert_awaited_once_with(
            tenant_id, start_time=start_time, end_time=end_time
        )

    @pytest.mark.asyncio
    async def test_get_audit_entries_invalid_page(
        self, query: GetAuditEntriesQuery, audit_repository: AsyncMock
    ) -> None:
        """Test validation of page number."""
        # Pydantic validates at DTO level
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            AuditQueryRequest(tenant_id=uuid4(), page=0)
        assert "greater than or equal to 1" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_get_audit_entries_with_decision_filter(
        self, query: GetAuditEntriesQuery, audit_repository: AsyncMock
    ) -> None:
        """Test retrieving audit entries with decision filter."""
        tenant_id = uuid4()
        request = AuditQueryRequest(tenant_id=tenant_id, decision="deny")

        # Mock repository
        audit_repository.find_by_decision.return_value = []
        audit_repository.count_entries_by_decision.return_value = 0

        # Execute query
        result = await query.execute(request)

        # Verify - decision counts use dedicated repository method
        assert isinstance(result, AuditListResponse)
        audit_repository.find_by_decision.assert_awaited_once()
        audit_repository.count_entries_by_decision.assert_awaited_once()
        assert audit_repository.count_entries_by_decision.await_args.kwargs == {
            "tenant_id": tenant_id,
            "decision": AccessDecision.DENY,
            "start_time": None,
            "end_time": None,
        }

    @pytest.mark.asyncio
    async def test_get_audit_entries_agent_filter(
        self, query: GetAuditEntriesQuery, audit_repository: AsyncMock
    ) -> None:
        """Ensure agent scoped queries use agent/time range count."""

        tenant_id = uuid4()
        agent_id = uuid4()
        start_time = datetime.now(UTC) - timedelta(days=1)
        end_time = datetime.now(UTC)

        request = AuditQueryRequest(
            tenant_id=tenant_id,
            agent_id=agent_id,
            start_time=start_time,
            end_time=end_time,
            page=1,
            page_size=10,
        )

        audit_repository.find_by_agent_time_range.return_value = []
        audit_repository.count_entries_by_agent_time_range.return_value = 0

        result = await query.execute(request)

        assert isinstance(result, AuditListResponse)
        audit_repository.count_entries_by_agent_time_range.assert_awaited_once()
        assert audit_repository.count_entries_by_agent_time_range.await_args.kwargs == {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "start_time": start_time,
            "end_time": end_time,
        }
