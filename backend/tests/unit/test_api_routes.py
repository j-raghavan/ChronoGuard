"""Tests for REST API routes."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest
from application.commands import (
    CreateAgentCommand,
    CreatePolicyCommand,
    DeletePolicyCommand,
    UpdateAgentCommand,
    UpdatePolicyCommand,
)
from application.dto import AgentDTO, AgentListResponse, PolicyDTO, PolicyListResponse
from application.queries import (
    GetAgentQuery,
    GetAuditEntriesQuery,
    GetPolicyQuery,
    ListAgentsQuery,
    ListPoliciesQuery,
)
from domain.common.exceptions import DuplicateEntityError, EntityNotFoundError
from fastapi import FastAPI
from fastapi.testclient import TestClient
from presentation.api.routes import agents_router, audit_router, health_router, policies_router


class TestHealthRoutes:
    """Test health check API routes."""

    @pytest.fixture
    def app(self) -> FastAPI:
        """Create FastAPI app with health routes."""
        app = FastAPI()
        app.include_router(health_router)
        return app

    @pytest.fixture
    def client(self, app: FastAPI) -> TestClient:
        """Create test client."""
        return TestClient(app)

    def test_health_check(self, client: TestClient) -> None:
        """Test basic health check endpoint."""
        response = client.get("/api/v1/health/")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "chronoguard"
        assert "timestamp" in data

    def test_readiness_check(self, client: TestClient) -> None:
        """Test readiness check endpoint."""
        response = client.get("/api/v1/health/ready")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"


class TestAgentRoutes:
    """Test agent API routes."""

    @pytest.fixture
    def app(self) -> FastAPI:
        """Create FastAPI app with agent routes."""
        app = FastAPI()
        app.include_router(agents_router)
        return app

    @pytest.fixture
    def client(self, app: FastAPI) -> TestClient:
        """Create test client."""
        return TestClient(app)

    @pytest.fixture
    def agent_dto(self) -> AgentDTO:
        """Create sample AgentDTO."""
        return AgentDTO(
            agent_id=uuid4(),
            tenant_id=uuid4(),
            name="test-agent",
            status="active",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            version=1,
        )

    def test_create_agent_success(
        self, app: FastAPI, client: TestClient, agent_dto: AgentDTO
    ) -> None:
        """Test successful agent creation."""
        from presentation.api.dependencies import get_create_agent_command

        mock_command = AsyncMock(spec=CreateAgentCommand)
        mock_command.execute.return_value = agent_dto

        app.dependency_overrides[get_create_agent_command] = lambda: mock_command

        response = client.post(
            "/api/v1/agents/",
            json={
                "name": "test-agent",
                "certificate_pem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            },
            headers={"X-Tenant-ID": str(agent_dto.tenant_id)},
        )

        assert response.status_code == 201
        assert response.json()["name"] == "test-agent"

    def test_create_agent_duplicate(
        self, app: FastAPI, client: TestClient, agent_dto: AgentDTO
    ) -> None:
        """Test creating duplicate agent."""
        from presentation.api.dependencies import get_create_agent_command

        mock_command = AsyncMock(spec=CreateAgentCommand)
        mock_command.execute.side_effect = DuplicateEntityError("Agent", "name", "duplicate")

        app.dependency_overrides[get_create_agent_command] = lambda: mock_command

        response = client.post(
            "/api/v1/agents/",
            json={
                "name": "duplicate",
                "certificate_pem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            },
            headers={"X-Tenant-ID": str(agent_dto.tenant_id)},
        )

        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]

    def test_get_agent_success(self, app: FastAPI, client: TestClient, agent_dto: AgentDTO) -> None:
        """Test successfully retrieving an agent."""
        from presentation.api.dependencies import get_get_agent_query

        mock_query = AsyncMock(spec=GetAgentQuery)
        mock_query.execute.return_value = agent_dto

        app.dependency_overrides[get_get_agent_query] = lambda: mock_query

        response = client.get(
            f"/api/v1/agents/{agent_dto.agent_id}",
            headers={"X-Tenant-ID": str(agent_dto.tenant_id)},
        )

        assert response.status_code == 200
        assert response.json()["agent_id"] == str(agent_dto.agent_id)

    def test_get_agent_not_found(self, app: FastAPI, client: TestClient) -> None:
        """Test retrieving non-existent agent."""
        from presentation.api.dependencies import get_get_agent_query

        mock_query = AsyncMock(spec=GetAgentQuery)
        mock_query.execute.return_value = None

        app.dependency_overrides[get_get_agent_query] = lambda: mock_query

        agent_id = uuid4()
        tenant_id = uuid4()
        response = client.get(
            f"/api/v1/agents/{agent_id}",
            headers={"X-Tenant-ID": str(tenant_id)},
        )

        assert response.status_code == 404

    def test_list_agents(self, app: FastAPI, client: TestClient, agent_dto: AgentDTO) -> None:
        """Test listing agents."""
        from presentation.api.dependencies import get_list_agents_query

        mock_query = AsyncMock(spec=ListAgentsQuery)
        mock_query.execute.return_value = AgentListResponse(
            agents=[agent_dto], total_count=1, page=1, page_size=50
        )

        app.dependency_overrides[get_list_agents_query] = lambda: mock_query

        response = client.get(
            "/api/v1/agents/",
            headers={"X-Tenant-ID": str(agent_dto.tenant_id)},
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data["agents"]) == 1
        assert data["total_count"] == 1

    def test_update_agent_success(
        self, app: FastAPI, client: TestClient, agent_dto: AgentDTO
    ) -> None:
        """Test successful agent update."""
        from presentation.api.dependencies import get_update_agent_command

        mock_command = AsyncMock(spec=UpdateAgentCommand)
        updated_dto = agent_dto.model_copy(update={"name": "updated-agent"})
        mock_command.execute.return_value = updated_dto

        app.dependency_overrides[get_update_agent_command] = lambda: mock_command

        response = client.put(
            f"/api/v1/agents/{agent_dto.agent_id}",
            json={"name": "updated-agent"},
            headers={"X-Tenant-ID": str(agent_dto.tenant_id)},
        )

        assert response.status_code == 200
        assert response.json()["name"] == "updated-agent"


class TestPolicyRoutes:
    """Test policy API routes."""

    @pytest.fixture
    def app(self) -> FastAPI:
        """Create FastAPI app with policy routes."""
        app = FastAPI()
        app.include_router(policies_router)
        return app

    @pytest.fixture
    def client(self, app: FastAPI) -> TestClient:
        """Create test client."""
        return TestClient(app)

    @pytest.fixture
    def policy_dto(self) -> PolicyDTO:
        """Create sample PolicyDTO."""
        return PolicyDTO(
            policy_id=uuid4(),
            tenant_id=uuid4(),
            name="test-policy",
            description="Test description",
            priority=500,
            status="draft",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            created_by=uuid4(),
            version=1,
        )

    def test_create_policy_success(
        self, app: FastAPI, client: TestClient, policy_dto: PolicyDTO
    ) -> None:
        """Test successful policy creation."""
        from presentation.api.dependencies import get_create_policy_command

        mock_command = AsyncMock(spec=CreatePolicyCommand)
        mock_command.execute.return_value = policy_dto

        app.dependency_overrides[get_create_policy_command] = lambda: mock_command

        response = client.post(
            "/api/v1/policies/",
            json={"name": "test-policy", "description": "Test description"},
            headers={
                "X-Tenant-ID": str(policy_dto.tenant_id),
                "X-User-ID": str(policy_dto.created_by),
            },
        )

        assert response.status_code == 201
        assert response.json()["name"] == "test-policy"

    def test_get_policy_success(
        self, app: FastAPI, client: TestClient, policy_dto: PolicyDTO
    ) -> None:
        """Test successfully retrieving a policy."""
        from presentation.api.dependencies import get_get_policy_query

        mock_query = AsyncMock(spec=GetPolicyQuery)
        mock_query.execute.return_value = policy_dto

        app.dependency_overrides[get_get_policy_query] = lambda: mock_query

        response = client.get(
            f"/api/v1/policies/{policy_dto.policy_id}",
            headers={"X-Tenant-ID": str(policy_dto.tenant_id)},
        )

        assert response.status_code == 200
        assert response.json()["policy_id"] == str(policy_dto.policy_id)

    def test_delete_policy_success(
        self, app: FastAPI, client: TestClient, policy_dto: PolicyDTO
    ) -> None:
        """Test successful policy deletion."""
        from presentation.api.dependencies import get_delete_policy_command

        mock_command = AsyncMock(spec=DeletePolicyCommand)
        mock_command.execute.return_value = True

        app.dependency_overrides[get_delete_policy_command] = lambda: mock_command

        response = client.delete(
            f"/api/v1/policies/{policy_dto.policy_id}",
            headers={"X-Tenant-ID": str(policy_dto.tenant_id)},
        )

        assert response.status_code == 204
