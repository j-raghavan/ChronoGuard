"""Tests for REST API routes."""

from collections.abc import Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
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
from core.security import create_access_token
from domain.common.exceptions import DuplicateEntityError, EntityNotFoundError
from fastapi import FastAPI
from fastapi.testclient import TestClient
from presentation.api.routes import agents_router, audit_router, health_router, policies_router


@pytest.fixture
def auth_headers_factory() -> Callable[[UUID, UUID | None], dict[str, str]]:
    """Factory to build auth headers with JWT tokens."""

    def _factory(tenant_id: UUID, user_id: UUID | None = None) -> dict[str, str]:
        actual_user = user_id or tenant_id
        token = create_access_token(
            {
                "sub": str(actual_user),
                "user_id": str(actual_user),
                "tenant_id": str(tenant_id),
            }
        )
        return {
            "Authorization": f"Bearer {token}",
            "X-Tenant-ID": str(tenant_id),
            "X-User-ID": str(actual_user),
        }

    return _factory


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
        with patch("sqlalchemy.ext.asyncio.create_async_engine") as mock_engine_ctor:

            class DummyConnection:
                async def execute(self, *_args: Any, **_kwargs: Any) -> None:
                    return None

            class DummyConnectionCtx:
                async def __aenter__(self) -> DummyConnection:
                    return DummyConnection()

                async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
                    return False

            class DummyEngine:
                def connect(self) -> DummyConnectionCtx:
                    return DummyConnectionCtx()

                async def dispose(self) -> None:
                    return None

            mock_engine_ctor.return_value = DummyEngine()

            response = client.get("/api/v1/health/ready")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"

    def test_metrics_summary(
        self,
        client: TestClient,
        auth_headers_factory: Callable[[UUID, UUID | None], dict[str, str]],
    ) -> None:
        """Test metrics summary endpoint."""
        tenant_id = UUID("550e8400-e29b-41d4-a716-446655440000")

        from unittest.mock import AsyncMock, MagicMock

        from domain.agent.entity import Agent, AgentStatus
        from domain.policy.entity import Policy
        from presentation.api.routes import health

        # Mock repositories
        mock_agent_repo = MagicMock()
        mock_policy_repo = MagicMock()

        # Create mock agents
        mock_agent_1 = MagicMock()
        mock_agent_1.status = "active"
        mock_agent_2 = MagicMock()
        mock_agent_2.status = "active"
        mock_agent_3 = MagicMock()
        mock_agent_3.status = "suspended"
        mock_agents = [mock_agent_1, mock_agent_2, mock_agent_3]
        mock_agent_repo.find_by_tenant_id = AsyncMock(return_value=mock_agents)

        # Create mock policies
        mock_policy_1 = MagicMock()
        mock_policy_1.is_active.return_value = True
        mock_policy_2 = MagicMock()
        mock_policy_2.is_active.return_value = False
        mock_policies = [mock_policy_1, mock_policy_2]
        mock_policy_repo.find_by_tenant_id = AsyncMock(return_value=mock_policies)

        # Override dependencies
        original_agent_dep = health.get_agent_repository
        original_policy_dep = health.get_policy_repository
        health.get_agent_repository = lambda: mock_agent_repo
        health.get_policy_repository = lambda: mock_policy_repo

        try:
            response = client.get("/api/v1/health/metrics", headers=auth_headers_factory(tenant_id))

            assert response.status_code == 200
            data = response.json()
            assert "agents" in data
            assert "policies" in data
            assert data["agents"]["total"] == 3
            assert data["agents"]["active"] == 2
            assert data["policies"]["total"] == 2
        finally:
            health.get_agent_repository = original_agent_dep
            health.get_policy_repository = original_policy_dep


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
        self, app: FastAPI, client: TestClient, agent_dto: AgentDTO, auth_headers_factory
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
            headers=auth_headers_factory(agent_dto.tenant_id),
        )

        assert response.status_code == 201
        assert response.json()["name"] == "test-agent"

    def test_create_agent_duplicate(
        self, app: FastAPI, client: TestClient, agent_dto: AgentDTO, auth_headers_factory
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
            headers=auth_headers_factory(agent_dto.tenant_id),
        )

        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]

    def test_get_agent_success(
        self, app: FastAPI, client: TestClient, agent_dto: AgentDTO, auth_headers_factory
    ) -> None:
        """Test successfully retrieving an agent."""
        from presentation.api.dependencies import get_get_agent_query

        mock_query = AsyncMock(spec=GetAgentQuery)
        mock_query.execute.return_value = agent_dto

        app.dependency_overrides[get_get_agent_query] = lambda: mock_query

        response = client.get(
            f"/api/v1/agents/{agent_dto.agent_id}",
            headers=auth_headers_factory(agent_dto.tenant_id),
        )

        assert response.status_code == 200
        assert response.json()["agent_id"] == str(agent_dto.agent_id)

    def test_get_agent_not_found(
        self, app: FastAPI, client: TestClient, auth_headers_factory
    ) -> None:
        """Test retrieving non-existent agent."""
        from presentation.api.dependencies import get_get_agent_query

        mock_query = AsyncMock(spec=GetAgentQuery)
        mock_query.execute.return_value = None

        app.dependency_overrides[get_get_agent_query] = lambda: mock_query

        agent_id = uuid4()
        tenant_id = uuid4()
        response = client.get(f"/api/v1/agents/{agent_id}", headers=auth_headers_factory(tenant_id))

        assert response.status_code == 404

    def test_list_agents(
        self, app: FastAPI, client: TestClient, agent_dto: AgentDTO, auth_headers_factory
    ) -> None:
        """Test listing agents."""
        from presentation.api.dependencies import get_list_agents_query

        mock_query = AsyncMock(spec=ListAgentsQuery)
        mock_query.execute.return_value = AgentListResponse(
            agents=[agent_dto], total_count=1, page=1, page_size=50
        )

        app.dependency_overrides[get_list_agents_query] = lambda: mock_query

        response = client.get("/api/v1/agents/", headers=auth_headers_factory(agent_dto.tenant_id))

        assert response.status_code == 200
        data = response.json()
        assert len(data["agents"]) == 1
        assert data["total_count"] == 1

    def test_update_agent_success(
        self, app: FastAPI, client: TestClient, agent_dto: AgentDTO, auth_headers_factory
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
            headers=auth_headers_factory(agent_dto.tenant_id),
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
        self, app: FastAPI, client: TestClient, policy_dto: PolicyDTO, auth_headers_factory
    ) -> None:
        """Test successful policy creation."""
        from presentation.api.dependencies import get_create_policy_command

        mock_command = AsyncMock(spec=CreatePolicyCommand)
        mock_command.execute.return_value = policy_dto

        app.dependency_overrides[get_create_policy_command] = lambda: mock_command

        response = client.post(
            "/api/v1/policies/",
            json={"name": "test-policy", "description": "Test description"},
            headers=auth_headers_factory(policy_dto.tenant_id, policy_dto.created_by),
        )

        assert response.status_code == 201
        assert response.json()["name"] == "test-policy"

    def test_get_policy_success(
        self, app: FastAPI, client: TestClient, policy_dto: PolicyDTO, auth_headers_factory
    ) -> None:
        """Test successfully retrieving a policy."""
        from presentation.api.dependencies import get_get_policy_query

        mock_query = AsyncMock(spec=GetPolicyQuery)
        mock_query.execute.return_value = policy_dto

        app.dependency_overrides[get_get_policy_query] = lambda: mock_query

        response = client.get(
            f"/api/v1/policies/{policy_dto.policy_id}",
            headers=auth_headers_factory(policy_dto.tenant_id),
        )

        assert response.status_code == 200
        assert response.json()["policy_id"] == str(policy_dto.policy_id)

    def test_delete_policy_success(
        self, app: FastAPI, client: TestClient, policy_dto: PolicyDTO, auth_headers_factory
    ) -> None:
        """Test successful policy deletion."""
        from presentation.api.dependencies import get_delete_policy_command

        mock_command = AsyncMock(spec=DeletePolicyCommand)
        mock_command.execute.return_value = True

        app.dependency_overrides[get_delete_policy_command] = lambda: mock_command

        response = client.delete(
            f"/api/v1/policies/{policy_dto.policy_id}",
            headers=auth_headers_factory(policy_dto.tenant_id),
        )

        assert response.status_code == 204


class TestAuthRoutes:
    """Tests for authentication routes."""

    @pytest.fixture
    def app(self) -> FastAPI:
        app = FastAPI()
        from presentation.api.routes import auth_router

        app.include_router(auth_router)
        return app

    @pytest.fixture
    def client(self, app: FastAPI) -> TestClient:
        return TestClient(app)

    def test_login_success(self, client: TestClient) -> None:
        """Login with correct password returns token."""
        response = client.post(
            "/api/v1/auth/login",
            json={"password": "chronoguard-admin-2025"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_invalid_password(self, client: TestClient) -> None:
        """Invalid credentials return 401."""
        response = client.post(
            "/api/v1/auth/login",
            json={"password": "wrong-password"},
        )

        assert response.status_code == 401
