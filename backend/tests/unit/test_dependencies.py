"""Tests for FastAPI dependency providers."""

from typing import Any
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException, Request

from core.security import create_access_token
from presentation.api.dependencies import (
    get_create_agent_command,
    get_create_policy_command,
    get_delete_policy_command,
    get_get_agent_query,
    get_get_policy_query,
    get_list_agents_query,
    get_list_policies_query,
    get_tenant_id,
    get_update_agent_command,
    get_update_policy_command,
    get_user_id,
)


class TestTenantDependency:
    """Test tenant ID extraction from headers."""

    @pytest.mark.asyncio
    async def test_get_tenant_id_valid(self) -> None:
        """Test extracting valid tenant ID from header with JWT."""
        tenant_id = uuid4()
        user_id = uuid4()

        # Create valid JWT token
        token = create_access_token(
            {
                "sub": str(user_id),
                "user_id": str(user_id),
                "tenant_id": str(tenant_id),
            }
        )

        # Create mock request
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.user = None

        result = await get_tenant_id(
            request=request, x_tenant_id=str(tenant_id), authorization=f"Bearer {token}"
        )

        assert isinstance(result, UUID)
        assert result == tenant_id

    @pytest.mark.asyncio
    async def test_get_tenant_id_missing(self) -> None:
        """Test missing tenant ID header."""
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.user = None

        with pytest.raises(HTTPException) as exc_info:
            await get_tenant_id(request=request, x_tenant_id=None, authorization=None)

        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_get_tenant_id_invalid_format(self) -> None:
        """Test invalid UUID format in header."""
        tenant_id = uuid4()
        user_id = uuid4()

        # Create valid JWT token with valid tenant_id
        token = create_access_token(
            {
                "sub": str(user_id),
                "user_id": str(user_id),
                "tenant_id": str(tenant_id),
            }
        )

        # But provide invalid format in header (mismatch detected before format validation)
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.user = None

        with pytest.raises(HTTPException) as exc_info:
            await get_tenant_id(
                request=request, x_tenant_id="invalid-uuid", authorization=f"Bearer {token}"
            )

        # Returns 403 for mismatch (security check happens before UUID format check)
        assert exc_info.value.status_code == 403
        assert "mismatch" in exc_info.value.detail.lower()


class TestUserDependency:
    """Test user ID extraction from headers."""

    @pytest.mark.asyncio
    async def test_get_user_id_valid(self) -> None:
        """Test extracting valid user ID from header with JWT."""
        tenant_id = uuid4()
        user_id = uuid4()

        # Create valid JWT token
        token = create_access_token(
            {
                "sub": str(user_id),
                "user_id": str(user_id),
                "tenant_id": str(tenant_id),
            }
        )

        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.user = None

        result = await get_user_id(
            request=request, x_user_id=str(user_id), authorization=f"Bearer {token}"
        )

        assert isinstance(result, UUID)
        assert result == user_id

    @pytest.mark.asyncio
    async def test_get_user_id_missing(self) -> None:
        """Test missing user ID header."""
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.user = None

        with pytest.raises(HTTPException) as exc_info:
            await get_user_id(request=request, x_user_id=None, authorization=None)

        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_get_user_id_invalid_format(self) -> None:
        """Test invalid UUID format in header."""
        tenant_id = uuid4()
        user_id = uuid4()

        # Create valid JWT token
        token = create_access_token(
            {
                "sub": str(user_id),
                "user_id": str(user_id),
                "tenant_id": str(tenant_id),
            }
        )

        # But provide invalid format in header (mismatch detected before format validation)
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.user = None

        with pytest.raises(HTTPException) as exc_info:
            await get_user_id(
                request=request, x_user_id="not-a-uuid", authorization=f"Bearer {token}"
            )

        # Returns 403 for mismatch (security check happens before UUID format check)
        assert exc_info.value.status_code == 403
        assert "mismatch" in exc_info.value.detail.lower()


class TestRepositoryProviders:
    """Test repository dependency providers."""

    def test_get_agent_repository(self) -> None:
        """Test AgentRepository provider."""
        from infrastructure.persistence.postgres.agent_repository import PostgresAgentRepository
        from presentation.api.dependencies import get_agent_repository

        repo = get_agent_repository()
        assert isinstance(repo, PostgresAgentRepository)

    def test_get_policy_repository(self) -> None:
        """Test PolicyRepository provider."""
        from infrastructure.persistence.postgres.policy_repository import PostgresPolicyRepository
        from presentation.api.dependencies import get_policy_repository

        repo = get_policy_repository()
        assert isinstance(repo, PostgresPolicyRepository)

    def test_repository_singleton_pattern(self) -> None:
        """Test repositories use singleton pattern."""
        from presentation.api.dependencies import get_agent_repository, get_policy_repository

        # Call twice, should get same instance
        agent_repo1 = get_agent_repository()
        agent_repo2 = get_agent_repository()
        assert agent_repo1 is agent_repo2

        policy_repo1 = get_policy_repository()
        policy_repo2 = get_policy_repository()
        assert policy_repo1 is policy_repo2


class TestCommandProviders:
    """Test command dependency providers."""

    def test_get_create_agent_command(self) -> None:
        """Test CreateAgentCommand provider returns correct type."""
        from application.commands import CreateAgentCommand

        command = get_create_agent_command()
        assert isinstance(command, CreateAgentCommand)
        # Verify it has real AgentService, not mock
        assert command._agent_service is not None

    def test_get_update_agent_command(self) -> None:
        """Test UpdateAgentCommand provider returns correct type."""
        from application.commands import UpdateAgentCommand

        command = get_update_agent_command()
        assert isinstance(command, UpdateAgentCommand)
        # Verify it has real repository
        assert command._repository is not None

    def test_get_create_policy_command(self) -> None:
        """Test CreatePolicyCommand provider returns correct type."""
        from application.commands import CreatePolicyCommand

        command = get_create_policy_command()
        assert isinstance(command, CreatePolicyCommand)
        # Verify it has real PolicyService
        assert command._policy_service is not None

    def test_get_update_policy_command(self) -> None:
        """Test UpdatePolicyCommand provider returns correct type."""
        from application.commands import UpdatePolicyCommand

        command = get_update_policy_command()
        assert isinstance(command, UpdatePolicyCommand)
        # Verify it has real repository
        assert command._repository is not None

    def test_get_delete_policy_command(self) -> None:
        """Test DeletePolicyCommand provider returns correct type."""
        from application.commands import DeletePolicyCommand

        command = get_delete_policy_command()
        assert isinstance(command, DeletePolicyCommand)
        # Verify it has real repository
        assert command._repository is not None


class TestQueryProviders:
    """Test query dependency providers."""

    def test_get_get_agent_query(self) -> None:
        """Test GetAgentQuery provider returns correct type."""
        from application.queries import GetAgentQuery

        query = get_get_agent_query()
        assert isinstance(query, GetAgentQuery)
        # Verify it has real repository
        assert query._repository is not None

    def test_get_list_agents_query(self) -> None:
        """Test ListAgentsQuery provider returns correct type."""
        from application.queries import ListAgentsQuery

        query = get_list_agents_query()
        assert isinstance(query, ListAgentsQuery)
        # Verify it has real repository
        assert query._repository is not None

    def test_get_get_policy_query(self) -> None:
        """Test GetPolicyQuery provider returns correct type."""
        from application.queries import GetPolicyQuery

        query = get_get_policy_query()
        assert isinstance(query, GetPolicyQuery)
        # Verify it has real repository
        assert query._repository is not None

    def test_get_list_policies_query(self) -> None:
        """Test ListPoliciesQuery provider returns correct type."""
        from application.queries import ListPoliciesQuery

        query = get_list_policies_query()
        assert isinstance(query, ListPoliciesQuery)
        # Verify it has real repository
        assert query._repository is not None
