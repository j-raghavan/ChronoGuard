"""FastAPI dependency providers.

This module provides dependency injection functions for FastAPI routes, creating
instances of commands, queries, and services with their required dependencies.

Production Implementation:
    - Uses real PostgreSQL repository implementations
    - Repositories are configured with database connection from environment
    - Services and commands are properly wired with real dependencies
"""

from __future__ import annotations

import os
from typing import Annotated
from uuid import UUID

from fastapi import Header, HTTPException, status

from application.commands import (
    CreateAgentCommand,
    CreatePolicyCommand,
    DeletePolicyCommand,
    UpdateAgentCommand,
    UpdatePolicyCommand,
)
from application.queries import (
    GetAgentQuery,
    GetPolicyQuery,
    ListAgentsQuery,
    ListPoliciesQuery,
)
from domain.agent.service import AgentService
from domain.policy.service import PolicyService
from infrastructure.persistence.postgres.agent_repository import PostgresAgentRepository
from infrastructure.persistence.postgres.policy_repository import PostgresPolicyRepository


def get_database_url() -> str:
    """Get database URL from environment with fallback.

    Returns:
        Database connection URL

    Note:
        In production, DATABASE_URL should be set via environment variable.
        For development/testing, uses a default value.
    """
    return os.getenv(
        "DATABASE_URL", "postgresql://chronoguard:devpassword@localhost:5433/chronoguard_dev"
    )


# Repository instances (singleton pattern for connection pooling)
_agent_repository: PostgresAgentRepository | None = None
_policy_repository: PostgresPolicyRepository | None = None


def get_agent_repository() -> PostgresAgentRepository:
    """Get or create AgentRepository instance.

    Returns:
        PostgresAgentRepository connected to database

    Note:
        Uses singleton pattern to reuse connection pool across requests.
    """
    global _agent_repository
    if _agent_repository is None:
        _agent_repository = PostgresAgentRepository(get_database_url())
    return _agent_repository


def get_policy_repository() -> PostgresPolicyRepository:
    """Get or create PolicyRepository instance.

    Returns:
        PostgresPolicyRepository connected to database

    Note:
        Uses singleton pattern to reuse connection pool across requests.
    """
    global _policy_repository
    if _policy_repository is None:
        _policy_repository = PostgresPolicyRepository(get_database_url())
    return _policy_repository


async def get_tenant_id(
    x_tenant_id: Annotated[str | None, Header()] = None,
) -> UUID:
    """Extract tenant ID from request header.

    Args:
        x_tenant_id: Tenant ID from X-Tenant-ID header

    Returns:
        Validated tenant UUID

    Raises:
        HTTPException: 401 if tenant ID is missing or invalid
    """
    if x_tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-Tenant-ID header is required",
        )

    try:
        return UUID(x_tenant_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid tenant ID format: {x_tenant_id}",
        ) from e


async def get_user_id(
    x_user_id: Annotated[str | None, Header()] = None,
) -> UUID:
    """Extract user ID from request header.

    Args:
        x_user_id: User ID from X-User-ID header

    Returns:
        Validated user UUID

    Raises:
        HTTPException: 401 if user ID is missing or invalid
    """
    if x_user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-User-ID header is required",
        )

    try:
        return UUID(x_user_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid user ID format: {x_user_id}",
        ) from e


# Command providers - Production implementations with real repositories/services


def get_create_agent_command() -> CreateAgentCommand:
    """Provide CreateAgentCommand with real AgentService.

    Returns:
        CreateAgentCommand instance with production dependencies
    """
    agent_repository = get_agent_repository()
    agent_service = AgentService(agent_repository)
    return CreateAgentCommand(agent_service)


def get_update_agent_command() -> UpdateAgentCommand:
    """Provide UpdateAgentCommand with real AgentRepository.

    Returns:
        UpdateAgentCommand instance with production dependencies
    """
    agent_repository = get_agent_repository()
    return UpdateAgentCommand(agent_repository)


def get_create_policy_command() -> CreatePolicyCommand:
    """Provide CreatePolicyCommand with real PolicyService.

    Returns:
        CreatePolicyCommand instance with production dependencies
    """
    policy_repository = get_policy_repository()
    agent_repository = get_agent_repository()
    policy_service = PolicyService(policy_repository, agent_repository)
    return CreatePolicyCommand(policy_service)


def get_update_policy_command() -> UpdatePolicyCommand:
    """Provide UpdatePolicyCommand with real PolicyRepository.

    Returns:
        UpdatePolicyCommand instance with production dependencies
    """
    policy_repository = get_policy_repository()
    return UpdatePolicyCommand(policy_repository)


def get_delete_policy_command() -> DeletePolicyCommand:
    """Provide DeletePolicyCommand with real PolicyRepository.

    Returns:
        DeletePolicyCommand instance with production dependencies
    """
    policy_repository = get_policy_repository()
    return DeletePolicyCommand(policy_repository)


# Query providers - Production implementations with real repositories


def get_get_agent_query() -> GetAgentQuery:
    """Provide GetAgentQuery with real AgentRepository.

    Returns:
        GetAgentQuery instance with production dependencies
    """
    agent_repository = get_agent_repository()
    return GetAgentQuery(agent_repository)


def get_list_agents_query() -> ListAgentsQuery:
    """Provide ListAgentsQuery with real AgentRepository.

    Returns:
        ListAgentsQuery instance with production dependencies
    """
    agent_repository = get_agent_repository()
    return ListAgentsQuery(agent_repository)


def get_get_policy_query() -> GetPolicyQuery:
    """Provide GetPolicyQuery with real PolicyRepository.

    Returns:
        GetPolicyQuery instance with production dependencies
    """
    policy_repository = get_policy_repository()
    return GetPolicyQuery(policy_repository)


def get_list_policies_query() -> ListPoliciesQuery:
    """Provide ListPoliciesQuery with real PolicyRepository.

    Returns:
        ListPoliciesQuery instance with production dependencies
    """
    policy_repository = get_policy_repository()
    return ListPoliciesQuery(policy_repository)
