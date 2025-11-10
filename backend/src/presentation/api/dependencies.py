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
from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import Header, HTTPException, Request, status

from application.commands import (
    CreateAgentCommand,
    CreatePolicyCommand,
    DeletePolicyCommand,
    UpdateAgentCommand,
    UpdatePolicyCommand,
)
from application.queries import (
    GetAgentQuery,
    GetAuditEntriesQuery,
    GetPolicyQuery,
    ListAgentsQuery,
    ListPoliciesQuery,
)
from application.queries.audit_export import AuditExporter
from application.queries.temporal_analytics import TemporalAnalyticsQuery
from core.config import ProxySettings
from core.security import TokenError, decode_token
from domain.agent.service import AgentService
from domain.audit.service import AuditService
from domain.policy.service import PolicyService
from infrastructure.opa.client import OPAClient
from infrastructure.opa.policy_compiler import PolicyCompiler
from infrastructure.persistence.postgres.agent_repository import PostgresAgentRepository
from infrastructure.persistence.postgres.audit_repository import PostgresAuditRepository
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
_audit_repository: PostgresAuditRepository | None = None


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


def get_audit_repository() -> PostgresAuditRepository:
    """Get or create AuditRepository instance.

    Returns:
        PostgresAuditRepository connected to database

    Note:
        Uses singleton pattern to reuse connection pool across requests.
    """
    global _audit_repository
    if _audit_repository is None:
        _audit_repository = PostgresAuditRepository(get_database_url())
    return _audit_repository


def get_audit_service() -> AuditService:
    """Get or create AuditService instance.

    Returns:
        AuditService instance with production dependencies
    """
    audit_repository = get_audit_repository()
    secret_key = os.getenv("AUDIT_SECRET_KEY")
    secret_key_bytes = secret_key.encode() if secret_key else None
    return AuditService(
        audit_repository=audit_repository,
        secret_key=secret_key_bytes,
        time_source=None,
        signer=None,
    )


def get_opa_client() -> OPAClient:
    """Get or create OPAClient instance.

    Returns:
        OPAClient configured with OPA URL from environment

    Note:
        OPA URL defaults to http://localhost:8181 for development
    """
    proxy_settings = ProxySettings()
    return OPAClient(settings=proxy_settings)


def get_policy_compiler() -> PolicyCompiler:
    """Get or create PolicyCompiler instance.

    Returns:
        PolicyCompiler for converting policies to Rego
    """
    # Template directory is in backend/templates/rego
    template_dir = Path(__file__).parent.parent.parent.parent / "templates" / "rego"
    proxy_settings = ProxySettings()
    return PolicyCompiler(template_dir=template_dir, opa_url=proxy_settings.opa_url)


def _decode_authorization_token(authorization: str | None) -> dict[str, str]:
    """Decode and validate the Authorization bearer token."""

    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header is required",
        )

    scheme, _, token = authorization.partition(" ")
    if token == "":  # nosec B105  # False positive: checking empty string, not hardcoded password
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format",
        )

    if scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization scheme must be Bearer",
        )

    try:
        payload = decode_token(token)
    except TokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {e}",
        ) from e

    return payload


async def get_tenant_id(
    request: Request,
    x_tenant_id: Annotated[str | None, Header()] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> UUID:
    """Extract tenant ID from the bearer token (and optional header)."""

    payload = getattr(request.state, "user", None)
    if payload is None:
        payload = _decode_authorization_token(authorization)
    token_tenant_id = payload.get("tenant_id")

    if token_tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing tenant scope",
        )

    if x_tenant_id and x_tenant_id != token_tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant ID mismatch between token and header",
        )

    tenant_value = x_tenant_id or token_tenant_id

    try:
        return UUID(tenant_value)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid tenant ID format: {tenant_value}",
        ) from e


async def get_user_id(
    request: Request,
    x_user_id: Annotated[str | None, Header()] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> UUID:
    """Extract user ID from the bearer token (and optional header)."""

    payload = getattr(request.state, "user", None)
    if payload is None:
        payload = _decode_authorization_token(authorization)
    token_user_id = payload.get("user_id") or payload.get("sub")

    if token_user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing user subject",
        )

    if x_user_id and x_user_id != token_user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User ID mismatch between token and header",
        )

    user_value = x_user_id or token_user_id

    try:
        return UUID(user_value)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid user ID format: {user_value}",
        ) from e


# Command providers - Production implementations with real repositories/services


def get_create_agent_command() -> CreateAgentCommand:
    """Provide CreateAgentCommand with real AgentService.

    Returns:
        CreateAgentCommand instance with production dependencies
    """
    agent_repository = get_agent_repository()
    agent_service = AgentService(agent_repository)
    audit_service = get_audit_service()

    return CreateAgentCommand(agent_service, audit_service=audit_service)


def get_update_agent_command() -> UpdateAgentCommand:
    """Provide UpdateAgentCommand with real AgentRepository.

    Returns:
        UpdateAgentCommand instance with production dependencies
    """
    agent_repository = get_agent_repository()
    audit_service = get_audit_service()

    return UpdateAgentCommand(agent_repository, audit_service=audit_service)


def get_create_policy_command() -> CreatePolicyCommand:
    """Provide CreatePolicyCommand with real PolicyService.

    Returns:
        CreatePolicyCommand instance with production dependencies
    """
    policy_repository = get_policy_repository()
    agent_repository = get_agent_repository()
    policy_service = PolicyService(policy_repository, agent_repository)

    # Add OPA integration
    opa_client = get_opa_client()
    policy_compiler = get_policy_compiler()

    # Add audit service
    audit_service = get_audit_service()

    return CreatePolicyCommand(
        policy_service,
        opa_client=opa_client,
        policy_compiler=policy_compiler,
        audit_service=audit_service,
    )


def get_update_policy_command() -> UpdatePolicyCommand:
    """Provide UpdatePolicyCommand with real PolicyRepository.

    Returns:
        UpdatePolicyCommand instance with production dependencies
    """
    policy_repository = get_policy_repository()

    # Add OPA integration
    opa_client = get_opa_client()
    policy_compiler = get_policy_compiler()

    # Add audit service
    audit_service = get_audit_service()

    return UpdatePolicyCommand(
        policy_repository,
        opa_client=opa_client,
        policy_compiler=policy_compiler,
        audit_service=audit_service,
    )


def get_delete_policy_command() -> DeletePolicyCommand:
    """Provide DeletePolicyCommand with real PolicyRepository.

    Returns:
        DeletePolicyCommand instance with production dependencies
    """
    policy_repository = get_policy_repository()

    # Add OPA integration
    opa_client = get_opa_client()

    # Add audit service
    audit_service = get_audit_service()

    return DeletePolicyCommand(
        policy_repository,
        opa_client=opa_client,
        audit_service=audit_service,
    )


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


def get_temporal_analytics_query() -> TemporalAnalyticsQuery:
    """Provide TemporalAnalyticsQuery with real AuditRepository.

    Returns:
        TemporalAnalyticsQuery instance with production dependencies
    """
    audit_repository = get_audit_repository()
    return TemporalAnalyticsQuery(audit_repository)


def get_audit_exporter() -> AuditExporter:
    """Provide AuditExporter with real AuditRepository.

    Returns:
        AuditExporter instance with production dependencies
    """
    audit_repository = get_audit_repository()
    return AuditExporter(audit_repository)


def get_audit_entries_query() -> GetAuditEntriesQuery:
    """Provide GetAuditEntriesQuery with real AuditRepository.

    Returns:
        GetAuditEntriesQuery instance with production dependencies
    """
    audit_repository = get_audit_repository()
    return GetAuditEntriesQuery(audit_repository)
