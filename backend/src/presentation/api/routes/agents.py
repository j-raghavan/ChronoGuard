"""Agent management API routes.

This module provides REST API endpoints for agent CRUD operations.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from application.commands import CreateAgentCommand, UpdateAgentCommand
from application.dto import AgentDTO, AgentListResponse, CreateAgentRequest, UpdateAgentRequest
from application.queries import GetAgentQuery, ListAgentsQuery
from domain.agent.entity import AgentStatus
from domain.common.exceptions import DuplicateEntityError, EntityNotFoundError
from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger
from presentation.api.dependencies import (
    get_create_agent_command,
    get_get_agent_query,
    get_list_agents_query,
    get_tenant_id,
    get_update_agent_command,
)

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


@router.post("/", response_model=AgentDTO, status_code=status.HTTP_201_CREATED)
async def create_agent(
    request: CreateAgentRequest,
    tenant_id: Annotated[UUID, Depends(get_tenant_id)],
    create_command: CreateAgentCommand = Depends(get_create_agent_command),
) -> AgentDTO:
    """Create a new agent.

    Args:
        request: Agent creation request
        tenant_id: Current tenant ID
        create_command: Injected create command handler

    Returns:
        Created agent details

    Raises:
        HTTPException: 400 if validation fails, 409 if duplicate exists, 500 on error
    """
    try:
        return await create_command.execute(request, tenant_id)

    except DuplicateEntityError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Agent {e.field} '{e.value}' already exists",
        ) from e
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:
        logger.opt(exception=True).error(f"Failed to create agent: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create agent",
        ) from e


@router.get("/{agent_id}", response_model=AgentDTO)
async def get_agent(
    agent_id: UUID,
    tenant_id: Annotated[UUID, Depends(get_tenant_id)],
    get_query: GetAgentQuery = Depends(get_get_agent_query),
) -> AgentDTO:
    """Retrieve an agent by ID.

    Args:
        agent_id: Agent identifier
        tenant_id: Current tenant ID
        get_query: Injected get query handler

    Returns:
        Agent details

    Raises:
        HTTPException: 404 if agent not found
    """
    result = await get_query.execute(agent_id, tenant_id)

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    return result


@router.get("/", response_model=AgentListResponse)
async def list_agents(
    tenant_id: Annotated[UUID, Depends(get_tenant_id)],
    page: int = 1,
    page_size: int = 50,
    status_filter: AgentStatus | None = None,
    list_query: ListAgentsQuery = Depends(get_list_agents_query),
) -> AgentListResponse:
    """List all agents for a tenant.

    Args:
        tenant_id: Current tenant ID
        page: Page number (default: 1)
        page_size: Items per page (default: 50, max: 1000)
        status_filter: Optional status filter
        list_query: Injected list query handler

    Returns:
        Paginated list of agents

    Raises:
        HTTPException: 400 if pagination parameters are invalid
    """
    try:
        return await list_query.execute(tenant_id, page, page_size, status_filter)

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.put("/{agent_id}", response_model=AgentDTO)
async def update_agent(
    agent_id: UUID,
    tenant_id: Annotated[UUID, Depends(get_tenant_id)],
    request: UpdateAgentRequest,
    update_command: UpdateAgentCommand = Depends(get_update_agent_command),
) -> AgentDTO:
    """Update an existing agent.

    Args:
        agent_id: Agent identifier
        tenant_id: Current tenant ID
        request: Update request (all fields optional)
        update_command: Injected update command handler

    Returns:
        Updated agent details

    Raises:
        HTTPException: 404 if agent not found, 400 if validation fails
    """
    try:
        return await update_command.execute(agent_id, tenant_id, request)

    except EntityNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        ) from e
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:
        logger.opt(exception=True).error(f"Failed to update agent: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update agent",
        ) from e
