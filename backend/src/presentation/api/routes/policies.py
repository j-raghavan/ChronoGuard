"""Policy management API routes.

This module provides REST API endpoints for policy CRUD operations.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger

from application.commands import CreatePolicyCommand, DeletePolicyCommand, UpdatePolicyCommand
from application.dto import CreatePolicyRequest, PolicyDTO, PolicyListResponse, UpdatePolicyRequest
from application.queries import GetPolicyQuery, ListPoliciesQuery
from domain.common.exceptions import DuplicateEntityError, EntityNotFoundError
from domain.policy.entity import PolicyStatus
from presentation.api.dependencies import (
    get_create_policy_command,
    get_delete_policy_command,
    get_get_policy_query,
    get_list_policies_query,
    get_tenant_id,
    get_update_policy_command,
    get_user_id,
)


router = APIRouter(prefix="/api/v1/policies", tags=["policies"])


@router.post("/", response_model=PolicyDTO, status_code=status.HTTP_201_CREATED)
async def create_policy(
    request: CreatePolicyRequest,
    tenant_id: Annotated[UUID, Depends(get_tenant_id)],
    created_by: Annotated[UUID, Depends(get_user_id)],
    create_command: CreatePolicyCommand = Depends(get_create_policy_command),
) -> PolicyDTO:
    """Create a new policy.

    Args:
        request: Policy creation request
        tenant_id: Current tenant ID
        created_by: User ID creating the policy
        create_command: Injected create command handler

    Returns:
        Created policy details

    Raises:
        HTTPException: 400 if validation fails, 409 if duplicate exists
    """
    try:
        return await create_command.execute(request, tenant_id, created_by)

    except DuplicateEntityError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Policy {e.field} '{e.value}' already exists",
        ) from e
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:
        logger.opt(exception=True).error(f"Failed to create policy: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create policy",
        ) from e


@router.get("/{policy_id}", response_model=PolicyDTO)
async def get_policy(
    policy_id: UUID,
    tenant_id: Annotated[UUID, Depends(get_tenant_id)],
    get_query: GetPolicyQuery = Depends(get_get_policy_query),
) -> PolicyDTO:
    """Retrieve a policy by ID.

    Args:
        policy_id: Policy identifier
        tenant_id: Current tenant ID
        get_query: Injected get query handler

    Returns:
        Policy details

    Raises:
        HTTPException: 404 if policy not found
    """
    result = await get_query.execute(policy_id, tenant_id)

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy {policy_id} not found",
        )

    return result


@router.get("/", response_model=PolicyListResponse)
async def list_policies(
    tenant_id: Annotated[UUID, Depends(get_tenant_id)],
    page: int = 1,
    page_size: int = 50,
    status_filter: PolicyStatus | None = None,
    list_query: ListPoliciesQuery = Depends(get_list_policies_query),
) -> PolicyListResponse:
    """List all policies for a tenant.

    Args:
        tenant_id: Current tenant ID
        page: Page number (default: 1)
        page_size: Items per page (default: 50, max: 1000)
        status_filter: Optional status filter
        list_query: Injected list query handler

    Returns:
        Paginated list of policies

    Raises:
        HTTPException: 400 if pagination parameters are invalid
    """
    try:
        return await list_query.execute(tenant_id, page, page_size, status_filter)

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.put("/{policy_id}", response_model=PolicyDTO)
async def update_policy(
    policy_id: UUID,
    tenant_id: Annotated[UUID, Depends(get_tenant_id)],
    request: UpdatePolicyRequest,
    update_command: UpdatePolicyCommand = Depends(get_update_policy_command),
) -> PolicyDTO:
    """Update an existing policy.

    Args:
        policy_id: Policy identifier
        tenant_id: Current tenant ID
        request: Update request (all fields optional)
        update_command: Injected update command handler

    Returns:
        Updated policy details

    Raises:
        HTTPException: 404 if policy not found, 400 if validation fails
    """
    try:
        return await update_command.execute(policy_id, tenant_id, request)

    except EntityNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy {policy_id} not found",
        ) from e
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:
        logger.opt(exception=True).error(f"Failed to update policy: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update policy",
        ) from e


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_policy(
    policy_id: UUID,
    tenant_id: Annotated[UUID, Depends(get_tenant_id)],
    delete_command: DeletePolicyCommand = Depends(get_delete_policy_command),
) -> None:
    """Delete a policy.

    Args:
        policy_id: Policy identifier
        tenant_id: Current tenant ID
        delete_command: Injected delete command handler

    Raises:
        HTTPException: 404 if policy not found
    """
    try:
        deleted = await delete_command.execute(policy_id, tenant_id)
        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Policy {policy_id} not found",
            )

    except EntityNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy {policy_id} not found",
        ) from e
    except Exception as e:
        logger.opt(exception=True).error(f"Failed to delete policy: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete policy",
        ) from e
