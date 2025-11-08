"""Audit log API routes.

This module provides REST API endpoints for audit log querying and export.

Note:
    Audit query and export endpoints require dependency injection configuration
    and will return 501 Not Implemented until the DI container is properly configured
    with repository instances. This is intentional to maintain Clean Architecture
    principles and avoid tight coupling.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response, status

from application.dto import AuditExportRequest, AuditListResponse, AuditQueryRequest

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.post("/query", response_model=AuditListResponse)
async def query_audit_entries(
    request: AuditQueryRequest,
) -> AuditListResponse:
    """Query audit log entries with filtering and pagination.

    Args:
        request: Query request with filters

    Returns:
        Paginated list of audit entries

    Raises:
        HTTPException: 501 until dependency injection is configured

    Note:
        This endpoint requires GetAuditEntriesQuery with AuditRepository dependency.
        Configuration needed in main.py or via DI container.
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Audit query endpoint requires dependency injection configuration",
    )


@router.post("/export", response_model=None)
async def export_audit_entries(
    request: AuditExportRequest,
) -> Response:
    """Export audit log entries to CSV or JSON format.

    Args:
        request: Export request with time range and format

    Returns:
        Exported data in requested format

    Raises:
        HTTPException: 501 until dependency injection is configured

    Note:
        This endpoint requires AuditExporter with AuditRepository dependency.
        Configuration needed in main.py or via DI container.
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Audit export endpoint requires dependency injection configuration",
    )
