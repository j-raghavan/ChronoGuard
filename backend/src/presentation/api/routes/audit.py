"""Audit log API routes.

This module provides REST API endpoints for audit log querying, export, and analytics.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from application.dto import (
    AuditEntryDTO,
    AuditExportRequest,
    AuditListResponse,
    AuditQueryRequest,
    TemporalPatternDTO,
)
from application.pagination import PaginatedResponse, PaginationParams
from application.queries import GetAuditEntriesQuery
from application.queries.audit_export import AuditExporter
from application.queries.temporal_analytics import TemporalAnalyticsQuery
from presentation.api.dependencies import (
    get_audit_entries_query,
    get_audit_exporter,
    get_temporal_analytics_query,
    get_tenant_id,
)


router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("/analytics", response_model=TemporalPatternDTO)
async def get_temporal_analytics(
    tenant_id: Annotated[UUID, Depends(get_tenant_id)],
    start_time: Annotated[datetime, Query(description="Start of analysis period")],
    end_time: Annotated[datetime, Query(description="End of analysis period")],
    analytics_query: Annotated[TemporalAnalyticsQuery, Depends(get_temporal_analytics_query)],
) -> TemporalPatternDTO:
    """Get temporal analytics for audit access patterns.

    Args:
        tenant_id: Tenant identifier from X-Tenant-ID header
        start_time: Start of analysis period
        end_time: End of analysis period
        analytics_query: Temporal analytics query handler

    Returns:
        Temporal pattern analysis with hourly/daily distributions, anomalies, compliance score

    Raises:
        HTTPException: 400 if time range is invalid
    """
    if end_time <= start_time:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="end_time must be after start_time",
        )

    try:
        pattern = await analytics_query.execute(tenant_id, start_time, end_time)
        return TemporalPatternDTO(
            tenant_id=pattern.tenant_id,
            start_time=pattern.start_time,
            end_time=pattern.end_time,
            hourly_distribution=pattern.hourly_distribution,
            daily_distribution=pattern.daily_distribution,
            peak_hours=pattern.peak_hours,
            off_hours_activity_percentage=pattern.off_hours_activity_percentage,
            weekend_activity_percentage=pattern.weekend_activity_percentage,
            top_domains=pattern.top_domains,
            anomalies=pattern.anomalies,
            compliance_score=pattern.compliance_score,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate temporal analytics: {str(e)}",
        ) from e


@router.post("/query", response_model=PaginatedResponse[AuditEntryDTO])
async def query_audit_entries(
    request: AuditQueryRequest,
    query: Annotated[GetAuditEntriesQuery, Depends(get_audit_entries_query)],
    tenant_id: Annotated[UUID, Depends(get_tenant_id)],
) -> PaginatedResponse[AuditEntryDTO]:
    """Query audit log entries with filtering and pagination.

    Args:
        request: Query request with filters
        query: Audit entries query handler
        tenant_id: Authenticated tenant ID from X-Tenant-ID header

    Returns:
        Paginated list of audit entries

    Raises:
        HTTPException: 400 if query parameters are invalid, 403 if tenant mismatch,
            500 if query fails
    """
    # Default tenant_id to authenticated tenant if not provided (backward compatibility)
    if request.tenant_id is None:
        request.tenant_id = tenant_id
    # Validate tenant_id in request body matches authenticated tenant
    elif request.tenant_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Tenant ID mismatch: cannot query audit logs for tenant {request.tenant_id}",
        )

    try:
        # Enforce simplified pagination limits
        if request.page_size > 100:
             raise ValueError("Limit must be between 1 and 100")

        result = await query.execute(request)
        
        # Map to standardized pagination
        pagination = PaginationParams(page=request.page, limit=request.page_size)
        return PaginatedResponse.create(result.entries, result.total_count, pagination)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query audit entries: {str(e)}",
        ) from e


@router.post("/export", response_model=None)
async def export_audit_entries(
    request: AuditExportRequest,
    exporter: Annotated[AuditExporter, Depends(get_audit_exporter)],
    tenant_id: Annotated[UUID, Depends(get_tenant_id)],
) -> Response:
    """Export audit log entries to CSV or JSON format.

    Args:
        request: Export request with time range and format
        exporter: Audit exporter instance
        tenant_id: Authenticated tenant ID from X-Tenant-ID header

    Returns:
        Exported data in requested format

    Raises:
        HTTPException: 400 if request is invalid, 403 if tenant mismatch, 500 if export fails
    """
    # Default tenant_id to authenticated tenant if not provided (backward compatibility)
    if request.tenant_id is None:
        request.tenant_id = tenant_id
    # Validate tenant_id in request body matches authenticated tenant
    elif request.tenant_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Tenant ID mismatch: cannot export audit logs for tenant {request.tenant_id}",
        )

    try:
        if request.format == "csv":
            content = await exporter.export_to_csv(
                request.tenant_id,
                request.start_time,
                request.end_time,
            )
            media_type = "text/csv"
            filename = f"audit_export_{request.start_time.date()}_{request.end_time.date()}.csv"
        else:  # JSON
            content = await exporter.export_to_json(
                request.tenant_id,
                request.start_time,
                request.end_time,
                pretty=request.pretty_json,
            )
            media_type = "application/json"
            filename = f"audit_export_{request.start_time.date()}_{request.end_time.date()}.json"

        return Response(
            content=content,
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to export audit logs: {str(e)}",
        ) from e
