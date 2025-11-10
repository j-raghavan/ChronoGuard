"""Health check API routes.

This module provides health check endpoints for monitoring and readiness probes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from presentation.api.dependencies import get_agent_repository, get_policy_repository, get_tenant_id


router = APIRouter(prefix="/api/v1/health", tags=["health"])


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str
    timestamp: datetime
    service: str
    version: str
    database: str | None = None

    class Config:
        """Pydantic configuration."""

        frozen = True


@router.get("/", response_model=HealthResponse, status_code=status.HTTP_200_OK)
async def health_check() -> HealthResponse:
    """Basic health check endpoint.

    Returns:
        Health status response

    Example:
        GET /api/v1/health/
        Response: {"status": "healthy", "timestamp": "2025-01-01T00:00:00Z", ...}
    """
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(UTC),
        service="chronoguard",
        version="1.0.0",
    )


@router.get("/ready", response_model=HealthResponse, status_code=status.HTTP_200_OK)
async def readiness_check() -> HealthResponse:
    """Readiness check for Kubernetes/deployment systems with database connectivity.

    Returns:
        Readiness status response

    Raises:
        HTTPException: 503 if database is not accessible

    Example:
        GET /api/v1/health/ready
        Response: {"status": "ready", "database": "connected", ...}
    """
    # Test database connectivity
    try:
        from sqlalchemy import text
        from sqlalchemy.ext.asyncio import create_async_engine

        from presentation.api.dependencies import get_database_url

        db_url = get_database_url()
        if db_url.startswith("postgresql://"):
            db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

        engine = create_async_engine(db_url, pool_pre_ping=True)

        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

        await engine.dispose()

        return HealthResponse(
            status="ready",
            timestamp=datetime.now(UTC),
            service="chronoguard",
            version="1.0.0",
            database="connected",
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database not available: {str(e)}",
        ) from e


class MetricsSummaryResponse(BaseModel):
    """Metrics summary response model."""

    timestamp: datetime
    agents: dict[str, int]
    policies: dict[str, int]
    recent_activity: dict[str, int] | None = None

    class Config:
        """Pydantic configuration."""

        frozen = True


@router.get("/metrics", response_model=MetricsSummaryResponse)
async def metrics_summary(
    tenant_id: Annotated[UUID, Depends(get_tenant_id)],
) -> MetricsSummaryResponse:
    """Get system metrics summary for dashboard.

    Args:
        tenant_id: Tenant identifier from X-Tenant-ID header

    Returns:
        Metrics summary with counts for agents, policies, and activity

    Raises:
        HTTPException: 500 if metrics collection fails
    """
    try:
        agent_repo = get_agent_repository()
        policy_repo = get_policy_repository()

        # Get agent counts by status
        all_agents = await agent_repo.find_by_tenant_id(tenant_id)
        agent_stats = {
            "total": len(all_agents),
            "active": sum(1 for a in all_agents if a.status == "active"),
            "suspended": sum(1 for a in all_agents if a.status == "suspended"),
            "pending": sum(1 for a in all_agents if a.status == "pending"),
        }

        # Get policy counts
        all_policies = await policy_repo.find_by_tenant_id(tenant_id)
        policy_stats = {
            "total": len(all_policies),
            "active": sum(1 for p in all_policies if p.is_active()),
        }

        return MetricsSummaryResponse(
            timestamp=datetime.now(UTC),
            agents=agent_stats,
            policies=policy_stats,
            recent_activity=None,  # Can be extended later with audit data
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to collect metrics: {str(e)}",
        ) from e
