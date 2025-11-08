"""Health check API routes.

This module provides health check endpoints for monitoring and readiness probes.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, status
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/health", tags=["health"])


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str
    timestamp: datetime
    service: str
    version: str

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
    """Readiness check for Kubernetes/deployment systems.

    Returns:
        Readiness status response

    Example:
        GET /api/v1/health/ready
        Response: {"status": "ready", ...}
    """
    return HealthResponse(
        status="ready",
        timestamp=datetime.now(UTC),
        service="chronoguard",
        version="1.0.0",
    )
