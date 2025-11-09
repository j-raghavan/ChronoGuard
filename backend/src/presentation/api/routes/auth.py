"""Authentication API routes for ChronoGuard."""

from __future__ import annotations

import secrets
from datetime import timedelta
from uuid import UUID

from core.config import get_settings
from core.security import create_access_token
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    """Login request body."""

    password: str = Field(..., min_length=8, description="Password for demo admin user")
    tenant_id: UUID | None = Field(
        default=None, description="Optional tenant override for the issued token"
    )
    user_id: UUID | None = Field(
        default=None, description="Optional user override for the issued token"
    )


class LoginResponse(BaseModel):
    """Login response body."""

    access_token: str
    token_type: str = "bearer"
    tenant_id: UUID
    user_id: UUID
    expires_in: int


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest) -> LoginResponse:
    """Exchange the shared demo password for a JWT access token."""

    settings = get_settings()
    security_settings = settings.security

    if not security_settings.demo_mode_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Demo authentication is disabled on this deployment.",
        )

    expected_password = security_settings.demo_admin_password
    if not secrets.compare_digest(request.password, expected_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    tenant_id = request.tenant_id or security_settings.demo_tenant_id
    user_id = request.user_id or security_settings.demo_user_id

    expires_delta = timedelta(minutes=security_settings.access_token_expire_minutes)
    token_payload = {
        "sub": str(user_id),
        "user_id": str(user_id),
        "tenant_id": str(tenant_id),
    }
    access_token = create_access_token(token_payload, expires_delta, security_settings)

    return LoginResponse(
        access_token=access_token,
        tenant_id=tenant_id,
        user_id=user_id,
        expires_in=int(expires_delta.total_seconds()),
    )
