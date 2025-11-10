"""Authentication API routes for ChronoGuard."""

from __future__ import annotations

import secrets
from datetime import timedelta
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from core.config import get_settings
from core.security import create_access_token


router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    """Login request body."""

    password: str = Field(..., min_length=8, description="Password for demo admin user")


class LoginResponse(BaseModel):
    """Login response body."""

    access_token: str
    token_type: str = "bearer"
    tenant_id: UUID
    user_id: UUID
    expires_in: int


class SessionResponse(BaseModel):
    """Session validation response."""

    authenticated: bool
    tenant_id: UUID | None = None
    user_id: UUID | None = None


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, response: Response) -> LoginResponse:
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

    # SECURITY: Use only server-configured tenant/user IDs (not client-supplied)
    tenant_id = security_settings.demo_tenant_id
    user_id = security_settings.demo_user_id

    expires_delta = timedelta(minutes=security_settings.access_token_expire_minutes)
    token_payload = {
        "sub": str(user_id),
        "user_id": str(user_id),
        "tenant_id": str(tenant_id),
    }
    access_token = create_access_token(token_payload, expires_delta, security_settings)

    response.set_cookie(
        key=security_settings.session_cookie_name,
        value=access_token,
        httponly=True,
        secure=security_settings.session_cookie_secure,
        samesite=security_settings.session_cookie_same_site,
        domain=security_settings.session_cookie_domain,
        path=security_settings.session_cookie_path,
        max_age=int(expires_delta.total_seconds()),
    )

    return LoginResponse(
        access_token=access_token,
        tenant_id=tenant_id,
        user_id=user_id,
        expires_in=int(expires_delta.total_seconds()),
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def logout(response: Response) -> None:
    """Clear authentication cookie."""

    security_settings = get_settings().security
    response.delete_cookie(
        key=security_settings.session_cookie_name,
        domain=security_settings.session_cookie_domain,
        path=security_settings.session_cookie_path,
    )


@router.get("/session", response_model=SessionResponse)
async def get_session(request: Request) -> SessionResponse:
    """Return current session context."""

    payload = getattr(request.state, "user", None)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session not found",
        )

    try:
        tenant_id = UUID(payload["tenant_id"])
        user_id = UUID(payload.get("user_id") or payload.get("sub"))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session payload",
        ) from exc

    return SessionResponse(authenticated=True, tenant_id=tenant_id, user_id=user_id)
