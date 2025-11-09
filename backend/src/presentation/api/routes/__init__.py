"""API route modules.

This module exports all API routers for inclusion in the FastAPI application.
"""

from .agents import router as agents_router
from .audit import router as audit_router
from .auth import router as auth_router
from .health import router as health_router
from .internal import router as internal_router
from .policies import router as policies_router

__all__ = [
    "auth_router",
    "agents_router",
    "policies_router",
    "audit_router",
    "health_router",
    "internal_router",
]
