"""ChronoGuard FastAPI application entry point."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from core.config import get_settings
from core.container import configure_container
from core.database import create_engine, initialize_database
from core.features import FeatureManager
from core.logging import configure_logging
from infrastructure.observability.telemetry import initialize_telemetry
from presentation.api.middleware.auth import AuthMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan management.

    Args:
        app: FastAPI application instance

    Yields:
        None during application runtime
    """
    # Startup
    feature_manager = FeatureManager()

    # Configure logging
    configure_logging(
        level="INFO",
        structured=True,
        environment=feature_manager.flags.environment,
    )

    # Initialize database schema
    engine = None
    try:
        logger.info("Initializing database schema...")
        engine = create_engine()
        await initialize_database(engine, create_tables=True, create_extensions=True)
        logger.info("Database schema initialized successfully")
    except Exception:
        logger.opt(exception=True).error("Database initialization failed")
        raise
    finally:
        if engine is not None:
            await engine.dispose()

    # Initialize telemetry
    telemetry = initialize_telemetry(
        service_name="chronoguard",
        service_version="1.0.0",
        environment=feature_manager.flags.environment,
        feature_manager=feature_manager,
    )

    # Configure dependency injection
    container = configure_container(feature_manager)

    # Store in app state
    app.state.feature_manager = feature_manager
    app.state.container = container
    app.state.telemetry = telemetry

    yield

    # Shutdown
    # Cleanup resources if needed


def create_app() -> FastAPI:
    """Create and configure FastAPI application.

    Returns:
        Configured FastAPI application
    """
    app = FastAPI(
        title="ChronoGuard API",
        description="Zero-trust proxy for browser automation with temporal controls",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Configure CORS
    settings = get_settings()
    # Base origins for local development
    cors_origins: list[str] = [
        "http://localhost:3000",  # Frontend production
        "http://localhost:5173",  # Frontend dev server (Vite)
    ]
    # In demo mode, also allow GitHub Codespaces domains (*.github.dev)
    # Users can customize CORS origins via CHRONOGUARD_API_CORS_ORIGINS env var
    if settings.security.demo_mode_enabled:
        cors_origins.append("https://*.github.dev")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        allow_headers=["*"],
        allow_origin_regex=r"https://.*\.github\.dev" if settings.security.demo_mode_enabled else None,
    )

    # Configure Authentication Middleware
    app.add_middleware(
        AuthMiddleware,
        exempt_paths=[
            "/health",
            "/metrics",
            "/api/v1/health",
            "/api/v1/health/",
            "/api/v1/health/ready",
            "/api/v1/auth/login",
            "/api/v1/auth/logout",
            "/api/v1/internal",  # Internal routes use their own auth
            "/docs",
            "/redoc",
            "/openapi.json",
        ],
        enable_mtls=False,  # Can enable for production
        enable_api_key=False,
        security_settings=settings.security,
    )

    # Include API routers
    from presentation.api.routes import (
        agents_router,
        audit_router,
        auth_router,
        health_router,
        internal_router,
        policies_router,
    )

    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(agents_router)
    app.include_router(policies_router)
    app.include_router(audit_router)
    app.include_router(internal_router)

    # Legacy health check endpoint (kept for backwards compatibility)
    @app.get("/health")
    async def legacy_health_check() -> dict[str, str]:
        """Legacy health check endpoint.

        Returns:
            Health status information
        """
        return {
            "status": "healthy",
            "service": "chronoguard",
            "version": "1.0.0",
            "timestamp": "2023-09-28T20:00:00Z",
        }

    # Prometheus metrics endpoint
    @app.get("/metrics")
    async def metrics_endpoint() -> dict[str, str]:
        """Prometheus metrics endpoint.

        Returns:
            Metrics information

        Note:
            Full Prometheus metrics available when OpenTelemetry PrometheusMetricReader
            is configured. This endpoint provides basic service info.
        """
        return {
            "service": "chronoguard",
            "version": "1.0.0",
            "status": "metrics_available",
        }

    return app


# Create application instance
app = create_app()
