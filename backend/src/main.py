"""ChronoGuard FastAPI application entry point."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from core.container import configure_container
from core.features import FeatureManager
from core.logging import configure_logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from infrastructure.observability.telemetry import initialize_telemetry


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
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],  # Frontend URL
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        allow_headers=["*"],
    )

    # Include API routers
    from presentation.api.routes import agents_router, audit_router, health_router, policies_router

    app.include_router(health_router)
    app.include_router(agents_router)
    app.include_router(policies_router)
    app.include_router(audit_router)

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

    # Metrics endpoint (provided by OpenTelemetry Prometheus exporter)
    # Note: /metrics endpoint is automatically provided by PrometheusMetricReader

    return app


# Create application instance
app = create_app()
