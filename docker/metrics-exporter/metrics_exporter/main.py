"""ChronoGuard Metrics Exporter - Prometheus/OTel metrics for temporal analysis."""

import asyncio
import os
from datetime import datetime, timezone
from typing import Dict

from fastapi import FastAPI
from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    generate_latest,
    CONTENT_TYPE_LATEST,
)
from starlette.responses import Response
import redis.asyncio as redis
from loguru import logger


# Prometheus metrics
TEMPORAL_ACCESS_TOTAL = Counter(
    "chronoguard_temporal_access_total",
    "Total temporal access attempts",
    ["tenant_id", "decision", "hour_of_day", "day_of_week"],
)

TEMPORAL_WINDOW_VIOLATIONS = Counter(
    "chronoguard_temporal_violations_total",
    "Total temporal window violations",
    ["tenant_id", "violation_type"],
)

AUDIT_LAG_SECONDS = Histogram(
    "chronoguard_audit_lag_seconds",
    "Time lag between decision and audit record creation",
    ["tenant_id"],
)

ACTIVE_AGENTS_BY_TENANT = Gauge(
    "chronoguard_active_agents", "Number of active agents per tenant", ["tenant_id"]
)

POLICY_EVALUATIONS_DURATION = Histogram(
    "chronoguard_policy_evaluation_duration_seconds",
    "Time spent evaluating policies",
    ["tenant_id", "policy_id"],
)

DENIED_REQUESTS_BY_REASON = Counter(
    "chronoguard_denied_requests_total",
    "Total denied requests by reason",
    ["tenant_id", "denial_reason"],
)

CERTIFICATE_EXPIRY_DAYS = Gauge(
    "chronoguard_certificate_expiry_days",
    "Days until certificate expiry",
    ["tenant_id", "agent_id"],
)

AUDIT_CHAIN_INTEGRITY = Gauge(
    "chronoguard_audit_chain_integrity_score",
    "Audit chain integrity score (0-100)",
    ["tenant_id", "agent_id"],
)


class MetricsExporter:
    """Metrics exporter for ChronoGuard temporal and security metrics."""

    def __init__(self):
        self.app = FastAPI(
            title="ChronoGuard Metrics Exporter",
            description="Prometheus/OTel metrics for temporal windows, denials, and audit lag",
            version="1.0.0",
        )
        self.redis_client = None
        self._setup_routes()

    def _setup_routes(self):
        """Setup FastAPI routes."""

        @self.app.get("/metrics")
        async def prometheus_metrics():
            """Prometheus metrics endpoint."""
            return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

        @self.app.get("/health")
        async def health_check():
            """Health check endpoint."""
            return {
                "status": "healthy",
                "service": "chronoguard-metrics-exporter",
                "version": "1.0.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        @self.app.post("/metrics/temporal_access")
        async def record_temporal_access(data: Dict):
            """Record temporal access metrics."""
            try:
                TEMPORAL_ACCESS_TOTAL.labels(
                    tenant_id=data.get("tenant_id", "unknown"),
                    decision=data.get("decision", "unknown"),
                    hour_of_day=str(data.get("hour_of_day", 0)),
                    day_of_week=str(data.get("day_of_week", 0)),
                ).inc()

                if data.get("decision") == "deny":
                    TEMPORAL_WINDOW_VIOLATIONS.labels(
                        tenant_id=data.get("tenant_id", "unknown"),
                        violation_type=data.get("violation_type", "unknown"),
                    ).inc()

                    DENIED_REQUESTS_BY_REASON.labels(
                        tenant_id=data.get("tenant_id", "unknown"),
                        denial_reason=data.get("reason", "unknown"),
                    ).inc()

                return {"status": "recorded"}

            except Exception as e:
                logger.error(f"Failed to record temporal access metric: {e}")
                return {"status": "error", "message": str(e)}

        @self.app.post("/metrics/audit_lag")
        async def record_audit_lag(data: Dict):
            """Record audit lag metrics."""
            try:
                lag_seconds = data.get("lag_seconds", 0.0)
                AUDIT_LAG_SECONDS.labels(
                    tenant_id=data.get("tenant_id", "unknown")
                ).observe(lag_seconds)

                return {"status": "recorded"}

            except Exception as e:
                logger.error(f"Failed to record audit lag metric: {e}")
                return {"status": "error", "message": str(e)}

        @self.app.post("/metrics/policy_evaluation")
        async def record_policy_evaluation(data: Dict):
            """Record policy evaluation metrics."""
            try:
                duration_seconds = data.get("duration_seconds", 0.0)
                POLICY_EVALUATIONS_DURATION.labels(
                    tenant_id=data.get("tenant_id", "unknown"),
                    policy_id=data.get("policy_id", "unknown"),
                ).observe(duration_seconds)

                return {"status": "recorded"}

            except Exception as e:
                logger.error(f"Failed to record policy evaluation metric: {e}")
                return {"status": "error", "message": str(e)}

        @self.app.put("/metrics/active_agents")
        async def update_active_agents(data: Dict):
            """Update active agents count."""
            try:
                ACTIVE_AGENTS_BY_TENANT.labels(
                    tenant_id=data.get("tenant_id", "unknown")
                ).set(data.get("count", 0))

                return {"status": "updated"}

            except Exception as e:
                logger.error(f"Failed to update active agents metric: {e}")
                return {"status": "error", "message": str(e)}

        @self.app.put("/metrics/certificate_expiry")
        async def update_certificate_expiry(data: Dict):
            """Update certificate expiry metrics."""
            try:
                CERTIFICATE_EXPIRY_DAYS.labels(
                    tenant_id=data.get("tenant_id", "unknown"),
                    agent_id=data.get("agent_id", "unknown"),
                ).set(data.get("days_until_expiry", 0))

                return {"status": "updated"}

            except Exception as e:
                logger.error(f"Failed to update certificate expiry metric: {e}")
                return {"status": "error", "message": str(e)}

        @self.app.put("/metrics/audit_integrity")
        async def update_audit_integrity(data: Dict):
            """Update audit chain integrity metrics."""
            try:
                AUDIT_CHAIN_INTEGRITY.labels(
                    tenant_id=data.get("tenant_id", "unknown"),
                    agent_id=data.get("agent_id", "unknown"),
                ).set(data.get("integrity_score", 0))

                return {"status": "updated"}

            except Exception as e:
                logger.error(f"Failed to update audit integrity metric: {e}")
                return {"status": "error", "message": str(e)}

    async def start_background_tasks(self):
        """Start background metric collection tasks."""
        logger.info("Starting background metric collection...")

        # Initialize Redis connection
        redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
        try:
            self.redis_client = redis.from_url(redis_url)
            await self.redis_client.ping()
            logger.info("Connected to Redis for metric streaming")
        except Exception as e:
            logger.warning(f"Could not connect to Redis: {e}")

        # Start metric collection tasks
        asyncio.create_task(self._collect_temporal_metrics())
        asyncio.create_task(self._collect_audit_metrics())

    async def _collect_temporal_metrics(self):
        """Collect temporal access pattern metrics."""
        while True:
            try:
                # Collect temporal access patterns
                # This would integrate with the main ChronoGuard database
                await asyncio.sleep(60)  # Collect every minute

            except Exception as e:
                logger.error(f"Error collecting temporal metrics: {e}")
                await asyncio.sleep(60)

    async def _collect_audit_metrics(self):
        """Collect audit lag and integrity metrics."""
        while True:
            try:
                # Collect audit lag metrics
                # This would measure time between decision and audit record creation
                await asyncio.sleep(30)  # Collect every 30 seconds

            except Exception as e:
                logger.error(f"Error collecting audit metrics: {e}")
                await asyncio.sleep(30)


def create_app() -> FastAPI:
    """Create and configure metrics exporter application."""
    exporter = MetricsExporter()

    @exporter.app.on_event("startup")
    async def startup_event():
        await exporter.start_background_tasks()

    return exporter.app


# Create app instance
app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8002)
