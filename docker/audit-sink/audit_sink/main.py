"""ChronoGuard Audit Sink - Ingests decisions and creates hash-chained audit records."""

from datetime import UTC, datetime

from domain.audit.entity import AccessDecision, AuditEntry
from domain.audit.service import AccessRequest
from fastapi import FastAPI, HTTPException
from loguru import logger
from pydantic import BaseModel


class DecisionLogEntry(BaseModel):
    """Decision log entry from OPA/Envoy."""

    timestamp: datetime
    agent_id: str
    domain: str
    method: str = "GET"
    path: str = "/"
    decision: str
    reason: str = ""
    user_agent: str = ""
    source_ip: str = ""
    tenant_id: str
    processing_time_ms: float = 0.0


class AuditSinkApp:
    """Audit sink application for processing decision logs."""

    def __init__(self):
        self.app = FastAPI(
            title="ChronoGuard Audit Sink",
            description="Ingests access decisions and creates hash-chained audit records",
            version="1.0.0",
        )
        self.redis_client = None
        self.audit_service = None
        self._setup_routes()

    def _setup_routes(self):
        """Setup FastAPI routes."""

        @self.app.post("/ingest/decision")
        async def ingest_decision(entry: DecisionLogEntry):
            """Ingest access decision for audit logging."""
            try:
                # Convert to audit service request
                access_request = AccessRequest(
                    tenant_id=entry.tenant_id,
                    agent_id=entry.agent_id,
                    domain=entry.domain,
                    decision=AccessDecision(entry.decision),
                    reason=entry.reason,
                    request_method=entry.method,
                    request_path=entry.path,
                    user_agent=entry.user_agent,
                    source_ip=entry.source_ip,
                    processing_time_ms=entry.processing_time_ms,
                    timestamp=entry.timestamp,
                )

                # Record in audit trail
                audit_entry = await self.audit_service.record_access(access_request)

                # Publish to real-time stream
                await self._publish_to_stream(audit_entry)

                return {
                    "status": "recorded",
                    "entry_id": str(audit_entry.entry_id),
                    "sequence_number": audit_entry.sequence_number,
                }

            except Exception as e:
                logger.error(f"Failed to ingest decision: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/health")
        async def health_check():
            """Health check endpoint."""
            return {
                "status": "healthy",
                "service": "chronoguard-audit-sink",
                "version": "1.0.0",
                "timestamp": datetime.now(UTC).isoformat(),
            }

        @self.app.get("/metrics")
        async def metrics():
            """Metrics endpoint for monitoring."""
            # Basic metrics - would be enhanced with Prometheus client
            return {
                "ingested_decisions_total": await self._get_ingestion_count(),
                "audit_chain_length": await self._get_chain_length(),
                "last_ingestion": await self._get_last_ingestion_time(),
            }

    async def _publish_to_stream(self, audit_entry: AuditEntry):
        """Publish audit entry to real-time stream."""
        if self.redis_client:
            try:
                stream_data = {
                    "entry_id": str(audit_entry.entry_id),
                    "tenant_id": str(audit_entry.tenant_id),
                    "agent_id": str(audit_entry.agent_id),
                    "domain": audit_entry.domain.value,
                    "decision": audit_entry.decision.value,
                    "timestamp": audit_entry.timestamp.isoformat(),
                    "risk_score": audit_entry.get_risk_score(),
                }

                await self.redis_client.xadd("chronoguard:audit:stream", stream_data)
            except Exception as e:
                logger.warning(f"Failed to publish to stream: {e}")

    async def _get_ingestion_count(self) -> int:
        """Get total ingestion count."""
        if self.redis_client:
            try:
                count = await self.redis_client.get("chronoguard:audit:count")
                return int(count) if count else 0
            except:
                return 0
        return 0

    async def _get_chain_length(self) -> int:
        """Get current audit chain length."""
        # Would query database for actual chain length
        return 0

    async def _get_last_ingestion_time(self) -> str:
        """Get timestamp of last ingestion."""
        if self.redis_client:
            try:
                timestamp = await self.redis_client.get(
                    "chronoguard:audit:last_ingestion"
                )
                return timestamp.decode() if timestamp else ""
            except:
                return ""
        return ""


def create_app() -> FastAPI:
    """Create and configure audit sink application."""
    sink_app = AuditSinkApp()
    return sink_app.app


# Create app instance
app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
