"""OpenTelemetry telemetry configuration for ChronoGuard."""

from __future__ import annotations

import os
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.propagators.b3 import B3MultiFormat
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

from core.features import FeatureManager


class ChronoGuardTelemetry:
    """Centralized telemetry configuration for ChronoGuard."""

    def __init__(
        self,
        service_name: str = "chronoguard",
        service_version: str = "1.0.0",
        environment: str = "production",
        feature_manager: FeatureManager | None = None,
    ) -> None:
        """Initialize telemetry configuration.

        Args:
            service_name: Name of the service
            service_version: Version of the service
            environment: Deployment environment
            feature_manager: Feature manager for conditional setup
        """
        self.service_name = service_name
        self.service_version = service_version
        self.environment = environment
        self.feature_manager = feature_manager

        self._resource = self._create_resource()
        self._tracer_provider: TracerProvider | None = None
        self._meter_provider: MeterProvider | None = None
        self._metrics: ChronoGuardMetrics | None = None

    def initialize(self) -> None:
        """Initialize all telemetry components."""
        self._setup_tracing()
        self._setup_metrics()
        self._setup_propagators()
        self._setup_instrumentation()

    def _create_resource(self) -> Resource:
        """Create OpenTelemetry resource with service information.

        Returns:
            Configured Resource instance
        """
        return Resource.create(
            {
                "service.name": self.service_name,
                "service.version": self.service_version,
                "deployment.environment": self.environment,
                "service.namespace": "chronoguard",
                "service.instance.id": os.environ.get("HOSTNAME", "unknown"),
            }
        )

    def _setup_tracing(self) -> None:
        """Configure distributed tracing."""
        if not self._should_enable_tracing():
            return

        # Create tracer provider
        self._tracer_provider = TracerProvider(resource=self._resource)

        # Console exporter for development
        if self.environment == "development":
            console_processor = BatchSpanProcessor(ConsoleSpanExporter())
            self._tracer_provider.add_span_processor(console_processor)

        # OTLP exporter for production
        otlp_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        if otlp_endpoint:
            otlp_exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
            otlp_processor = BatchSpanProcessor(otlp_exporter)
            self._tracer_provider.add_span_processor(otlp_processor)

        # Set global tracer provider
        trace.set_tracer_provider(self._tracer_provider)

    def _setup_metrics(self) -> None:
        """Configure metrics collection and export."""
        if not self._should_enable_metrics():
            return

        # Create metric readers
        readers: list[Any] = []

        # Prometheus reader for /metrics endpoint
        if self._should_enable_prometheus():
            prometheus_reader = PrometheusMetricReader()
            readers.append(prometheus_reader)

        # OTLP reader for centralized metrics
        otlp_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
        if otlp_endpoint:
            otlp_exporter = OTLPMetricExporter(endpoint=otlp_endpoint)
            otlp_reader = PeriodicExportingMetricReader(
                exporter=otlp_exporter,
                export_interval_millis=60000,  # 1 minute
            )
            readers.append(otlp_reader)

        if readers:
            # Create meter provider
            self._meter_provider = MeterProvider(
                resource=self._resource,
                metric_readers=readers,
            )

            # Set global meter provider
            metrics.set_meter_provider(self._meter_provider)

            # Initialize application metrics
            self._metrics = ChronoGuardMetrics(self._meter_provider)

    def _setup_propagators(self) -> None:
        """Configure trace propagation."""
        if not self._should_enable_tracing():
            return

        # Configure propagators for distributed tracing
        from opentelemetry.propagate import set_global_textmap

        # Use B3 propagation for better compatibility
        set_global_textmap(B3MultiFormat())

    def _setup_instrumentation(self) -> None:
        """Configure automatic instrumentation."""
        if not self._should_enable_tracing():
            return

        # Auto-instrument FastAPI
        FastAPIInstrumentor().instrument()

        # Auto-instrument SQLAlchemy
        SQLAlchemyInstrumentor().instrument()

        # Auto-instrument Redis
        RedisInstrumentor().instrument()

    def _should_enable_tracing(self) -> bool:
        """Check if tracing should be enabled.

        Returns:
            True if tracing should be enabled
        """
        if not self.feature_manager:
            return True
        return self.feature_manager.is_enabled("opentelemetry_tracing")

    def _should_enable_metrics(self) -> bool:
        """Check if metrics should be enabled.

        Returns:
            True if metrics should be enabled
        """
        if not self.feature_manager:
            return True
        return self.feature_manager.is_enabled("prometheus_metrics")

    def _should_enable_prometheus(self) -> bool:
        """Check if Prometheus metrics should be enabled.

        Returns:
            True if Prometheus metrics should be enabled
        """
        return self._should_enable_metrics()

    def get_tracer(self, name: str) -> trace.Tracer:
        """Get a tracer instance.

        Args:
            name: Tracer name

        Returns:
            Tracer instance
        """
        return trace.get_tracer(name, self.service_version)

    def get_meter(self, name: str) -> metrics.Meter:
        """Get a meter instance.

        Args:
            name: Meter name

        Returns:
            Meter instance
        """
        return metrics.get_meter(name, self.service_version)

    @property
    def metrics(self) -> ChronoGuardMetrics | None:
        """Get the metrics instance.

        Returns:
            ChronoGuardMetrics instance if metrics are enabled
        """
        return self._metrics


class ChronoGuardMetrics:
    """Application-specific metrics for ChronoGuard."""

    def __init__(self, meter_provider: MeterProvider) -> None:
        """Initialize ChronoGuard metrics.

        Args:
            meter_provider: OpenTelemetry meter provider
        """
        self.meter = meter_provider.get_meter("chronoguard.metrics")

        # Access control metrics
        self.access_requests_total = self.meter.create_counter(
            name="chronoguard_access_requests_total",
            description="Total number of access requests",
            unit="1",
        )

        self.access_decisions_total = self.meter.create_counter(
            name="chronoguard_access_decisions_total",
            description="Total number of access decisions by type",
            unit="1",
        )

        self.policy_evaluations_total = self.meter.create_counter(
            name="chronoguard_policy_evaluations_total",
            description="Total number of policy evaluations",
            unit="1",
        )

        self.policy_evaluation_duration = self.meter.create_histogram(
            name="chronoguard_policy_evaluation_duration_seconds",
            description="Time taken to evaluate policies",
            unit="s",
        )

        # Agent metrics
        self.active_agents_gauge = self.meter.create_up_down_counter(
            name="chronoguard_active_agents",
            description="Number of active agents",
            unit="1",
        )

        self.agent_certificate_expiry_days = self.meter.create_histogram(
            name="chronoguard_agent_certificate_expiry_days",
            description="Days until agent certificate expiry",
            unit="d",
        )

        # Audit metrics
        self.audit_entries_total = self.meter.create_counter(
            name="chronoguard_audit_entries_total",
            description="Total number of audit entries created",
            unit="1",
        )

        self.audit_chain_verifications_total = self.meter.create_counter(
            name="chronoguard_audit_chain_verifications_total",
            description="Total number of audit chain verifications",
            unit="1",
        )

        self.audit_integrity_violations_total = self.meter.create_counter(
            name="chronoguard_audit_integrity_violations_total",
            description="Total number of audit integrity violations",
            unit="1",
        )

        # Performance metrics
        self.request_duration = self.meter.create_histogram(
            name="chronoguard_request_duration_seconds",
            description="HTTP request duration",
            unit="s",
        )

        self.database_query_duration = self.meter.create_histogram(
            name="chronoguard_database_query_duration_seconds",
            description="Database query duration",
            unit="s",
        )

        # Security metrics
        self.security_events_total = self.meter.create_counter(
            name="chronoguard_security_events_total",
            description="Total number of security events",
            unit="1",
        )

        self.failed_authentication_attempts_total = self.meter.create_counter(
            name="chronoguard_failed_authentication_attempts_total",
            description="Total number of failed authentication attempts",
            unit="1",
        )

        # System metrics
        self.system_errors_total = self.meter.create_counter(
            name="chronoguard_system_errors_total",
            description="Total number of system errors",
            unit="1",
        )

    def record_access_request(
        self,
        tenant_id: str,
        agent_id: str,
        domain: str,
        decision: str,
        processing_time_seconds: float,
    ) -> None:
        """Record access request metrics.

        Args:
            tenant_id: Tenant ID
            agent_id: Agent ID
            domain: Domain accessed
            decision: Access decision
            processing_time_seconds: Processing time in seconds
        """
        labels = {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "domain": domain,
        }

        self.access_requests_total.add(1, labels)
        self.access_decisions_total.add(1, {**labels, "decision": decision})
        self.request_duration.record(processing_time_seconds, labels)

    def record_policy_evaluation(
        self,
        tenant_id: str,
        policy_id: str,
        evaluation_time_seconds: float,
        matched: bool,
    ) -> None:
        """Record policy evaluation metrics.

        Args:
            tenant_id: Tenant ID
            policy_id: Policy ID
            evaluation_time_seconds: Evaluation time in seconds
            matched: Whether policy matched
        """
        labels = {
            "tenant_id": tenant_id,
            "policy_id": policy_id,
            "matched": str(matched).lower(),
        }

        self.policy_evaluations_total.add(1, labels)
        self.policy_evaluation_duration.record(evaluation_time_seconds, labels)

    def record_audit_entry(self, tenant_id: str, agent_id: str, decision: str) -> None:
        """Record audit entry creation.

        Args:
            tenant_id: Tenant ID
            agent_id: Agent ID
            decision: Access decision
        """
        labels = {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "decision": decision,
        }

        self.audit_entries_total.add(1, labels)

    def record_audit_verification(
        self, tenant_id: str, agent_id: str, integrity_valid: bool
    ) -> None:
        """Record audit chain verification.

        Args:
            tenant_id: Tenant ID
            agent_id: Agent ID
            integrity_valid: Whether integrity check passed
        """
        labels = {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "valid": str(integrity_valid).lower(),
        }

        self.audit_chain_verifications_total.add(1, labels)

        if not integrity_valid:
            self.audit_integrity_violations_total.add(1, labels)

    def record_security_event(
        self, event_type: str, severity: str, tenant_id: str | None = None
    ) -> None:
        """Record security event.

        Args:
            event_type: Type of security event
            severity: Event severity
            tenant_id: Optional tenant ID
        """
        labels = {
            "event_type": event_type,
            "severity": severity,
        }

        if tenant_id:
            labels["tenant_id"] = tenant_id

        self.security_events_total.add(1, labels)

    def record_database_query(self, operation: str, duration_seconds: float, success: bool) -> None:
        """Record database query metrics.

        Args:
            operation: Database operation type
            duration_seconds: Query duration in seconds
            success: Whether query succeeded
        """
        labels = {
            "operation": operation,
            "success": str(success).lower(),
        }

        self.database_query_duration.record(duration_seconds, labels)

    def update_active_agents(self, tenant_id: str, count: int) -> None:
        """Update active agents count.

        Args:
            tenant_id: Tenant ID
            count: Current count of active agents
        """
        # Note: This requires the gauge to be updated periodically
        # In practice, you'd implement this with a background task
        # labels = {"tenant_id": tenant_id}
        # ACTIVE_AGENTS_BY_TENANT.labels(**labels).set(count)


# Global telemetry instance
_telemetry: ChronoGuardTelemetry | None = None


def initialize_telemetry(
    service_name: str = "chronoguard",
    service_version: str = "1.0.0",
    environment: str = "production",
    feature_manager: FeatureManager | None = None,
) -> ChronoGuardTelemetry:
    """Initialize global telemetry.

    Args:
        service_name: Name of the service
        service_version: Version of the service
        environment: Deployment environment
        feature_manager: Feature manager for conditional setup

    Returns:
        Configured ChronoGuardTelemetry instance
    """
    global _telemetry
    _telemetry = ChronoGuardTelemetry(service_name, service_version, environment, feature_manager)
    _telemetry.initialize()
    return _telemetry


def get_telemetry() -> ChronoGuardTelemetry | None:
    """Get the global telemetry instance.

    Returns:
        ChronoGuardTelemetry instance if initialized, None otherwise
    """
    return _telemetry


def get_tracer(name: str) -> trace.Tracer:
    """Get a tracer instance.

    Args:
        name: Tracer name

    Returns:
        Tracer instance
    """
    if _telemetry:
        return _telemetry.get_tracer(name)
    return trace.get_tracer(name)


def get_meter(name: str) -> metrics.Meter:
    """Get a meter instance.

    Args:
        name: Meter name

    Returns:
        Meter instance
    """
    if _telemetry:
        return _telemetry.get_meter(name)
    return metrics.get_meter(name)


def get_metrics() -> ChronoGuardMetrics | None:
    """Get the application metrics instance.

    Returns:
        ChronoGuardMetrics instance if available, None otherwise
    """
    if _telemetry:
        return _telemetry.metrics
    return None
