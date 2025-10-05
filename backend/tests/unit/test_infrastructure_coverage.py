"""Tests for infrastructure components to improve coverage."""

from unittest.mock import MagicMock, patch

import pytest
from infrastructure.observability.telemetry import (
    ChronoGuardMetrics,
    ChronoGuardTelemetry,
    get_metrics,
    get_telemetry,
    initialize_telemetry,
)
from main import create_app, lifespan


class TestMainApplicationCoverage:
    """Test main application for coverage."""

    def test_create_app(self) -> None:
        """Test FastAPI app creation."""
        app = create_app()

        assert app.title == "ChronoGuard API"
        assert app.version == "1.0.0"
        assert app.description == "Zero-trust proxy for browser automation with temporal controls"

    @pytest.mark.asyncio
    @patch("main.initialize_telemetry")
    @patch("main.configure_logging")
    @patch("main.configure_container")
    async def test_lifespan_context_manager(
        self, mock_configure_container, mock_configure_logging, mock_initialize_telemetry
    ) -> None:
        """Test application lifespan management."""
        from core.container import DependencyContainer
        from core.features import FeatureManager
        from fastapi import FastAPI

        app = FastAPI()

        # Mock the returns to avoid actual telemetry setup
        mock_feature_manager = FeatureManager()
        mock_container = DependencyContainer()
        mock_telemetry = MagicMock()

        mock_configure_container.return_value = mock_container
        mock_initialize_telemetry.return_value = mock_telemetry

        # Test lifespan startup and shutdown
        async with lifespan(app):
            # During lifespan, app should have state attributes
            assert hasattr(app.state, "feature_manager")
            assert hasattr(app.state, "container")
            assert hasattr(app.state, "telemetry")

    @pytest.mark.asyncio
    async def test_health_endpoint(self) -> None:
        """Test health check endpoint."""
        app = create_app()

        # Get the health check route function
        for route in app.routes:
            if hasattr(route, "path") and route.path == "/health":
                health_func = route.endpoint
                result = await health_func()

                assert result["status"] == "healthy"
                assert result["service"] == "chronoguard"
                assert result["version"] == "1.0.0"
                break
        else:
            pytest.fail("Health endpoint not found")


class TestTelemetryCoverage:
    """Test telemetry components for coverage."""

    def test_chronoguard_telemetry_creation(self) -> None:
        """Test ChronoGuardTelemetry creation."""
        from core.features import FeatureManager

        feature_manager = FeatureManager()
        telemetry = ChronoGuardTelemetry(
            service_name="test-service",
            service_version="0.1.0",
            environment="testing",
            feature_manager=feature_manager,
        )

        assert telemetry.service_name == "test-service"
        assert telemetry.service_version == "0.1.0"
        assert telemetry.environment == "testing"
        assert telemetry.feature_manager == feature_manager

    @patch("infrastructure.observability.telemetry.Resource")
    def test_create_resource(self, mock_resource) -> None:
        """Test resource creation."""
        mock_resource.create.return_value = "test_resource"

        telemetry = ChronoGuardTelemetry()
        result = telemetry._create_resource()

        assert mock_resource.create.call_count == 2  # Called twice as expected

    def test_should_enable_flags(self) -> None:
        """Test feature flag checking methods."""
        from core.features import FeatureManager

        feature_manager = FeatureManager()
        telemetry = ChronoGuardTelemetry(feature_manager=feature_manager)

        # Test tracing enablement
        tracing_enabled = telemetry._should_enable_tracing()
        assert isinstance(tracing_enabled, bool)

        # Test metrics enablement
        metrics_enabled = telemetry._should_enable_metrics()
        assert isinstance(metrics_enabled, bool)

        # Test prometheus enablement
        prometheus_enabled = telemetry._should_enable_prometheus()
        assert isinstance(prometheus_enabled, bool)

    def test_telemetry_without_feature_manager(self) -> None:
        """Test telemetry without feature manager."""
        telemetry = ChronoGuardTelemetry()

        # Should still work with defaults
        assert telemetry._should_enable_tracing() is True
        assert telemetry._should_enable_metrics() is True

    @patch("infrastructure.observability.telemetry.trace")
    @patch("infrastructure.observability.telemetry.metrics")
    def test_telemetry_getters(self, mock_metrics, mock_trace) -> None:
        """Test telemetry getter methods."""
        # Create proper mock objects instead of strings
        mock_tracer = MagicMock()
        mock_meter = MagicMock()

        mock_trace.get_tracer.return_value = mock_tracer
        mock_metrics.get_meter.return_value = mock_meter

        telemetry = ChronoGuardTelemetry()

        tracer = telemetry.get_tracer("test")
        meter = telemetry.get_meter("test")

        assert tracer == mock_tracer
        assert meter == mock_meter

    def test_chronoguard_metrics_creation(self) -> None:
        """Test ChronoGuardMetrics creation."""
        mock_meter_provider = MagicMock()
        mock_meter = MagicMock()
        mock_meter_provider.get_meter.return_value = mock_meter

        # Mock all the metric creation methods
        mock_meter.create_counter.return_value = MagicMock()
        mock_meter.create_histogram.return_value = MagicMock()
        mock_meter.create_up_down_counter.return_value = MagicMock()

        metrics = ChronoGuardMetrics(mock_meter_provider)

        assert metrics.meter == mock_meter
        # Verify metrics were created
        assert mock_meter.create_counter.call_count >= 5
        assert mock_meter.create_histogram.call_count >= 3

    def test_chronoguard_metrics_recording(self) -> None:
        """Test ChronoGuardMetrics recording methods."""
        mock_meter_provider = MagicMock()
        mock_meter = MagicMock()
        mock_meter_provider.get_meter.return_value = mock_meter

        # Mock metrics
        mock_counter = MagicMock()
        mock_histogram = MagicMock()
        mock_meter.create_counter.return_value = mock_counter
        mock_meter.create_histogram.return_value = mock_histogram
        mock_meter.create_up_down_counter.return_value = MagicMock()

        metrics = ChronoGuardMetrics(mock_meter_provider)

        # Test recording methods
        metrics.record_access_request("tenant-123", "agent-456", "example.com", "allow", 0.15)
        metrics.record_policy_evaluation("tenant-123", "policy-789", 0.05, True)
        metrics.record_audit_entry("tenant-123", "agent-456", "allow")
        metrics.record_audit_verification("tenant-123", "agent-456", True)
        metrics.record_security_event("auth_failure", "medium", "tenant-123")
        metrics.record_database_query("SELECT", 0.1, True)

        # Verify metrics were recorded (add() calls)
        assert mock_counter.add.call_count >= 4
        assert mock_histogram.record.call_count >= 2

    @patch("infrastructure.observability.telemetry._telemetry", None)
    def test_global_telemetry_functions(self) -> None:
        """Test global telemetry utility functions."""
        # Test with no telemetry initialized
        assert get_telemetry() is None
        assert get_metrics() is None

        # Test initialization (with mocked setup to prevent shutdown issues)
        with patch.object(ChronoGuardTelemetry, "initialize"):
            from core.features import FeatureManager

            feature_manager = FeatureManager()

            telemetry = initialize_telemetry(
                service_name="test",
                service_version="1.0.0",
                environment="testing",
                feature_manager=feature_manager,
            )

            assert isinstance(telemetry, ChronoGuardTelemetry)

    @patch("infrastructure.observability.telemetry.FastAPIInstrumentor")
    @patch("infrastructure.observability.telemetry.SQLAlchemyInstrumentor")
    @patch("infrastructure.observability.telemetry.RedisInstrumentor")
    def test_setup_instrumentation(
        self, mock_redis_instr, mock_sql_instr, mock_fastapi_instr
    ) -> None:
        """Test automatic instrumentation setup."""
        from core.features import FeatureManager

        feature_manager = FeatureManager()
        telemetry = ChronoGuardTelemetry(feature_manager=feature_manager)

        # Mock the should_enable_tracing to return True
        telemetry._should_enable_tracing = MagicMock(return_value=True)

        telemetry._setup_instrumentation()

        # Verify instrumentation was called
        mock_fastapi_instr.instrument.assert_called_once()
        mock_sql_instr.instrument.assert_called_once()

    @patch.dict("os.environ", {"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://otel:4318"})
    @patch("infrastructure.observability.telemetry.OTLPSpanExporter")
    @patch("infrastructure.observability.telemetry.BatchSpanProcessor")
    @patch("infrastructure.observability.telemetry.TracerProvider")
    def test_setup_tracing_with_otlp(
        self, mock_tracer_provider, mock_processor, mock_exporter
    ) -> None:
        """Test tracing setup with OTLP endpoint."""
        mock_exporter.return_value = "otlp_exporter"
        mock_processor.return_value = "batch_processor"
        mock_provider_instance = MagicMock()
        mock_tracer_provider.return_value = mock_provider_instance

        telemetry = ChronoGuardTelemetry()

        # Mock the feature check to enable tracing
        with patch.object(telemetry, "_should_enable_tracing", return_value=True):
            telemetry._setup_tracing()

        # Verify tracer provider was created and span processor was added
        mock_tracer_provider.assert_called_once()
        mock_provider_instance.add_span_processor.assert_called()

    @patch.dict("os.environ", {"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://otel:4318"})
    @patch("infrastructure.observability.telemetry.OTLPMetricExporter")
    @patch("infrastructure.observability.telemetry.PeriodicExportingMetricReader")
    @patch("infrastructure.observability.telemetry.PrometheusMetricReader")
    @patch("infrastructure.observability.telemetry.MeterProvider")
    def test_setup_metrics_with_otlp(
        self, mock_meter_provider, mock_prometheus, mock_periodic, mock_exporter
    ) -> None:
        """Test metrics setup with OTLP endpoint."""
        # Create proper mock objects
        mock_otlp_exporter = MagicMock()
        mock_prometheus_reader = MagicMock()
        mock_periodic_reader = MagicMock()
        mock_provider = MagicMock()

        mock_exporter.return_value = mock_otlp_exporter
        mock_prometheus.return_value = mock_prometheus_reader
        mock_periodic.return_value = mock_periodic_reader
        mock_meter_provider.return_value = mock_provider

        telemetry = ChronoGuardTelemetry()
        telemetry._should_enable_metrics = MagicMock(return_value=True)
        telemetry._should_enable_prometheus = MagicMock(return_value=True)

        # This would test the OTLP metrics exporter path
        telemetry._setup_metrics()


class TestAuditHasherCoverage:
    """Test audit hasher for coverage."""

    def test_enhanced_audit_hasher_creation(self) -> None:
        """Test EnhancedAuditHasher creation."""
        from domain.audit.hasher import EnhancedAuditHasher

        # Test with provided secret
        hasher1 = EnhancedAuditHasher(b"test_secret_32_bytes_long_enough")
        assert len(hasher1.secret_key) >= 32

        # Test with generated secret
        hasher2 = EnhancedAuditHasher()
        assert len(hasher2.secret_key) == 32

    def test_audit_hash_error(self) -> None:
        """Test AuditHashError exception."""
        from domain.audit.hasher import AuditHashError

        error = AuditHashError("Hash computation failed")
        assert error.violation_type == "AUDIT_HASH_ERROR"
        assert "Hash computation failed" in str(error)

    def test_merkle_root_computation(self) -> None:
        """Test merkle root hash computation."""
        from domain.audit.hasher import EnhancedAuditHasher

        hasher = EnhancedAuditHasher()

        # Test empty hashes
        result = hasher._compute_merkle_root([])
        assert result == ""

        # Test single hash
        result = hasher._compute_merkle_root(["hash1"])
        assert result == "hash1"

        # Test multiple hashes
        result = hasher._compute_merkle_root(["hash1", "hash2"])
        assert isinstance(result, str)
        assert len(result) == 64  # SHA-256 hex string

    def test_sign_proof(self) -> None:
        """Test proof signing."""
        from domain.audit.hasher import EnhancedAuditHasher

        hasher = EnhancedAuditHasher()
        proof = {"root_hash": "abc123", "entry_count": "10", "timestamp": "2023-09-28T10:00:00Z"}

        signature = hasher._sign_proof(proof)
        assert isinstance(signature, str)
        assert len(signature) == 64  # SHA-256 hex signature
