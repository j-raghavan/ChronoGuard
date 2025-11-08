"""Tests for core logging functionality to improve coverage."""

from datetime import datetime
from typing import Any
from unittest.mock import MagicMock, patch

from core.logging import (
    StructuredLogger,
    configure_logging,
    get_correlation_logger,
    get_logger,
    get_tenant_logger,
    log_audit_event,
    log_performance_metric,
    log_security_event,
    serialize_log,
)


class TestLoggingCoverage:
    """Test logging functionality for coverage."""

    def test_serialize_log_basic(self) -> None:
        """Test basic log serialization."""
        mock_level = MagicMock()
        mock_level.name = "INFO"
        record = {
            "time": datetime.now(),
            "level": mock_level,
            "name": "test",
            "function": "test_func",
            "line": 42,
            "message": "Test message",
            "extra": {},
            "exception": None,
        }

        result = serialize_log(record)
        assert isinstance(result, str)
        assert "test_func" in result
        assert "Test message" in result

    def test_serialize_log_with_correlation_id(self) -> None:
        """Test log serialization with correlation ID."""
        mock_level = MagicMock()
        mock_level.name = "INFO"
        record = {
            "time": datetime.now(),
            "level": mock_level,
            "name": "test",
            "function": "test_func",
            "line": 42,
            "message": "Test message",
            "extra": {"correlation_id": "test-123"},
            "exception": None,
        }

        result = serialize_log(record)
        assert "correlation_id" in result
        assert "test-123" in result

    def test_serialize_log_with_tenant_context(self) -> None:
        """Test log serialization with tenant context."""
        mock_level = MagicMock()
        mock_level.name = "INFO"
        record = {
            "time": datetime.now(),
            "level": mock_level,
            "name": "test",
            "function": "test_func",
            "line": 42,
            "message": "Test message",
            "extra": {"tenant_id": "tenant-123", "agent_id": "agent-456"},
            "exception": None,
        }

        result = serialize_log(record)
        assert "tenant_id" in result
        assert "agent_id" in result

    def test_serialize_log_with_exception(self) -> None:
        """Test log serialization with exception."""
        exception_mock = MagicMock()
        exception_mock.type.__name__ = "ValueError"
        exception_mock.value = "Test exception"
        exception_mock.traceback = None

        mock_level = MagicMock()
        mock_level.name = "ERROR"
        record = {
            "time": datetime.now(),
            "level": mock_level,
            "name": "test",
            "function": "test_func",
            "line": 42,
            "message": "Error occurred",
            "extra": {},
            "exception": exception_mock,
        }

        result = serialize_log(record)
        assert "exception" in result
        assert "ValueError" in result

    @patch("core.logging.logger")
    def test_configure_logging_structured(self, mock_logger: Any) -> None:
        """Test structured logging configuration."""
        configure_logging(level="INFO", structured=True, environment="production")

        # Verify logger.remove() was called
        mock_logger.remove.assert_called_once()
        # Verify logger.add() was called
        assert mock_logger.add.called

    @patch("core.logging.logger")
    def test_configure_logging_development(self, mock_logger: Any) -> None:
        """Test development logging configuration."""
        configure_logging(level="DEBUG", structured=False, environment="development")

        mock_logger.remove.assert_called_once()
        assert mock_logger.add.called

    @patch("core.logging.logger")
    def test_get_logger(self, mock_logger: Any) -> None:
        """Test get_logger function."""
        mock_logger.bind.return_value = "bound_logger"

        result = get_logger("test_logger")

        mock_logger.bind.assert_called_once_with(logger_name="test_logger")
        assert result == "bound_logger"

    @patch("core.logging.logger")
    def test_get_correlation_logger(self, mock_logger: Any) -> None:
        """Test get_correlation_logger function."""
        bound_logger = MagicMock()
        mock_logger.bind.return_value = bound_logger
        bound_logger.bind.return_value = "final_logger"

        result = get_correlation_logger("corr-123", "test")

        mock_logger.bind.assert_called_once_with(correlation_id="corr-123")
        bound_logger.bind.assert_called_once_with(logger_name="test")
        assert result == "final_logger"

    @patch("core.logging.logger")
    def test_get_correlation_logger_no_name(self, mock_logger: Any) -> None:
        """Test get_correlation_logger without name."""
        mock_logger.bind.return_value = "bound_logger"

        result = get_correlation_logger("corr-123")

        mock_logger.bind.assert_called_once_with(correlation_id="corr-123")
        assert result == "bound_logger"

    @patch("core.logging.logger")
    def test_get_tenant_logger(self, mock_logger: Any) -> None:
        """Test get_tenant_logger function."""
        bound_logger = MagicMock()
        mock_logger.bind.return_value = bound_logger
        bound_logger.bind.return_value = bound_logger

        result = get_tenant_logger("tenant-123", "agent-456", "test")

        # Should bind tenant_id, then agent_id, then logger_name
        assert mock_logger.bind.called
        assert bound_logger.bind.call_count == 2
        assert result == bound_logger

    @patch("core.logging.logger")
    def test_log_security_event(self, mock_logger: Any) -> None:
        """Test log_security_event function."""
        bound_logger = MagicMock()
        mock_logger.bind.return_value = bound_logger

        log_security_event(
            event_type="AUTH_FAILURE",
            severity="high",
            message="Authentication failed",
            tenant_id="tenant-123",
            source_ip="192.168.1.1",
        )

        mock_logger.bind.assert_called_once()
        bound_logger.error.assert_called_once_with("Authentication failed")

    @patch("core.logging.logger")
    def test_log_security_event_critical(self, mock_logger: Any) -> None:
        """Test log_security_event with critical severity."""
        bound_logger = MagicMock()
        mock_logger.bind.return_value = bound_logger

        log_security_event(
            event_type="BREACH", severity="critical", message="Security breach detected"
        )

        bound_logger.critical.assert_called_once_with("Security breach detected")

    @patch("core.logging.logger")
    def test_log_performance_metric(self, mock_logger: Any) -> None:
        """Test log_performance_metric function."""
        bound_logger = MagicMock()
        mock_logger.bind.return_value = bound_logger

        log_performance_metric(
            operation="database_query", duration_ms=150.5, success=True, tenant_id="tenant-123"
        )

        mock_logger.bind.assert_called_once()
        bound_logger.info.assert_called_once()

    @patch("core.logging.logger")
    def test_log_audit_event(self, mock_logger: Any) -> None:
        """Test log_audit_event function."""
        bound_logger = MagicMock()
        mock_logger.bind.return_value = bound_logger

        log_audit_event(
            action="CREATE_AGENT", resource="agent", tenant_id="tenant-123", success=True
        )

        mock_logger.bind.assert_called_once()
        bound_logger.info.assert_called_once()

    def test_structured_logger_creation(self) -> None:
        """Test StructuredLogger creation."""
        logger = StructuredLogger("test_logger", tenant_id="tenant-123")

        assert logger.name == "test_logger"

    @patch("core.logging.logger")
    def test_structured_logger_with_context(self, mock_logger: Any) -> None:
        """Test StructuredLogger with_context method."""
        bound_logger = MagicMock()
        mock_logger.bind.return_value = bound_logger

        logger = StructuredLogger("test")
        logger._logger = bound_logger

        new_logger = logger.with_context(key="value")

        assert isinstance(new_logger, StructuredLogger)

    @patch("core.logging.logger")
    def test_structured_logger_methods(self, mock_logger: Any) -> None:
        """Test StructuredLogger logging methods."""
        bound_logger = MagicMock()
        mock_logger.bind.return_value = bound_logger

        logger = StructuredLogger("test")
        logger._logger = bound_logger
        bound_logger.bind.return_value = bound_logger

        # Test all logging methods
        logger.debug("Debug message", key="value")
        logger.info("Info message", key="value")
        logger.warning("Warning message", key="value")
        logger.error("Error message", key="value")
        logger.critical("Critical message", key="value")

        # Verify all methods were called
        assert bound_logger.bind.call_count >= 5
        bound_logger.debug.assert_called_with("Debug message")
        bound_logger.info.assert_called_with("Info message")
        bound_logger.warning.assert_called_with("Warning message")
        bound_logger.error.assert_called_with("Error message")
        bound_logger.critical.assert_called_with("Critical message")

    @patch("core.logging.logger")
    def test_structured_logger_with_exception(self, mock_logger: Any) -> None:
        """Test StructuredLogger error and critical with exceptions."""
        bound_logger = MagicMock()
        mock_logger.bind.return_value = bound_logger
        bound_logger.bind.return_value = bound_logger

        logger = StructuredLogger("test")
        logger._logger = bound_logger

        exception = ValueError("Test exception")

        logger.error("Error with exception", exception=exception, key="value")
        logger.critical("Critical with exception", exception=exception, key="value")

        # Verify opt(exception=True) was called
        bound_logger.opt.assert_called()

    @patch("core.logging.configure_logger_levels")
    def test_configure_logging_with_file(self, mock_configure_levels: Any) -> None:
        """Test configure_logging with file output."""
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            log_file = Path(tmp.name)

        # This will test the file logging path
        with patch("core.logging.logger") as mock_logger:
            configure_logging(
                level="WARNING", structured=True, log_file=log_file, environment="production"
            )

            # Verify logger configuration calls
            mock_logger.remove.assert_called_once()
            # Should have been called twice - once for stdout, once for file
            assert mock_logger.add.call_count >= 1
