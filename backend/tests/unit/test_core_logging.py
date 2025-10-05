"""Tests for core logging functionality."""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

from core.logging import (
    StructuredLogger,
    configure_logger_levels,
    configure_logging,
    get_correlation_logger,
    get_logger,
    get_tenant_logger,
    log_audit_event,
    log_performance_metric,
    log_security_event,
    serialize_log,
)


class TestSerializeLog:
    """Test log serialization functionality."""

    def test_serialize_log_basic(self):
        """Test basic log serialization."""
        mock_level = Mock()
        mock_level.name = "INFO"
        record = {
            "time": datetime.now(),
            "level": mock_level,
            "name": "test_logger",
            "function": "test_function",
            "line": 42,
            "message": "Test message",
            "extra": {},
            "exception": None,
        }

        result = serialize_log(record)
        data = json.loads(result)

        assert "timestamp" in data
        assert data["level"] == "INFO"
        assert data["logger"] == "test_logger"
        assert data["function"] == "test_function"
        assert data["line"] == 42
        assert data["message"] == "Test message"

    def test_serialize_log_with_correlation_id(self):
        """Test log serialization with correlation ID."""
        mock_level = Mock()
        mock_level.name = "DEBUG"
        record = {
            "time": datetime.now(),
            "level": mock_level,
            "name": "test_logger",
            "function": "test_function",
            "line": 42,
            "message": "Test message",
            "extra": {"correlation_id": "test-corr-123"},
            "exception": None,
        }

        result = serialize_log(record)
        data = json.loads(result)

        assert data["correlation_id"] == "test-corr-123"

    def test_serialize_log_with_tenant_context(self):
        """Test log serialization with tenant context."""
        mock_level = Mock()
        mock_level.name = "INFO"
        record = {
            "time": datetime.now(),
            "level": mock_level,
            "name": "test_logger",
            "function": "test_function",
            "line": 42,
            "message": "Test message",
            "extra": {"tenant_id": "tenant-123", "agent_id": "agent-456"},
            "exception": None,
        }

        result = serialize_log(record)
        data = json.loads(result)

        assert data["tenant_id"] == "tenant-123"
        assert data["agent_id"] == "agent-456"

    def test_serialize_log_with_exception(self):
        """Test log serialization with exception."""
        # Mock exception
        mock_exception = Mock()
        mock_exception.type.__name__ = "ValueError"
        mock_exception.value = "Test error"
        mock_exception.traceback = Mock()
        mock_exception.traceback.format.return_value = "Traceback: line 1"

        mock_level = Mock()
        mock_level.name = "ERROR"
        record = {
            "time": datetime.now(),
            "level": mock_level,
            "name": "test_logger",
            "function": "test_function",
            "line": 42,
            "message": "Error occurred",
            "extra": {},
            "exception": mock_exception,
        }

        result = serialize_log(record)
        data = json.loads(result)

        assert data["exception"]["type"] == "ValueError"
        assert data["exception"]["value"] == "Test error"
        assert data["exception"]["traceback"] == "Traceback: line 1"

    def test_serialize_log_with_extra_fields(self):
        """Test log serialization with extra fields."""
        mock_level = Mock()
        mock_level.name = "INFO"
        record = {
            "time": datetime.now(),
            "level": mock_level,
            "name": "test_logger",
            "function": "test_function",
            "line": 42,
            "message": "Test message",
            "extra": {
                "tenant_id": "tenant-123",
                "custom_field": "custom_value",
                "request_id": "req-456",
            },
            "exception": None,
        }

        result = serialize_log(record)
        data = json.loads(result)

        assert data["tenant_id"] == "tenant-123"
        assert data["extra"]["custom_field"] == "custom_value"
        assert data["extra"]["request_id"] == "req-456"
        # tenant_id should not be duplicated in extra
        assert "tenant_id" not in data["extra"]


class TestConfigureLogging:
    """Test logging configuration."""

    @patch("core.logging.logger")
    def test_configure_logging_structured(self, mock_logger):
        """Test structured logging configuration."""
        mock_logger.remove = Mock()
        mock_logger.add = Mock()

        configure_logging(level="INFO", structured=True, environment="production")

        mock_logger.remove.assert_called_once()
        # Should add at least console handler
        assert mock_logger.add.call_count >= 1

    @patch("core.logging.logger")
    def test_configure_logging_text_format(self, mock_logger):
        """Test text logging configuration."""
        mock_logger.remove = Mock()
        mock_logger.add = Mock()

        configure_logging(level="DEBUG", structured=False, environment="development")

        mock_logger.remove.assert_called_once()
        mock_logger.add.assert_called()

    @patch("core.logging.logger")
    def test_configure_logging_with_file(self, mock_logger):
        """Test logging configuration with file."""
        mock_logger.remove = Mock()
        mock_logger.add = Mock()

        log_file = Path("/tmp/test.log")
        configure_logging(log_file=log_file)

        mock_logger.remove.assert_called_once()
        # Should add console + file handlers
        assert mock_logger.add.call_count >= 2

    @patch("core.logging.configure_logger_levels")
    @patch("core.logging.logger")
    def test_configure_logging_calls_level_config(self, mock_logger, mock_configure_levels):
        """Test that logging configuration calls level configuration."""
        mock_logger.remove = Mock()
        mock_logger.add = Mock()

        configure_logging(environment="production")

        mock_configure_levels.assert_called_once_with("production")


class TestConfigureLoggerLevels:
    """Test logger level configuration."""

    @patch("core.logging.logger")
    def test_configure_logger_levels_development(self, mock_logger):
        """Test logger level configuration for development."""
        mock_logger.level = Mock()

        configure_logger_levels("development")

        mock_logger.level.assert_called_with("TRACE", color="<dim>")

    @patch("core.logging.logger")
    def test_configure_logger_levels_production(self, mock_logger):
        """Test logger level configuration for production."""
        mock_logger.disable = Mock()

        configure_logger_levels("production")

        # Should disable noisy loggers in production
        mock_logger.disable.assert_any_call("urllib3")
        mock_logger.disable.assert_any_call("httpx")
        mock_logger.disable.assert_any_call("asyncio")


class TestGetLogger:
    """Test logger factory functions."""

    @patch("core.logging.logger")
    def test_get_logger(self, mock_logger):
        """Test getting a named logger."""
        mock_logger.bind = Mock(return_value="bound_logger")

        result = get_logger("test_logger")

        mock_logger.bind.assert_called_once_with(logger_name="test_logger")
        assert result == "bound_logger"

    @patch("core.logging.logger")
    def test_get_correlation_logger(self, mock_logger):
        """Test getting correlation logger."""
        mock_bound = Mock()
        mock_logger.bind.return_value = mock_bound
        mock_bound.bind.return_value = "final_logger"

        result = get_correlation_logger("corr-123", "test_logger")

        mock_logger.bind.assert_called_once_with(correlation_id="corr-123")
        mock_bound.bind.assert_called_once_with(logger_name="test_logger")
        assert result == "final_logger"

    @patch("core.logging.logger")
    def test_get_correlation_logger_no_name(self, mock_logger):
        """Test getting correlation logger without name."""
        mock_logger.bind.return_value = "bound_logger"

        result = get_correlation_logger("corr-123")

        mock_logger.bind.assert_called_once_with(correlation_id="corr-123")
        assert result == "bound_logger"

    @patch("core.logging.logger")
    def test_get_tenant_logger(self, mock_logger):
        """Test getting tenant logger."""
        mock_bound = Mock()
        mock_logger.bind.return_value = mock_bound
        mock_bound.bind.return_value = mock_bound

        result = get_tenant_logger("tenant-123", "agent-456", "test_logger")

        mock_logger.bind.assert_called_once_with(tenant_id="tenant-123")
        # Should bind agent_id and logger_name
        assert mock_bound.bind.call_count == 2

    @patch("core.logging.logger")
    def test_get_tenant_logger_minimal(self, mock_logger):
        """Test getting tenant logger with minimal args."""
        mock_logger.bind.return_value = "bound_logger"

        result = get_tenant_logger("tenant-123")

        mock_logger.bind.assert_called_once_with(tenant_id="tenant-123")
        assert result == "bound_logger"


class TestSpecializedLogging:
    """Test specialized logging functions."""

    @patch("core.logging.logger")
    def test_log_security_event_critical(self, mock_logger):
        """Test logging critical security event."""
        mock_bound = Mock()
        mock_logger.bind.return_value = mock_bound
        mock_bound.critical = Mock()

        log_security_event(
            event_type="authentication_failure",
            severity="critical",
            message="Failed login attempt",
            tenant_id="tenant-123",
            source_ip="192.168.1.1",
        )

        mock_logger.bind.assert_called_once()
        mock_bound.critical.assert_called_once_with("Failed login attempt")

    @patch("core.logging.logger")
    def test_log_security_event_low_severity(self, mock_logger):
        """Test logging low severity security event."""
        mock_bound = Mock()
        mock_logger.bind.return_value = mock_bound
        mock_bound.info = Mock()

        log_security_event(
            event_type="user_access", severity="low", message="User accessed resource"
        )

        mock_bound.info.assert_called_once_with("User accessed resource")

    @patch("core.logging.logger")
    def test_log_performance_metric(self, mock_logger):
        """Test logging performance metric."""
        mock_bound = Mock()
        mock_logger.bind.return_value = mock_bound
        mock_bound.info = Mock()

        log_performance_metric(
            operation="database_query",
            duration_ms=150.5,
            success=True,
            tenant_id="tenant-123",
            additional_metrics={"query_count": 3},
        )

        mock_logger.bind.assert_called_once()
        mock_bound.info.assert_called_once()
        # Verify context was passed
        call_args = mock_logger.bind.call_args[1]
        assert call_args["operation"] == "database_query"
        assert call_args["duration_ms"] == 150.5
        assert call_args["success"] is True
        assert call_args["query_count"] == 3

    @patch("core.logging.logger")
    def test_log_audit_event(self, mock_logger):
        """Test logging audit event."""
        mock_bound = Mock()
        mock_logger.bind.return_value = mock_bound
        mock_bound.info = Mock()

        log_audit_event(
            action="create",
            resource="user",
            tenant_id="tenant-123",
            agent_id="agent-456",
            user_id="user-789",
            success=True,
            additional_data={"resource_id": "123"},
        )

        mock_logger.bind.assert_called_once()
        mock_bound.info.assert_called_once_with("Audit: create on user succeeded")

    @patch("core.logging.logger")
    def test_log_audit_event_failure(self, mock_logger):
        """Test logging failed audit event."""
        mock_bound = Mock()
        mock_logger.bind.return_value = mock_bound
        mock_bound.info = Mock()

        log_audit_event(action="delete", resource="policy", tenant_id="tenant-123", success=False)

        mock_bound.info.assert_called_once_with("Audit: delete on policy failed")


class TestStructuredLogger:
    """Test StructuredLogger class."""

    @patch("core.logging.logger")
    def test_structured_logger_init(self, mock_logger):
        """Test StructuredLogger initialization."""
        mock_logger.bind.return_value = mock_logger

        logger_instance = StructuredLogger(
            "test_logger", tenant_id="tenant-123", agent_id="agent-456", correlation_id="corr-789"
        )

        assert logger_instance.name == "test_logger"
        # Should bind all context
        assert mock_logger.bind.call_count >= 1

    @patch("core.logging.logger")
    def test_structured_logger_minimal_init(self, mock_logger):
        """Test StructuredLogger with minimal args."""
        mock_logger.bind.return_value = mock_logger

        logger_instance = StructuredLogger("test_logger")

        assert logger_instance.name == "test_logger"
        mock_logger.bind.assert_called_once_with(logger_name="test_logger")

    @patch("core.logging.logger")
    def test_structured_logger_with_context(self, mock_logger):
        """Test StructuredLogger with_context method."""
        mock_logger.bind.return_value = mock_logger

        logger_instance = StructuredLogger("test_logger")
        new_logger = logger_instance.with_context(request_id="req-123")

        assert isinstance(new_logger, StructuredLogger)
        assert new_logger.name == "test_logger"

    @patch("core.logging.logger")
    def test_structured_logger_debug(self, mock_logger):
        """Test StructuredLogger debug method."""
        mock_bound = Mock()
        mock_logger.bind.return_value = mock_bound
        mock_bound.bind.return_value = mock_bound
        mock_bound.debug = Mock()

        logger_instance = StructuredLogger("test_logger")
        logger_instance.debug("Debug message", extra_field="value")

        mock_bound.debug.assert_called_once_with("Debug message")

    @patch("core.logging.logger")
    def test_structured_logger_info(self, mock_logger):
        """Test StructuredLogger info method."""
        mock_bound = Mock()
        mock_logger.bind.return_value = mock_bound
        mock_bound.bind.return_value = mock_bound
        mock_bound.info = Mock()

        logger_instance = StructuredLogger("test_logger")
        logger_instance.info("Info message")

        mock_bound.info.assert_called_once_with("Info message")

    @patch("core.logging.logger")
    def test_structured_logger_error_with_exception(self, mock_logger):
        """Test StructuredLogger error with exception."""
        mock_bound = Mock()
        mock_logger.bind.return_value = mock_bound
        mock_bound.bind.return_value = mock_bound
        mock_opt = Mock()
        mock_bound.opt.return_value = mock_opt
        mock_opt.error = Mock()

        exception = ValueError("Test error")
        logger_instance = StructuredLogger("test_logger")
        logger_instance.error("Error occurred", exception=exception)

        mock_bound.opt.assert_called_once_with(exception=True)
        mock_opt.error.assert_called_once_with("Error occurred")

    @patch("core.logging.logger")
    def test_structured_logger_error_without_exception(self, mock_logger):
        """Test StructuredLogger error without exception."""
        mock_bound = Mock()
        mock_logger.bind.return_value = mock_bound
        mock_bound.bind.return_value = mock_bound
        mock_bound.error = Mock()

        logger_instance = StructuredLogger("test_logger")
        logger_instance.error("Error occurred")

        mock_bound.error.assert_called_once_with("Error occurred")

    @patch("core.logging.logger")
    def test_structured_logger_critical(self, mock_logger):
        """Test StructuredLogger critical method."""
        mock_bound = Mock()
        mock_logger.bind.return_value = mock_bound
        mock_bound.bind.return_value = mock_bound
        mock_bound.critical = Mock()

        logger_instance = StructuredLogger("test_logger")
        logger_instance.critical("Critical error")

        mock_bound.critical.assert_called_once_with("Critical error")

    @patch("core.logging.logger")
    def test_structured_logger_warning(self, mock_logger):
        """Test StructuredLogger warning method."""
        mock_bound = Mock()
        mock_logger.bind.return_value = mock_bound
        mock_bound.bind.return_value = mock_bound
        mock_bound.warning = Mock()

        logger_instance = StructuredLogger("test_logger")
        logger_instance.warning("Warning message")

        mock_bound.warning.assert_called_once_with("Warning message")
