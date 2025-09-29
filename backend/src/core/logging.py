"""Loguru logging configuration for ChronoGuard."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from loguru import logger


def serialize_log(record: dict[str, Any]) -> str:
    """Serialize log record to JSON for structured logging.

    Args:
        record: Log record from loguru

    Returns:
        JSON string
    """
    subset = {
        "timestamp": record["time"].isoformat(),
        "level": record["level"].name,
        "logger": record["name"],
        "function": record["function"],
        "line": record["line"],
        "message": record["message"],
    }

    # Add correlation ID if present
    if "correlation_id" in record["extra"]:
        subset["correlation_id"] = record["extra"]["correlation_id"]

    # Add tenant/agent context if present
    if "tenant_id" in record["extra"]:
        subset["tenant_id"] = record["extra"]["tenant_id"]
    if "agent_id" in record["extra"]:
        subset["agent_id"] = record["extra"]["agent_id"]

    # Add exception if present
    if record["exception"]:
        subset["exception"] = {
            "type": record["exception"].type.__name__,
            "value": str(record["exception"].value),
            "traceback": (
                record["exception"].traceback.format() if record["exception"].traceback else None
            ),
        }

    # Add all extra fields (excluding already processed ones)
    subset["extra"] = {
        k: v
        for k, v in record["extra"].items()
        if k not in ["correlation_id", "tenant_id", "agent_id"]
    }

    return json.dumps(subset)


def configure_logging(
    level: str = "INFO",
    structured: bool = True,
    log_file: Path | None = None,
    environment: str = "production",
) -> None:
    """Configure loguru logging for production.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        structured: Use JSON structured logging
        log_file: Optional file path for logs
        environment: Deployment environment (development/production)
    """
    # Remove default handler
    logger.remove()

    # Enable backtrace/diagnose only in development for security
    enable_debug_info = environment == "development"

    if structured:
        # JSON logging for production (no backtrace/diagnose for security)
        logger.add(
            sys.stdout,
            format=serialize_log,
            level=level,
            backtrace=enable_debug_info,
            diagnose=enable_debug_info,
        )
    else:
        # Human-readable logging for development
        logger.add(
            sys.stdout,
            format=(
                "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
                "<level>{level: <8}</level> | "
                "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
                "<level>{message}</level> | "
                "{extra}"
            ),
            level=level,
            colorize=True,
            backtrace=True,
            diagnose=True,
        )

    # Add file logging if specified
    if log_file:
        logger.add(
            log_file,
            format=serialize_log if structured else None,
            level=level,
            rotation="100 MB",
            retention="30 days",
            compression="gz",
            backtrace=enable_debug_info,
            diagnose=enable_debug_info,
        )

    # Configure specific loggers
    configure_logger_levels(environment)


def configure_logger_levels(environment: str) -> None:
    """Configure logging levels for different components.

    Args:
        environment: Deployment environment
    """
    # Set levels based on environment
    if environment == "development":
        # More verbose in development
        logger.level("TRACE", color="<dim>")
        pass  # Keep default levels
    elif environment == "production":
        # Less verbose in production
        logger.disable("urllib3")
        logger.disable("httpx")
        logger.disable("asyncio")


def get_logger(name: str) -> Any:
    """Get a logger instance with the specified name.

    Args:
        name: Logger name

    Returns:
        Configured logger instance
    """
    return logger.bind(logger_name=name)


def get_correlation_logger(correlation_id: str, name: str = "") -> Any:
    """Get a logger with correlation ID bound.

    Args:
        correlation_id: Correlation ID for request tracing
        name: Optional logger name

    Returns:
        Logger with correlation ID bound
    """
    bound_logger = logger.bind(correlation_id=correlation_id)
    if name:
        bound_logger = bound_logger.bind(logger_name=name)
    return bound_logger


def get_tenant_logger(tenant_id: str, agent_id: str | None = None, name: str = "") -> Any:
    """Get a logger with tenant context bound.

    Args:
        tenant_id: Tenant ID
        agent_id: Optional agent ID
        name: Optional logger name

    Returns:
        Logger with tenant context bound
    """
    bound_logger = logger.bind(tenant_id=tenant_id)
    if agent_id:
        bound_logger = bound_logger.bind(agent_id=agent_id)
    if name:
        bound_logger = bound_logger.bind(logger_name=name)
    return bound_logger


def log_security_event(
    event_type: str,
    severity: str,
    message: str,
    tenant_id: str | None = None,
    agent_id: str | None = None,
    source_ip: str | None = None,
    additional_context: dict[str, Any] | None = None,
) -> None:
    """Log security events with standardized format.

    Args:
        event_type: Type of security event
        severity: Event severity (low, medium, high, critical)
        message: Event message
        tenant_id: Optional tenant ID
        agent_id: Optional agent ID
        source_ip: Optional source IP
        additional_context: Additional context data
    """
    context = {
        "event_type": event_type,
        "severity": severity,
        "security_event": True,
    }

    if tenant_id:
        context["tenant_id"] = tenant_id
    if agent_id:
        context["agent_id"] = agent_id
    if source_ip:
        context["source_ip"] = source_ip
    if additional_context:
        context.update(additional_context)

    security_logger = logger.bind(**context)

    # Log at appropriate level based on severity
    if severity == "critical":
        security_logger.critical(message)
    elif severity == "high":
        security_logger.error(message)
    elif severity == "medium":
        security_logger.warning(message)
    else:
        security_logger.info(message)


def log_performance_metric(
    operation: str,
    duration_ms: float,
    success: bool = True,
    tenant_id: str | None = None,
    agent_id: str | None = None,
    additional_metrics: dict[str, Any] | None = None,
) -> None:
    """Log performance metrics with standardized format.

    Args:
        operation: Operation name
        duration_ms: Operation duration in milliseconds
        success: Whether operation succeeded
        tenant_id: Optional tenant ID
        agent_id: Optional agent ID
        additional_metrics: Additional metric data
    """
    context = {
        "operation": operation,
        "duration_ms": duration_ms,
        "success": success,
        "performance_metric": True,
    }

    if tenant_id:
        context["tenant_id"] = tenant_id
    if agent_id:
        context["agent_id"] = agent_id
    if additional_metrics:
        context.update(additional_metrics)

    perf_logger = logger.bind(**context)
    perf_logger.info(f"Performance: {operation} completed in {duration_ms:.2f}ms")


def log_audit_event(
    action: str,
    resource: str,
    tenant_id: str,
    agent_id: str | None = None,
    user_id: str | None = None,
    success: bool = True,
    additional_data: dict[str, Any] | None = None,
) -> None:
    """Log audit events with standardized format.

    Args:
        action: Action performed
        resource: Resource affected
        tenant_id: Tenant ID
        agent_id: Optional agent ID
        user_id: Optional user ID
        success: Whether action succeeded
        additional_data: Additional audit data
    """
    context = {
        "action": action,
        "resource": resource,
        "tenant_id": tenant_id,
        "success": success,
        "audit_event": True,
    }

    if agent_id:
        context["agent_id"] = agent_id
    if user_id:
        context["user_id"] = user_id
    if additional_data:
        context.update(additional_data)

    audit_logger = logger.bind(**context)
    status = "succeeded" if success else "failed"
    audit_logger.info(f"Audit: {action} on {resource} {status}")


class StructuredLogger:
    """Structured logger with context management."""

    def __init__(
        self,
        name: str,
        tenant_id: str | None = None,
        agent_id: str | None = None,
        correlation_id: str | None = None,
    ) -> None:
        """Initialize structured logger.

        Args:
            name: Logger name
            tenant_id: Optional tenant ID
            agent_id: Optional agent ID
            correlation_id: Optional correlation ID
        """
        self.name = name
        self._logger = logger.bind(logger_name=name)

        if tenant_id:
            self._logger = self._logger.bind(tenant_id=tenant_id)
        if agent_id:
            self._logger = self._logger.bind(agent_id=agent_id)
        if correlation_id:
            self._logger = self._logger.bind(correlation_id=correlation_id)

    def with_context(self, **context: str) -> StructuredLogger:
        """Create a new logger with additional context.

        Args:
            **context: Additional context to bind

        Returns:
            New StructuredLogger with context
        """
        new_logger = StructuredLogger(self.name)
        new_logger._logger = self._logger.bind(**context)
        return new_logger

    def debug(self, message: str, **context: str) -> None:
        """Log debug message."""
        self._logger.bind(**context).debug(message)

    def info(self, message: str, **context: str) -> None:
        """Log info message."""
        self._logger.bind(**context).info(message)

    def warning(self, message: str, **context: str) -> None:
        """Log warning message."""
        self._logger.bind(**context).warning(message)

    def error(self, message: str, exception: Exception | None = None, **context: str) -> None:
        """Log error message."""
        if exception:
            self._logger.bind(**context).opt(exception=True).error(message)
        else:
            self._logger.bind(**context).error(message)

    def critical(self, message: str, exception: Exception | None = None, **context: str) -> None:
        """Log critical message."""
        if exception:
            self._logger.bind(**context).opt(exception=True).critical(message)
        else:
            self._logger.bind(**context).critical(message)
