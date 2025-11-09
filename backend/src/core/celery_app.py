"""Celery task queue configuration for ChronoGuard.

This module provides asynchronous task queue management using Celery with Redis
as the broker and result backend. It includes task definitions for background
operations like audit log cleanup, policy compilation, and periodic maintenance.

Example:
    Start a Celery worker:

    >>> celery -A core.celery_app worker --loglevel=info

    Start beat scheduler for periodic tasks:

    >>> celery -A core.celery_app beat --loglevel=info

    Execute a task:

    >>> from core.celery_app import cleanup_old_audit_logs
    >>> result = cleanup_old_audit_logs.delay(days=90)
    >>> result.get()  # Wait for result
"""

from __future__ import annotations

import signal
from datetime import UTC, datetime, timedelta
from typing import Any

from celery import Celery, Task, signals
from celery.schedules import crontab
from celery.signals import (
    after_task_publish,
    task_failure,
    task_postrun,
    task_prerun,
    task_retry,
    task_success,
)
from core.config import get_settings
from loguru import logger

# Initialize Celery app
settings = get_settings()
celery_settings = settings.celery

app = Celery(
    "chronoguard",
    broker=celery_settings.broker_url,
    backend=celery_settings.result_backend,
)

# Configure Celery from settings
app.conf.update(
    # Serialization
    task_serializer=celery_settings.task_serializer,
    result_serializer=celery_settings.result_serializer,
    accept_content=celery_settings.accept_content,
    # Timezone
    timezone=celery_settings.timezone,
    enable_utc=celery_settings.enable_utc,
    # Task tracking
    task_track_started=celery_settings.task_track_started,
    # Time limits
    task_time_limit=celery_settings.task_time_limit,
    task_soft_time_limit=celery_settings.task_soft_time_limit,
    # Worker
    worker_prefetch_multiplier=celery_settings.worker_prefetch_multiplier,
    worker_max_tasks_per_child=celery_settings.worker_max_tasks_per_child,
    # Result backend
    result_expires=3600,  # Results expire after 1 hour
    result_backend_transport_options={"master_name": "chronoguard"},
    # Task events
    task_send_sent_event=True,
    # Broker settings
    broker_connection_retry_on_startup=True,
    broker_connection_retry=True,
    broker_connection_max_retries=10,
)

# Beat schedule for periodic tasks
app.conf.beat_schedule = {
    "cleanup-old-audit-logs": {
        "task": "core.celery_app.cleanup_old_audit_logs",
        "schedule": crontab(hour=2, minute=0),  # Daily at 2 AM
        "args": (90,),  # Clean logs older than 90 days
    },
    "compile-active-policies": {
        "task": "core.celery_app.compile_active_policies",
        "schedule": crontab(minute="*/30"),  # Every 30 minutes
    },
    "refresh-agent-certificates": {
        "task": "core.celery_app.refresh_agent_certificates",
        "schedule": crontab(hour="*/6", minute=0),  # Every 6 hours
    },
    "generate-analytics-report": {
        "task": "core.celery_app.generate_analytics_report",
        "schedule": crontab(hour=1, minute=0),  # Daily at 1 AM
    },
    "health-check-workers": {
        "task": "core.celery_app.health_check_workers",
        "schedule": crontab(minute="*/5"),  # Every 5 minutes
    },
}


class LoggingTask(Task):
    """Base task class with logging support."""

    def on_success(
        self, retval: Any, task_id: str, args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> None:
        """Log task success.

        Args:
            retval: Task return value
            task_id: Unique task ID
            args: Task positional arguments
            kwargs: Task keyword arguments
        """
        logger.info(
            f"Task {self.name} [{task_id}] succeeded",
            task_name=self.name,
            task_id=task_id,
            result=str(retval),
        )

    def on_failure(
        self,
        exc: Exception,
        task_id: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        einfo: Any,
    ) -> None:
        """Log task failure.

        Args:
            exc: Exception raised
            task_id: Unique task ID
            args: Task positional arguments
            kwargs: Task keyword arguments
            einfo: Exception info
        """
        logger.error(
            f"Task {self.name} [{task_id}] failed: {exc}",
            task_name=self.name,
            task_id=task_id,
            exception=str(exc),
            exc_info=True,
        )

    def on_retry(
        self,
        exc: Exception,
        task_id: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        einfo: Any,
    ) -> None:
        """Log task retry.

        Args:
            exc: Exception that caused retry
            task_id: Unique task ID
            args: Task positional arguments
            kwargs: Task keyword arguments
            einfo: Exception info
        """
        logger.warning(
            f"Task {self.name} [{task_id}] retry due to: {exc}",
            task_name=self.name,
            task_id=task_id,
            exception=str(exc),
        )


# Set default task base class
app.Task = LoggingTask


# Signal handlers for task lifecycle events
@signals.worker_ready.connect
def worker_ready_handler(sender: Any, **kwargs: Any) -> None:
    """Handle worker ready signal.

    Args:
        sender: Signal sender
        **kwargs: Additional signal arguments
    """
    logger.info(
        "Celery worker ready",
        worker_id=sender.hostname if hasattr(sender, "hostname") else "unknown",
    )


@signals.worker_shutdown.connect
def worker_shutdown_handler(sender: Any, **kwargs: Any) -> None:
    """Handle worker shutdown signal.

    Args:
        sender: Signal sender
        **kwargs: Additional signal arguments
    """
    logger.info(
        "Celery worker shutting down",
        worker_id=sender.hostname if hasattr(sender, "hostname") else "unknown",
    )


@task_prerun.connect
def task_prerun_handler(
    task_id: str, task: Task, args: tuple[Any, ...], kwargs: dict[str, Any], **extra: Any
) -> None:
    """Handle task pre-run signal.

    Args:
        task_id: Unique task ID
        task: Task instance
        args: Task positional arguments
        kwargs: Task keyword arguments
        **extra: Additional signal arguments
    """
    logger.debug(f"Task {task.name} [{task_id}] starting", task_name=task.name, task_id=task_id)


@task_postrun.connect
def task_postrun_handler(
    task_id: str,
    task: Task,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    retval: Any,
    state: str,
    **extra: Any,
) -> None:
    """Handle task post-run signal.

    Args:
        task_id: Unique task ID
        task: Task instance
        args: Task positional arguments
        kwargs: Task keyword arguments
        retval: Task return value
        state: Task state
        **extra: Additional signal arguments
    """
    logger.debug(
        f"Task {task.name} [{task_id}] finished with state: {state}",
        task_name=task.name,
        task_id=task_id,
        state=state,
    )


@task_success.connect
def task_success_handler(sender: Task, result: Any, **kwargs: Any) -> None:
    """Handle task success signal.

    Args:
        sender: Task instance
        result: Task result
        **kwargs: Additional signal arguments
    """
    task_name = sender.name if sender else "unknown"
    logger.debug(
        f"Task {task_name} completed successfully", task_name=task_name, result=str(result)
    )


@task_failure.connect
def task_failure_handler(
    sender: Task,
    task_id: str,
    exception: Exception,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    traceback: Any,
    einfo: Any,
    **extra: Any,
) -> None:
    """Handle task failure signal.

    Args:
        sender: Task instance
        task_id: Unique task ID
        exception: Exception raised
        args: Task positional arguments
        kwargs: Task keyword arguments
        traceback: Exception traceback
        einfo: Exception info
        **extra: Additional signal arguments
    """
    task_name = sender.name if sender else "unknown"
    logger.error(
        f"Task {task_name} [{task_id}] failed with exception: {exception}",
        task_name=task_name,
        task_id=task_id,
        exception=str(exception),
        exc_info=True,
    )


@task_retry.connect
def task_retry_handler(
    sender: Task,
    task_id: str,
    reason: Exception,
    einfo: Any,
    **kwargs: Any,
) -> None:
    """Handle task retry signal.

    Args:
        sender: Task instance
        task_id: Unique task ID
        reason: Exception that triggered retry
        einfo: Exception info
        **kwargs: Additional signal arguments
    """
    task_name = sender.name if sender else "unknown"
    logger.warning(
        f"Task {task_name} [{task_id}] retrying due to: {reason}",
        task_name=task_name,
        task_id=task_id,
        reason=str(reason),
    )


@after_task_publish.connect
def after_task_publish_handler(
    sender: str, headers: dict[str, Any], body: Any, **kwargs: Any
) -> None:
    """Handle after task publish signal.

    Args:
        sender: Task name
        headers: Task message headers
        body: Task message body
        **kwargs: Additional signal arguments
    """
    task_id = headers.get("id", "unknown")
    logger.debug(f"Task {sender} [{task_id}] published to queue", task_name=sender, task_id=task_id)


# Task definitions
@app.task(
    bind=True, name="core.celery_app.cleanup_old_audit_logs", max_retries=3, default_retry_delay=300
)
def cleanup_old_audit_logs(self: Task, days: int = 90) -> dict[str, Any]:
    """Clean up audit logs older than specified days.

    Args:
        self: Task instance
        days: Number of days to retain logs

    Returns:
        Dictionary with cleanup statistics

    Raises:
        Exception: If cleanup fails after retries

    Example:
        >>> result = cleanup_old_audit_logs.delay(90)
        >>> result.get()
        {'deleted_count': 1000, 'cutoff_date': '2024-01-01T00:00:00'}
    """
    try:
        cutoff_date = datetime.now(UTC) - timedelta(days=days)
        logger.info(f"Starting audit log cleanup for logs older than {cutoff_date}")

        # Placeholder for actual cleanup logic
        deleted_count = 0  # Would be actual deletion count

        return {
            "deleted_count": deleted_count,
            "cutoff_date": cutoff_date.isoformat(),
            "retention_days": days,
        }

    except Exception as exc:
        logger.error(f"Audit log cleanup failed: {exc}", exc_info=True)
        raise self.retry(exc=exc, countdown=300) from exc


@app.task(
    bind=True, name="core.celery_app.compile_active_policies", max_retries=3, default_retry_delay=60
)
def compile_active_policies(self: Task) -> dict[str, Any]:
    """Compile all active policies to OPA format.

    Args:
        self: Task instance

    Returns:
        Dictionary with compilation statistics

    Raises:
        Exception: If compilation fails after retries

    Example:
        >>> result = compile_active_policies.delay()
        >>> result.get()
        {'compiled_count': 50, 'failed_count': 0}
    """
    try:
        logger.info("Starting policy compilation for all active policies")

        # Placeholder for actual compilation logic
        compiled_count = 0
        failed_count = 0

        return {
            "compiled_count": compiled_count,
            "failed_count": failed_count,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    except Exception as exc:
        logger.error(f"Policy compilation failed: {exc}", exc_info=True)
        raise self.retry(exc=exc, countdown=60) from exc


@app.task(
    bind=True,
    name="core.celery_app.refresh_agent_certificates",
    max_retries=3,
    default_retry_delay=300,
)
def refresh_agent_certificates(self: Task) -> dict[str, Any]:
    """Refresh expiring agent certificates.

    Args:
        self: Task instance

    Returns:
        Dictionary with refresh statistics

    Raises:
        Exception: If refresh fails after retries

    Example:
        >>> result = refresh_agent_certificates.delay()
        >>> result.get()
        {'refreshed_count': 10, 'failed_count': 0}
    """
    try:
        logger.info("Starting agent certificate refresh")

        # Placeholder for actual certificate refresh logic
        refreshed_count = 0
        failed_count = 0

        return {
            "refreshed_count": refreshed_count,
            "failed_count": failed_count,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    except Exception as exc:
        logger.error(f"Certificate refresh failed: {exc}", exc_info=True)
        raise self.retry(exc=exc, countdown=300) from exc


@app.task(
    bind=True,
    name="core.celery_app.generate_analytics_report",
    max_retries=3,
    default_retry_delay=300,
)
def generate_analytics_report(self: Task, report_type: str = "daily") -> dict[str, Any]:
    """Generate analytics report for temporal access patterns.

    Args:
        self: Task instance
        report_type: Type of report (daily, weekly, monthly)

    Returns:
        Dictionary with report metadata

    Raises:
        Exception: If report generation fails after retries

    Example:
        >>> result = generate_analytics_report.delay("daily")
        >>> result.get()
        {'report_type': 'daily', 'records_processed': 10000}
    """
    try:
        logger.info(f"Starting {report_type} analytics report generation")

        # Placeholder for actual report generation logic
        records_processed = 0

        return {
            "report_type": report_type,
            "records_processed": records_processed,
            "generated_at": datetime.now(UTC).isoformat(),
        }

    except Exception as exc:
        logger.error(f"Analytics report generation failed: {exc}", exc_info=True)
        raise self.retry(exc=exc, countdown=300) from exc


@app.task(bind=True, name="core.celery_app.health_check_workers", max_retries=1)
def health_check_workers(self: Task) -> dict[str, Any]:
    """Perform health check on all workers.

    Args:
        self: Task instance

    Returns:
        Dictionary with health check results

    Example:
        >>> result = health_check_workers.delay()
        >>> result.get()
        {'healthy_workers': 3, 'total_workers': 3, 'status': 'healthy'}
    """
    try:
        logger.debug("Performing worker health check")

        # Get active workers
        inspect = app.control.inspect()
        active_workers = inspect.active() or {}
        stats = inspect.stats() or {}

        healthy_workers = len(list(stats))
        total_workers = len(active_workers.keys()) if active_workers else 0

        return {
            "healthy_workers": healthy_workers,
            "total_workers": total_workers,
            "status": "healthy" if healthy_workers > 0 else "unhealthy",
            "timestamp": datetime.now(UTC).isoformat(),
        }

    except Exception as exc:
        logger.error(f"Worker health check failed: {exc}", exc_info=True)
        return {
            "healthy_workers": 0,
            "total_workers": 0,
            "status": "error",
            "error": str(exc),
            "timestamp": datetime.now(UTC).isoformat(),
        }


@app.task(name="core.celery_app.async_audit_export", max_retries=3, default_retry_delay=120)
def async_audit_export(
    tenant_id: str,
    start_date: str,
    end_date: str,
    format_type: str = "json",
) -> dict[str, Any]:
    """Export audit logs asynchronously.

    Args:
        tenant_id: Tenant ID for filtering
        start_date: Start date in ISO format
        end_date: End date in ISO format
        format_type: Export format (json, csv, parquet)

    Returns:
        Dictionary with export metadata

    Example:
        >>> result = async_audit_export.delay("tenant-123", "2024-01-01", "2024-01-31")
        >>> result.get()
        {'export_file': '/path/to/export.json', 'record_count': 5000}
    """
    logger.info(
        f"Starting async audit export for tenant {tenant_id}",
        tenant_id=tenant_id,
        start_date=start_date,
        end_date=end_date,
        format_type=format_type,
    )

    # Placeholder for actual export logic
    record_count = 0
    # Note: In production, use a secure temp directory
    export_file = (
        f"/tmp/audit_export_{tenant_id}_{start_date}_{end_date}.{format_type}"  # noqa: S108
    )

    return {
        "export_file": export_file,
        "record_count": record_count,
        "tenant_id": tenant_id,
        "start_date": start_date,
        "end_date": end_date,
        "format": format_type,
        "timestamp": datetime.now(UTC).isoformat(),
    }


def get_celery_app() -> Celery:
    """Get the configured Celery application instance.

    Returns:
        Configured Celery app instance

    Example:
        >>> celery_app = get_celery_app()
        >>> celery_app.conf.broker_url
        'redis://localhost:6379/1'
    """
    return app


def graceful_shutdown(signum: int, frame: Any) -> None:
    """Handle graceful shutdown of Celery workers.

    Args:
        signum: Signal number
        frame: Current stack frame
    """
    logger.info(f"Received signal {signum}, initiating graceful shutdown")
    app.control.shutdown()


# Register signal handlers for graceful shutdown
signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)
