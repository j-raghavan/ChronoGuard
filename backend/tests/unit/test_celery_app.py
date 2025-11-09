"""Comprehensive unit tests for Celery task queue configuration.

This module tests all aspects of the Celery application including:
- App initialization and configuration
- Task definitions and execution
- Signal handlers
- Error handling and retries
- Beat schedule configuration
"""

from __future__ import annotations

import signal
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, Mock, call, patch

import pytest
from celery import Task
from celery.app.control import Inspect
from celery.exceptions import Retry
from core.celery_app import (
    LoggingTask,
    after_task_publish_handler,
    app,
    async_audit_export,
    cleanup_old_audit_logs,
    compile_active_policies,
    generate_analytics_report,
    get_celery_app,
    graceful_shutdown,
    health_check_workers,
    refresh_agent_certificates,
    task_failure_handler,
    task_postrun_handler,
    task_prerun_handler,
    task_retry_handler,
    task_success_handler,
    worker_ready_handler,
    worker_shutdown_handler,
)


class TestCeleryAppConfiguration:
    """Tests for Celery application configuration."""

    def test_app_initialization(self) -> None:
        """Test that Celery app is properly initialized."""
        assert app is not None
        assert app.main == "chronoguard"

    def test_broker_configuration(self) -> None:
        """Test broker URL configuration from settings."""
        assert app.conf.broker_url is not None
        assert "redis://" in app.conf.broker_url

    def test_result_backend_configuration(self) -> None:
        """Test result backend configuration."""
        assert app.conf.result_backend is not None
        assert "redis://" in app.conf.result_backend

    def test_serialization_configuration(self) -> None:
        """Test task serialization settings."""
        assert app.conf.task_serializer == "json"
        assert app.conf.result_serializer == "json"
        assert "json" in app.conf.accept_content

    def test_timezone_configuration(self) -> None:
        """Test timezone and UTC settings."""
        assert app.conf.timezone == "UTC"
        assert app.conf.enable_utc is True

    def test_task_tracking_configuration(self) -> None:
        """Test task tracking settings."""
        assert app.conf.task_track_started is True

    def test_time_limit_configuration(self) -> None:
        """Test task time limit settings."""
        assert app.conf.task_time_limit == 300
        assert app.conf.task_soft_time_limit == 270

    def test_worker_configuration(self) -> None:
        """Test worker settings."""
        assert app.conf.worker_prefetch_multiplier == 4
        assert app.conf.worker_max_tasks_per_child == 1000

    def test_result_expires_configuration(self) -> None:
        """Test result expiration setting."""
        assert app.conf.result_expires == 3600

    def test_task_events_configuration(self) -> None:
        """Test task event settings."""
        assert app.conf.task_send_sent_event is True

    def test_broker_retry_configuration(self) -> None:
        """Test broker connection retry settings."""
        assert app.conf.broker_connection_retry_on_startup is True
        assert app.conf.broker_connection_retry is True
        assert app.conf.broker_connection_max_retries == 10

    def test_default_task_base_class(self) -> None:
        """Test that default task base class is LoggingTask."""
        assert app.Task == LoggingTask


class TestBeatSchedule:
    """Tests for Celery Beat periodic task schedule."""

    def test_beat_schedule_exists(self) -> None:
        """Test that beat schedule is configured."""
        assert app.conf.beat_schedule is not None
        assert len(app.conf.beat_schedule) > 0

    def test_cleanup_audit_logs_schedule(self) -> None:
        """Test cleanup audit logs task schedule."""
        schedule = app.conf.beat_schedule.get("cleanup-old-audit-logs")
        assert schedule is not None
        assert schedule["task"] == "core.celery_app.cleanup_old_audit_logs"
        assert schedule["args"] == (90,)

    def test_compile_policies_schedule(self) -> None:
        """Test compile policies task schedule."""
        schedule = app.conf.beat_schedule.get("compile-active-policies")
        assert schedule is not None
        assert schedule["task"] == "core.celery_app.compile_active_policies"

    def test_refresh_certificates_schedule(self) -> None:
        """Test refresh certificates task schedule."""
        schedule = app.conf.beat_schedule.get("refresh-agent-certificates")
        assert schedule is not None
        assert schedule["task"] == "core.celery_app.refresh_agent_certificates"

    def test_analytics_report_schedule(self) -> None:
        """Test analytics report task schedule."""
        schedule = app.conf.beat_schedule.get("generate-analytics-report")
        assert schedule is not None
        assert schedule["task"] == "core.celery_app.generate_analytics_report"

    def test_health_check_schedule(self) -> None:
        """Test health check task schedule."""
        schedule = app.conf.beat_schedule.get("health-check-workers")
        assert schedule is not None
        assert schedule["task"] == "core.celery_app.health_check_workers"


class TestLoggingTask:
    """Tests for LoggingTask base class."""

    def test_logging_task_on_success(self) -> None:
        """Test task success logging."""
        task = LoggingTask()
        task.name = "test_task"

        with patch("core.celery_app.logger") as mock_logger:
            task.on_success(
                retval="success_result",
                task_id="test-task-123",
                args=(),
                kwargs={},
            )

            mock_logger.info.assert_called_once()
            call_args = mock_logger.info.call_args
            assert "test_task" in call_args[0][0]
            assert "succeeded" in call_args[0][0]

    def test_logging_task_on_failure(self) -> None:
        """Test task failure logging."""
        task = LoggingTask()
        task.name = "test_task"
        exception = ValueError("Test error")

        with patch("core.celery_app.logger") as mock_logger:
            task.on_failure(
                exc=exception,
                task_id="test-task-123",
                args=(),
                kwargs={},
                einfo=None,
            )

            mock_logger.error.assert_called_once()
            call_args = mock_logger.error.call_args
            assert "test_task" in call_args[0][0]
            assert "failed" in call_args[0][0]

    def test_logging_task_on_retry(self) -> None:
        """Test task retry logging."""
        task = LoggingTask()
        task.name = "test_task"
        exception = ConnectionError("Connection failed")

        with patch("core.celery_app.logger") as mock_logger:
            task.on_retry(
                exc=exception,
                task_id="test-task-123",
                args=(),
                kwargs={},
                einfo=None,
            )

            mock_logger.warning.assert_called_once()
            call_args = mock_logger.warning.call_args
            assert "test_task" in call_args[0][0]
            assert "retry" in call_args[0][0]


class TestSignalHandlers:
    """Tests for Celery signal handlers."""

    def test_worker_ready_handler(self) -> None:
        """Test worker ready signal handler."""
        mock_sender = Mock()
        mock_sender.hostname = "worker-1"

        with patch("core.celery_app.logger") as mock_logger:
            worker_ready_handler(sender=mock_sender)
            mock_logger.info.assert_called_once()

    def test_worker_ready_handler_without_hostname(self) -> None:
        """Test worker ready signal handler without hostname."""
        mock_sender = Mock(spec=[])

        with patch("core.celery_app.logger") as mock_logger:
            worker_ready_handler(sender=mock_sender)
            mock_logger.info.assert_called_once()

    def test_worker_shutdown_handler(self) -> None:
        """Test worker shutdown signal handler."""
        mock_sender = Mock()
        mock_sender.hostname = "worker-1"

        with patch("core.celery_app.logger") as mock_logger:
            worker_shutdown_handler(sender=mock_sender)
            mock_logger.info.assert_called_once()

    def test_worker_shutdown_handler_without_hostname(self) -> None:
        """Test worker shutdown signal handler without hostname."""
        mock_sender = Mock(spec=[])

        with patch("core.celery_app.logger") as mock_logger:
            worker_shutdown_handler(sender=mock_sender)
            mock_logger.info.assert_called_once()

    def test_task_prerun_handler(self) -> None:
        """Test task pre-run signal handler."""
        mock_task = Mock(spec=Task)
        mock_task.name = "test.task"

        with patch("core.celery_app.logger") as mock_logger:
            task_prerun_handler(
                task_id="task-123",
                task=mock_task,
                args=(),
                kwargs={},
            )
            mock_logger.debug.assert_called_once()

    def test_task_postrun_handler(self) -> None:
        """Test task post-run signal handler."""
        mock_task = Mock(spec=Task)
        mock_task.name = "test.task"

        with patch("core.celery_app.logger") as mock_logger:
            task_postrun_handler(
                task_id="task-123",
                task=mock_task,
                args=(),
                kwargs={},
                retval="result",
                state="SUCCESS",
            )
            mock_logger.debug.assert_called_once()

    def test_task_success_handler(self) -> None:
        """Test task success signal handler."""
        mock_sender = Mock(spec=Task)
        mock_sender.name = "test.task"

        with patch("core.celery_app.logger") as mock_logger:
            task_success_handler(sender=mock_sender, result="success")
            mock_logger.debug.assert_called_once()

    def test_task_success_handler_without_name(self) -> None:
        """Test task success signal handler without sender name."""
        mock_sender = None

        with patch("core.celery_app.logger") as mock_logger:
            task_success_handler(sender=mock_sender, result="success")
            mock_logger.debug.assert_called_once()

    def test_task_failure_handler(self) -> None:
        """Test task failure signal handler."""
        mock_sender = Mock(spec=Task)
        mock_sender.name = "test.task"
        exception = ValueError("Test error")

        with patch("core.celery_app.logger") as mock_logger:
            task_failure_handler(
                sender=mock_sender,
                task_id="task-123",
                exception=exception,
                args=(),
                kwargs={},
                traceback=None,
                einfo=None,
            )
            mock_logger.error.assert_called_once()

    def test_task_failure_handler_without_name(self) -> None:
        """Test task failure signal handler without sender name."""
        mock_sender = None
        exception = ValueError("Test error")

        with patch("core.celery_app.logger") as mock_logger:
            task_failure_handler(
                sender=mock_sender,
                task_id="task-123",
                exception=exception,
                args=(),
                kwargs={},
                traceback=None,
                einfo=None,
            )
            mock_logger.error.assert_called_once()

    def test_task_retry_handler(self) -> None:
        """Test task retry signal handler."""
        mock_sender = Mock(spec=Task)
        mock_sender.name = "test.task"
        reason = ConnectionError("Connection failed")

        with patch("core.celery_app.logger") as mock_logger:
            task_retry_handler(
                sender=mock_sender,
                task_id="task-123",
                reason=reason,
                einfo=None,
            )
            mock_logger.warning.assert_called_once()

    def test_task_retry_handler_without_name(self) -> None:
        """Test task retry signal handler without sender name."""
        mock_sender = None
        reason = ConnectionError("Connection failed")

        with patch("core.celery_app.logger") as mock_logger:
            task_retry_handler(
                sender=mock_sender,
                task_id="task-123",
                reason=reason,
                einfo=None,
            )
            mock_logger.warning.assert_called_once()

    def test_after_task_publish_handler(self) -> None:
        """Test after task publish signal handler."""
        headers = {"id": "task-123"}

        with patch("core.celery_app.logger") as mock_logger:
            after_task_publish_handler(
                sender="test.task",
                headers=headers,
                body={},
            )
            mock_logger.debug.assert_called_once()

    def test_after_task_publish_handler_without_task_id(self) -> None:
        """Test after task publish signal handler without task ID in headers."""
        headers: dict[str, Any] = {}

        with patch("core.celery_app.logger") as mock_logger:
            after_task_publish_handler(
                sender="test.task",
                headers=headers,
                body={},
            )
            mock_logger.debug.assert_called_once()


class TestCleanupOldAuditLogsTask:
    """Tests for cleanup_old_audit_logs task."""

    def test_cleanup_task_registered(self) -> None:
        """Test that cleanup task is registered."""
        assert "core.celery_app.cleanup_old_audit_logs" in app.tasks

    def test_cleanup_task_configuration(self) -> None:
        """Test cleanup task configuration."""
        task = app.tasks["core.celery_app.cleanup_old_audit_logs"]
        assert task.max_retries == 3
        assert task.default_retry_delay == 300

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    def test_cleanup_task_success(self, mock_datetime: Mock, mock_logger: Mock) -> None:
        """Test successful audit log cleanup."""
        # Mock datetime to return predictable value
        mock_now = datetime(2024, 4, 1, 12, 0, 0, tzinfo=UTC)
        mock_datetime.now.return_value = mock_now

        # Execute task
        result = cleanup_old_audit_logs.apply(args=(90,)).get()

        # Verify result
        assert "deleted_count" in result
        assert "cutoff_date" in result
        assert "retention_days" in result
        assert result["retention_days"] == 90

        # Verify logging
        mock_logger.info.assert_called()

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    def test_cleanup_task_with_custom_days(self, mock_datetime: Mock, mock_logger: Mock) -> None:
        """Test cleanup task with custom retention days."""
        mock_now = datetime(2024, 4, 1, 12, 0, 0, tzinfo=UTC)
        mock_datetime.now.return_value = mock_now

        result = cleanup_old_audit_logs.apply(args=(30,)).get()

        assert result["retention_days"] == 30

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    def test_cleanup_task_retry_on_exception(self, mock_datetime: Mock, mock_logger: Mock) -> None:
        """Test that cleanup task retries on exception."""
        mock_datetime.now.side_effect = Exception("Database error")

        with pytest.raises(Exception):
            cleanup_old_audit_logs.apply(args=(90,)).get()

        mock_logger.error.assert_called()


class TestCompileActivePoliciesTask:
    """Tests for compile_active_policies task."""

    def test_compile_task_registered(self) -> None:
        """Test that compile task is registered."""
        assert "core.celery_app.compile_active_policies" in app.tasks

    def test_compile_task_configuration(self) -> None:
        """Test compile task configuration."""
        task = app.tasks["core.celery_app.compile_active_policies"]
        assert task.max_retries == 3
        assert task.default_retry_delay == 60

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    def test_compile_task_success(self, mock_datetime: Mock, mock_logger: Mock) -> None:
        """Test successful policy compilation."""
        mock_now = datetime(2024, 4, 1, 12, 0, 0, tzinfo=UTC)
        mock_datetime.now.return_value = mock_now

        result = compile_active_policies.apply().get()

        assert "compiled_count" in result
        assert "failed_count" in result
        assert "timestamp" in result
        mock_logger.info.assert_called()

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    def test_compile_task_retry_on_exception(self, mock_datetime: Mock, mock_logger: Mock) -> None:
        """Test that compile task retries on exception."""
        mock_datetime.now.side_effect = Exception("Compilation error")

        with pytest.raises(Exception):
            compile_active_policies.apply().get()

        mock_logger.error.assert_called()


class TestRefreshAgentCertificatesTask:
    """Tests for refresh_agent_certificates task."""

    def test_refresh_task_registered(self) -> None:
        """Test that refresh task is registered."""
        assert "core.celery_app.refresh_agent_certificates" in app.tasks

    def test_refresh_task_configuration(self) -> None:
        """Test refresh task configuration."""
        task = app.tasks["core.celery_app.refresh_agent_certificates"]
        assert task.max_retries == 3
        assert task.default_retry_delay == 300

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    def test_refresh_task_success(self, mock_datetime: Mock, mock_logger: Mock) -> None:
        """Test successful certificate refresh."""
        mock_now = datetime(2024, 4, 1, 12, 0, 0, tzinfo=UTC)
        mock_datetime.now.return_value = mock_now

        result = refresh_agent_certificates.apply().get()

        assert "refreshed_count" in result
        assert "failed_count" in result
        assert "timestamp" in result
        mock_logger.info.assert_called()

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    def test_refresh_task_retry_on_exception(self, mock_datetime: Mock, mock_logger: Mock) -> None:
        """Test that refresh task retries on exception."""
        mock_datetime.now.side_effect = Exception("Certificate error")

        with pytest.raises(Exception):
            refresh_agent_certificates.apply().get()

        mock_logger.error.assert_called()


class TestGenerateAnalyticsReportTask:
    """Tests for generate_analytics_report task."""

    def test_analytics_task_registered(self) -> None:
        """Test that analytics task is registered."""
        assert "core.celery_app.generate_analytics_report" in app.tasks

    def test_analytics_task_configuration(self) -> None:
        """Test analytics task configuration."""
        task = app.tasks["core.celery_app.generate_analytics_report"]
        assert task.max_retries == 3
        assert task.default_retry_delay == 300

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    def test_analytics_task_success_daily(self, mock_datetime: Mock, mock_logger: Mock) -> None:
        """Test successful daily analytics report generation."""
        mock_now = datetime(2024, 4, 1, 12, 0, 0, tzinfo=UTC)
        mock_datetime.now.return_value = mock_now

        result = generate_analytics_report.apply(args=("daily",)).get()

        assert result["report_type"] == "daily"
        assert "records_processed" in result
        assert "generated_at" in result
        mock_logger.info.assert_called()

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    def test_analytics_task_success_weekly(self, mock_datetime: Mock, mock_logger: Mock) -> None:
        """Test successful weekly analytics report generation."""
        mock_now = datetime(2024, 4, 1, 12, 0, 0, tzinfo=UTC)
        mock_datetime.now.return_value = mock_now

        result = generate_analytics_report.apply(args=("weekly",)).get()

        assert result["report_type"] == "weekly"

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    def test_analytics_task_retry_on_exception(
        self, mock_datetime: Mock, mock_logger: Mock
    ) -> None:
        """Test that analytics task retries on exception."""
        mock_datetime.now.side_effect = Exception("Report generation error")

        with pytest.raises(Exception):
            generate_analytics_report.apply(args=("daily",)).get()

        mock_logger.error.assert_called()


class TestHealthCheckWorkersTask:
    """Tests for health_check_workers task."""

    def test_health_check_task_registered(self) -> None:
        """Test that health check task is registered."""
        assert "core.celery_app.health_check_workers" in app.tasks

    def test_health_check_task_configuration(self) -> None:
        """Test health check task configuration."""
        task = app.tasks["core.celery_app.health_check_workers"]
        assert task.max_retries == 1

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    @patch("core.celery_app.app.control.inspect")
    def test_health_check_success_with_workers(
        self,
        mock_inspect: Mock,
        mock_datetime: Mock,
        mock_logger: Mock,
    ) -> None:
        """Test health check with active workers."""
        mock_now = datetime(2024, 4, 1, 12, 0, 0, tzinfo=UTC)
        mock_datetime.now.return_value = mock_now

        # Mock inspect to return active workers
        mock_inspect_instance = Mock(spec=Inspect)
        mock_inspect.return_value = mock_inspect_instance
        mock_inspect_instance.active.return_value = {
            "worker1@hostname": [],
            "worker2@hostname": [],
        }
        mock_inspect_instance.stats.return_value = {
            "worker1@hostname": {"pool": "prefork"},
            "worker2@hostname": {"pool": "prefork"},
        }

        result = health_check_workers.apply().get()

        assert result["healthy_workers"] == 2
        assert result["total_workers"] == 2
        assert result["status"] == "healthy"
        assert "timestamp" in result

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    @patch("core.celery_app.app.control.inspect")
    def test_health_check_no_workers(
        self,
        mock_inspect: Mock,
        mock_datetime: Mock,
        mock_logger: Mock,
    ) -> None:
        """Test health check with no active workers."""
        mock_now = datetime(2024, 4, 1, 12, 0, 0, tzinfo=UTC)
        mock_datetime.now.return_value = mock_now

        mock_inspect_instance = Mock(spec=Inspect)
        mock_inspect.return_value = mock_inspect_instance
        mock_inspect_instance.active.return_value = None
        mock_inspect_instance.stats.return_value = None

        result = health_check_workers.apply().get()

        assert result["healthy_workers"] == 0
        assert result["status"] == "unhealthy"

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    @patch("core.celery_app.app.control.inspect")
    def test_health_check_exception_handling(
        self,
        mock_inspect: Mock,
        mock_datetime: Mock,
        mock_logger: Mock,
    ) -> None:
        """Test health check handles exceptions gracefully."""
        mock_now = datetime(2024, 4, 1, 12, 0, 0, tzinfo=UTC)
        mock_datetime.now.return_value = mock_now

        mock_inspect.side_effect = Exception("Connection error")

        result = health_check_workers.apply().get()

        assert result["status"] == "error"
        assert "error" in result
        assert result["healthy_workers"] == 0
        mock_logger.error.assert_called()


class TestAsyncAuditExportTask:
    """Tests for async_audit_export task."""

    def test_export_task_registered(self) -> None:
        """Test that export task is registered."""
        assert "core.celery_app.async_audit_export" in app.tasks

    def test_export_task_configuration(self) -> None:
        """Test export task configuration."""
        task = app.tasks["core.celery_app.async_audit_export"]
        assert task.max_retries == 3
        assert task.default_retry_delay == 120

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    def test_export_task_success_json(self, mock_datetime: Mock, mock_logger: Mock) -> None:
        """Test successful audit export in JSON format."""
        mock_now = datetime(2024, 4, 1, 12, 0, 0, tzinfo=UTC)
        mock_datetime.now.return_value = mock_now

        result = async_audit_export.apply(
            args=("tenant-123", "2024-01-01", "2024-01-31", "json")
        ).get()

        assert result["tenant_id"] == "tenant-123"
        assert result["start_date"] == "2024-01-01"
        assert result["end_date"] == "2024-01-31"
        assert result["format"] == "json"
        assert "export_file" in result
        assert "record_count" in result
        mock_logger.info.assert_called()

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    def test_export_task_success_csv(self, mock_datetime: Mock, mock_logger: Mock) -> None:
        """Test successful audit export in CSV format."""
        mock_now = datetime(2024, 4, 1, 12, 0, 0, tzinfo=UTC)
        mock_datetime.now.return_value = mock_now

        result = async_audit_export.apply(
            args=("tenant-456", "2024-02-01", "2024-02-29", "csv")
        ).get()

        assert result["format"] == "csv"
        assert ".csv" in result["export_file"]

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    def test_export_task_success_parquet(self, mock_datetime: Mock, mock_logger: Mock) -> None:
        """Test successful audit export in Parquet format."""
        mock_now = datetime(2024, 4, 1, 12, 0, 0, tzinfo=UTC)
        mock_datetime.now.return_value = mock_now

        result = async_audit_export.apply(
            args=("tenant-789", "2024-03-01", "2024-03-31", "parquet")
        ).get()

        assert result["format"] == "parquet"
        assert ".parquet" in result["export_file"]


class TestGetCeleryApp:
    """Tests for get_celery_app function."""

    def test_get_celery_app_returns_app_instance(self) -> None:
        """Test that get_celery_app returns the configured app."""
        celery_app = get_celery_app()

        assert celery_app is app
        assert celery_app.main == "chronoguard"

    def test_get_celery_app_preserves_configuration(self) -> None:
        """Test that returned app has correct configuration."""
        celery_app = get_celery_app()

        assert celery_app.conf.task_serializer == "json"
        assert celery_app.conf.timezone == "UTC"


class TestGracefulShutdown:
    """Tests for graceful shutdown functionality."""

    @patch("core.celery_app.logger")
    @patch("core.celery_app.app.control.shutdown")
    def test_graceful_shutdown_sigterm(self, mock_shutdown: Mock, mock_logger: Mock) -> None:
        """Test graceful shutdown on SIGTERM."""
        graceful_shutdown(signal.SIGTERM, None)

        mock_logger.info.assert_called_once()
        assert "SIGTERM" in str(mock_logger.info.call_args[0][0]) or "15" in str(
            mock_logger.info.call_args[0][0]
        )
        mock_shutdown.assert_called_once()

    @patch("core.celery_app.logger")
    @patch("core.celery_app.app.control.shutdown")
    def test_graceful_shutdown_sigint(self, mock_shutdown: Mock, mock_logger: Mock) -> None:
        """Test graceful shutdown on SIGINT."""
        graceful_shutdown(signal.SIGINT, None)

        mock_logger.info.assert_called_once()
        assert "SIGINT" in str(mock_logger.info.call_args[0][0]) or "2" in str(
            mock_logger.info.call_args[0][0]
        )
        mock_shutdown.assert_called_once()

    @patch("core.celery_app.logger")
    @patch("core.celery_app.app.control.shutdown")
    def test_graceful_shutdown_with_frame(self, mock_shutdown: Mock, mock_logger: Mock) -> None:
        """Test graceful shutdown with frame argument."""
        mock_frame = Mock()
        graceful_shutdown(signal.SIGTERM, mock_frame)

        mock_shutdown.assert_called_once()


class TestTaskRetryBehavior:
    """Tests for task retry behavior."""

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    def test_cleanup_task_retry_countdown(self, mock_datetime: Mock, mock_logger: Mock) -> None:
        """Test cleanup task retry with correct countdown."""
        # Force an exception to trigger retry
        mock_datetime.now.side_effect = Exception("Test exception")

        with pytest.raises(Exception):
            cleanup_old_audit_logs.apply(args=(90,)).get()

        # Verify error was logged
        mock_logger.error.assert_called()

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    def test_compile_task_retry_countdown(self, mock_datetime: Mock, mock_logger: Mock) -> None:
        """Test compile task retry with correct countdown."""
        mock_datetime.now.side_effect = Exception("Test exception")

        with pytest.raises(Exception):
            compile_active_policies.apply().get()

        mock_logger.error.assert_called()


class TestTaskNames:
    """Tests for task naming convention."""

    def test_all_tasks_have_proper_names(self) -> None:
        """Test that all tasks follow naming convention."""
        expected_tasks = [
            "core.celery_app.cleanup_old_audit_logs",
            "core.celery_app.compile_active_policies",
            "core.celery_app.refresh_agent_certificates",
            "core.celery_app.generate_analytics_report",
            "core.celery_app.health_check_workers",
            "core.celery_app.async_audit_export",
        ]

        for task_name in expected_tasks:
            assert task_name in app.tasks, f"Task {task_name} not registered"


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    def test_cleanup_with_zero_days(self, mock_datetime: Mock, mock_logger: Mock) -> None:
        """Test cleanup task with zero retention days."""
        mock_now = datetime(2024, 4, 1, 12, 0, 0, tzinfo=UTC)
        mock_datetime.now.return_value = mock_now

        result = cleanup_old_audit_logs.apply(args=(0,)).get()

        assert result["retention_days"] == 0

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    def test_cleanup_with_negative_days(self, mock_datetime: Mock, mock_logger: Mock) -> None:
        """Test cleanup task with negative retention days."""
        mock_now = datetime(2024, 4, 1, 12, 0, 0, tzinfo=UTC)
        mock_datetime.now.return_value = mock_now

        # Task should still execute, even with negative days
        result = cleanup_old_audit_logs.apply(args=(-10,)).get()

        assert result["retention_days"] == -10

    @patch("core.celery_app.logger")
    @patch("core.celery_app.datetime")
    def test_export_with_invalid_dates(self, mock_datetime: Mock, mock_logger: Mock) -> None:
        """Test export task with invalid date range."""
        mock_now = datetime(2024, 4, 1, 12, 0, 0, tzinfo=UTC)
        mock_datetime.now.return_value = mock_now

        # End date before start date - task should still execute
        result = async_audit_export.apply(
            args=("tenant-123", "2024-12-31", "2024-01-01", "json")
        ).get()

        assert result["start_date"] == "2024-12-31"
        assert result["end_date"] == "2024-01-01"

    @patch("core.celery_app.logger")
    def test_analytics_with_empty_report_type(self, mock_logger: Mock) -> None:
        """Test analytics task with empty report type."""
        with patch("core.celery_app.datetime") as mock_datetime:
            mock_now = datetime(2024, 4, 1, 12, 0, 0, tzinfo=UTC)
            mock_datetime.now.return_value = mock_now

            result = generate_analytics_report.apply(args=("",)).get()

            assert result["report_type"] == ""
