"""Comprehensive tests for OPA decision logger."""

import asyncio
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest
from infrastructure.opa.decision_logger import (
    DecisionLogger,
    DecisionMetadata,
    create_decision_metadata,
)


class TestDecisionMetadata:
    """Test suite for DecisionMetadata."""

    @pytest.fixture
    def sample_timestamp(self) -> datetime:
        """Sample timestamp for testing."""
        return datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)

    @pytest.fixture
    def sample_agent_id(self) -> UUID:
        """Sample agent ID for testing."""
        return uuid4()

    @pytest.fixture
    def sample_tenant_id(self) -> UUID:
        """Sample tenant ID for testing."""
        return uuid4()

    def test_init_minimal(self, sample_timestamp: datetime, sample_agent_id: UUID) -> None:
        """Test DecisionMetadata initialization with minimal args."""
        metadata = DecisionMetadata(
            timestamp=sample_timestamp,
            agent_id=sample_agent_id,
            domain="example.com",
            decision=True,
            latency_ms=5.2,
        )

        assert metadata.timestamp == sample_timestamp
        assert metadata.agent_id == str(sample_agent_id)
        assert metadata.domain == "example.com"
        assert metadata.decision is True
        assert metadata.latency_ms == 5.2
        assert metadata.tenant_id is None
        assert metadata.policy_id is None
        assert metadata.reason is None
        assert metadata.request_id is None
        assert metadata.additional_context == {}

    def test_init_full(
        self,
        sample_timestamp: datetime,
        sample_agent_id: UUID,
        sample_tenant_id: UUID,
    ) -> None:
        """Test DecisionMetadata initialization with all args."""
        policy_id = uuid4()
        additional_context = {"key": "value", "count": 42}

        metadata = DecisionMetadata(
            timestamp=sample_timestamp,
            agent_id=sample_agent_id,
            domain="example.com",
            decision=False,
            latency_ms=10.5,
            tenant_id=sample_tenant_id,
            policy_id=policy_id,
            reason="Policy violation",
            request_id="req-123",
            additional_context=additional_context,
        )

        assert metadata.timestamp == sample_timestamp
        assert metadata.agent_id == str(sample_agent_id)
        assert metadata.domain == "example.com"
        assert metadata.decision is False
        assert metadata.latency_ms == 10.5
        assert metadata.tenant_id == str(sample_tenant_id)
        assert metadata.policy_id == str(policy_id)
        assert metadata.reason == "Policy violation"
        assert metadata.request_id == "req-123"
        assert metadata.additional_context == additional_context

    def test_init_with_string_ids(self, sample_timestamp: datetime) -> None:
        """Test DecisionMetadata accepts string IDs."""
        metadata = DecisionMetadata(
            timestamp=sample_timestamp,
            agent_id="agent-123",
            domain="example.com",
            decision=True,
            latency_ms=5.2,
            tenant_id="tenant-456",
            policy_id="policy-789",
        )

        assert metadata.agent_id == "agent-123"
        assert metadata.tenant_id == "tenant-456"
        assert metadata.policy_id == "policy-789"

    def test_to_dict_minimal(self, sample_timestamp: datetime, sample_agent_id: UUID) -> None:
        """Test to_dict with minimal metadata."""
        metadata = DecisionMetadata(
            timestamp=sample_timestamp,
            agent_id=sample_agent_id,
            domain="example.com",
            decision=True,
            latency_ms=5.234,
        )

        result = metadata.to_dict()

        assert result["timestamp"] == sample_timestamp.isoformat()
        assert result["agent_id"] == str(sample_agent_id)
        assert result["domain"] == "example.com"
        assert result["decision"] == "allow"
        assert result["latency_ms"] == 5.23  # Rounded to 2 decimals
        assert "tenant_id" not in result
        assert "policy_id" not in result
        assert "reason" not in result
        assert "request_id" not in result

    def test_to_dict_full(
        self,
        sample_timestamp: datetime,
        sample_agent_id: UUID,
        sample_tenant_id: UUID,
    ) -> None:
        """Test to_dict with full metadata."""
        policy_id = uuid4()
        additional_context = {"key": "value"}

        metadata = DecisionMetadata(
            timestamp=sample_timestamp,
            agent_id=sample_agent_id,
            domain="example.com",
            decision=False,
            latency_ms=10.567,
            tenant_id=sample_tenant_id,
            policy_id=policy_id,
            reason="Policy violation",
            request_id="req-123",
            additional_context=additional_context,
        )

        result = metadata.to_dict()

        assert result["timestamp"] == sample_timestamp.isoformat()
        assert result["agent_id"] == str(sample_agent_id)
        assert result["domain"] == "example.com"
        assert result["decision"] == "deny"
        assert result["latency_ms"] == 10.57
        assert result["tenant_id"] == str(sample_tenant_id)
        assert result["policy_id"] == str(policy_id)
        assert result["reason"] == "Policy violation"
        assert result["request_id"] == "req-123"
        assert result["context"] == additional_context

    def test_to_dict_decision_allow(
        self, sample_timestamp: datetime, sample_agent_id: UUID
    ) -> None:
        """Test to_dict converts True decision to 'allow'."""
        metadata = DecisionMetadata(
            timestamp=sample_timestamp,
            agent_id=sample_agent_id,
            domain="example.com",
            decision=True,
            latency_ms=5.2,
        )

        result = metadata.to_dict()
        assert result["decision"] == "allow"

    def test_to_dict_decision_deny(self, sample_timestamp: datetime, sample_agent_id: UUID) -> None:
        """Test to_dict converts False decision to 'deny'."""
        metadata = DecisionMetadata(
            timestamp=sample_timestamp,
            agent_id=sample_agent_id,
            domain="example.com",
            decision=False,
            latency_ms=5.2,
        )

        result = metadata.to_dict()
        assert result["decision"] == "deny"


class TestDecisionLogger:
    """Test suite for DecisionLogger."""

    @pytest.fixture
    def logger(self) -> DecisionLogger:
        """Create decision logger instance."""
        return DecisionLogger(
            logger_name="test.logger",
            enable_async_logging=False,  # Disable async for simpler testing
            batch_size=5,
            batch_timeout_seconds=1.0,
        )

    @pytest.fixture
    def async_logger(self) -> DecisionLogger:
        """Create decision logger with async logging enabled."""
        return DecisionLogger(
            logger_name="test.async.logger",
            enable_async_logging=True,
            batch_size=5,
            batch_timeout_seconds=0.5,
        )

    @pytest.fixture
    def sample_metadata(self) -> DecisionMetadata:
        """Create sample decision metadata."""
        return DecisionMetadata(
            timestamp=datetime.now(UTC),
            agent_id=uuid4(),
            domain="example.com",
            decision=True,
            latency_ms=5.2,
        )

    def test_init_defaults(self) -> None:
        """Test DecisionLogger initialization with defaults."""
        logger = DecisionLogger()

        assert logger._logger is not None
        assert logger.enable_async_logging is True
        assert logger.batch_size == 100
        assert logger.batch_timeout_seconds == 5.0
        assert logger._batch == []
        assert logger._shutdown is False

    def test_init_custom(self) -> None:
        """Test DecisionLogger initialization with custom values."""
        logger = DecisionLogger(
            logger_name="custom.logger",
            enable_async_logging=False,
            batch_size=50,
            batch_timeout_seconds=2.0,
        )

        assert logger.enable_async_logging is False
        assert logger.batch_size == 50
        assert logger.batch_timeout_seconds == 2.0

    @pytest.mark.asyncio
    async def test_log_decision_sync_allow(
        self,
        logger: DecisionLogger,
        sample_metadata: DecisionMetadata,
    ) -> None:
        """Test synchronous logging of allow decision."""
        sample_metadata.decision = True

        with patch.object(logger._logger, "info") as mock_info:
            await logger.log_decision(sample_metadata)

            mock_info.assert_called_once()
            call_args = mock_info.call_args
            assert "ALLOW" in call_args[0][0]
            assert "example.com" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_log_decision_sync_deny(
        self,
        logger: DecisionLogger,
        sample_metadata: DecisionMetadata,
    ) -> None:
        """Test synchronous logging of deny decision."""
        sample_metadata.decision = False

        with patch.object(logger._logger, "warning") as mock_warning:
            await logger.log_decision(sample_metadata)

            mock_warning.assert_called_once()
            call_args = mock_warning.call_args
            assert "DENY" in call_args[0][0]
            assert "example.com" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_log_decision_async_batching(self, async_logger: DecisionLogger) -> None:
        """Test async logging adds to batch."""
        metadata = DecisionMetadata(
            timestamp=datetime.now(UTC),
            agent_id=uuid4(),
            domain="example.com",
            decision=True,
            latency_ms=5.2,
        )

        await async_logger.log_decision(metadata)

        assert len(async_logger._batch) == 1
        assert async_logger._batch[0] == metadata

        await async_logger.shutdown()

    @pytest.mark.asyncio
    async def test_log_decision_async_auto_flush(self, async_logger: DecisionLogger) -> None:
        """Test async logging auto-flushes when batch is full."""
        async_logger.batch_size = 3

        with patch.object(async_logger._logger, "info"):
            # Add 3 decisions to trigger auto-flush
            for _ in range(3):
                metadata = DecisionMetadata(
                    timestamp=datetime.now(UTC),
                    agent_id=uuid4(),
                    domain="example.com",
                    decision=True,
                    latency_ms=5.2,
                )
                await async_logger.log_decision(metadata)

            # Batch should be empty after auto-flush
            assert len(async_logger._batch) == 0

        await async_logger.shutdown()

    @pytest.mark.asyncio
    async def test_log_batch_sync(self, logger: DecisionLogger) -> None:
        """Test synchronous batch logging."""
        decisions = [
            DecisionMetadata(
                timestamp=datetime.now(UTC),
                agent_id=uuid4(),
                domain=f"example{i}.com",
                decision=True,
                latency_ms=5.2,
            )
            for i in range(3)
        ]

        with patch.object(logger._logger, "info") as mock_info:
            await logger.log_batch(decisions)

            assert mock_info.call_count == 3

    @pytest.mark.asyncio
    async def test_log_batch_empty(self, logger: DecisionLogger) -> None:
        """Test batch logging with empty list."""
        with patch.object(logger._logger, "info") as mock_info:
            await logger.log_batch([])

            mock_info.assert_not_called()

    @pytest.mark.asyncio
    async def test_log_batch_async(self, async_logger: DecisionLogger) -> None:
        """Test async batch logging."""
        decisions = [
            DecisionMetadata(
                timestamp=datetime.now(UTC),
                agent_id=uuid4(),
                domain=f"example{i}.com",
                decision=True,
                latency_ms=5.2,
            )
            for i in range(3)
        ]

        await async_logger.log_batch(decisions)

        assert len(async_logger._batch) == 3

        await async_logger.shutdown()

    @pytest.mark.asyncio
    async def test_flush_empty_batch(self, async_logger: DecisionLogger) -> None:
        """Test flushing empty batch."""
        await async_logger.flush()

        assert len(async_logger._batch) == 0

    @pytest.mark.asyncio
    async def test_flush_with_pending(self, async_logger: DecisionLogger) -> None:
        """Test flushing pending batch."""
        decisions = [
            DecisionMetadata(
                timestamp=datetime.now(UTC),
                agent_id=uuid4(),
                domain=f"example{i}.com",
                decision=True,
                latency_ms=5.2,
            )
            for i in range(3)
        ]

        with patch.object(async_logger._logger, "info") as mock_info:
            await async_logger.log_batch(decisions)
            assert len(async_logger._batch) == 3

            await async_logger.flush()
            assert len(async_logger._batch) == 0
            assert mock_info.call_count == 3

    @pytest.mark.asyncio
    async def test_batch_timer_auto_flush(self, async_logger: DecisionLogger) -> None:
        """Test batch timer auto-flushes after timeout."""
        async_logger.batch_timeout_seconds = 0.1

        metadata = DecisionMetadata(
            timestamp=datetime.now(UTC),
            agent_id=uuid4(),
            domain="example.com",
            decision=True,
            latency_ms=5.2,
        )

        with patch.object(async_logger._logger, "info") as mock_info:
            await async_logger.log_decision(metadata)
            assert len(async_logger._batch) == 1

            # Wait for timer to flush
            await asyncio.sleep(0.2)

            # Batch should be empty
            assert len(async_logger._batch) == 0
            assert mock_info.call_count == 1

        await async_logger.shutdown()

    @pytest.mark.asyncio
    async def test_shutdown_flushes_pending(self, async_logger: DecisionLogger) -> None:
        """Test shutdown flushes pending batch."""
        decisions = [
            DecisionMetadata(
                timestamp=datetime.now(UTC),
                agent_id=uuid4(),
                domain=f"example{i}.com",
                decision=True,
                latency_ms=5.2,
            )
            for i in range(2)
        ]

        with patch.object(async_logger._logger, "info") as mock_info:
            await async_logger.log_batch(decisions)
            assert len(async_logger._batch) == 2

            await async_logger.shutdown()

            assert len(async_logger._batch) == 0
            assert mock_info.call_count == 2
            assert async_logger._shutdown is True

    @pytest.mark.asyncio
    async def test_shutdown_cancels_timer(self, async_logger: DecisionLogger) -> None:
        """Test shutdown cancels running batch timer."""
        metadata = DecisionMetadata(
            timestamp=datetime.now(UTC),
            agent_id=uuid4(),
            domain="example.com",
            decision=True,
            latency_ms=5.2,
        )

        await async_logger.log_decision(metadata)

        # Timer should be running
        assert async_logger._batch_task is not None
        assert not async_logger._batch_task.done()

        await async_logger.shutdown()

        # Timer should be cancelled
        assert async_logger._batch_task.cancelled() or async_logger._batch_task.done()

    @pytest.mark.asyncio
    async def test_context_manager(self) -> None:
        """Test DecisionLogger as async context manager."""
        async with DecisionLogger() as logger:
            assert logger is not None
            assert not logger._shutdown

        # Should be shutdown after exiting context
        assert logger._shutdown

    @pytest.mark.asyncio
    async def test_write_log_allow(self, logger: DecisionLogger) -> None:
        """Test _write_log for allow decision."""
        metadata = DecisionMetadata(
            timestamp=datetime.now(UTC),
            agent_id=uuid4(),
            domain="example.com",
            decision=True,
            latency_ms=5.2,
        )

        with patch.object(logger._logger, "info") as mock_info:
            logger._write_log(metadata)

            mock_info.assert_called_once()
            call_args = mock_info.call_args
            assert "ALLOW" in call_args[0][0]
            assert "example.com" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_write_log_deny(self, logger: DecisionLogger) -> None:
        """Test _write_log for deny decision."""
        metadata = DecisionMetadata(
            timestamp=datetime.now(UTC),
            agent_id=uuid4(),
            domain="example.com",
            decision=False,
            latency_ms=5.2,
        )

        with patch.object(logger._logger, "warning") as mock_warning:
            logger._write_log(metadata)

            mock_warning.assert_called_once()
            call_args = mock_warning.call_args
            assert "DENY" in call_args[0][0]
            assert "example.com" in call_args[0][0]


class TestCreateDecisionMetadata:
    """Test suite for create_decision_metadata factory function."""

    def test_create_minimal(self) -> None:
        """Test create_decision_metadata with minimal args."""
        agent_id = uuid4()

        metadata = create_decision_metadata(
            agent_id=agent_id,
            domain="example.com",
            decision=True,
            latency_ms=5.2,
        )

        assert metadata.agent_id == str(agent_id)
        assert metadata.domain == "example.com"
        assert metadata.decision is True
        assert metadata.latency_ms == 5.2
        assert metadata.tenant_id is None
        assert metadata.policy_id is None
        assert metadata.reason is None
        assert metadata.request_id is None

    def test_create_full(self) -> None:
        """Test create_decision_metadata with all args."""
        agent_id = uuid4()
        tenant_id = uuid4()
        policy_id = uuid4()
        timestamp = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)

        metadata = create_decision_metadata(
            agent_id=agent_id,
            domain="example.com",
            decision=False,
            latency_ms=10.5,
            tenant_id=tenant_id,
            policy_id=policy_id,
            reason="Policy violation",
            request_id="req-123",
            timestamp=timestamp,
            custom_field="custom_value",
        )

        assert metadata.agent_id == str(agent_id)
        assert metadata.domain == "example.com"
        assert metadata.decision is False
        assert metadata.latency_ms == 10.5
        assert metadata.tenant_id == str(tenant_id)
        assert metadata.policy_id == str(policy_id)
        assert metadata.reason == "Policy violation"
        assert metadata.request_id == "req-123"
        assert metadata.timestamp == timestamp
        assert metadata.additional_context == {"custom_field": "custom_value"}

    def test_create_default_timestamp(self) -> None:
        """Test create_decision_metadata uses current time by default."""
        before = datetime.now(UTC)

        metadata = create_decision_metadata(
            agent_id=uuid4(),
            domain="example.com",
            decision=True,
            latency_ms=5.2,
        )

        after = datetime.now(UTC)

        assert before <= metadata.timestamp <= after

    def test_create_with_kwargs(self) -> None:
        """Test create_decision_metadata with additional context kwargs."""
        metadata = create_decision_metadata(
            agent_id=uuid4(),
            domain="example.com",
            decision=True,
            latency_ms=5.2,
            custom_key="custom_value",
            count=42,
        )

        assert metadata.additional_context == {"custom_key": "custom_value", "count": 42}

    def test_create_with_string_ids(self) -> None:
        """Test create_decision_metadata with string IDs."""
        metadata = create_decision_metadata(
            agent_id="agent-123",
            domain="example.com",
            decision=True,
            latency_ms=5.2,
            tenant_id="tenant-456",
            policy_id="policy-789",
        )

        assert metadata.agent_id == "agent-123"
        assert metadata.tenant_id == "tenant-456"
        assert metadata.policy_id == "policy-789"
