"""OPA decision logger for structured logging of policy decisions.

This module provides structured logging of OPA policy evaluation decisions.
It integrates with the core logging system and supports async batch logging
to avoid blocking policy evaluation.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from core.logging import StructuredLogger
from loguru import logger


class DecisionMetadata:
    """Metadata for an OPA policy decision.

    Captures all relevant information about a policy evaluation including
    timing, decision outcome, and context.
    """

    def __init__(
        self,
        timestamp: datetime,
        agent_id: UUID | str,
        domain: str,
        decision: bool,
        latency_ms: float,
        tenant_id: UUID | str | None = None,
        policy_id: UUID | str | None = None,
        reason: str | None = None,
        request_id: str | None = None,
        additional_context: dict[str, Any] | None = None,
    ) -> None:
        """Initialize decision metadata.

        Args:
            timestamp: When the decision was made
            agent_id: Agent that made the request
            domain: Domain being accessed
            decision: Policy decision (True=allow, False=deny)
            latency_ms: Decision latency in milliseconds
            tenant_id: Optional tenant identifier
            policy_id: Optional policy identifier
            reason: Optional decision reason/explanation
            request_id: Optional request correlation ID
            additional_context: Optional additional metadata
        """
        self.timestamp = timestamp
        self.agent_id = str(agent_id)
        self.domain = domain
        self.decision = decision
        self.latency_ms = latency_ms
        self.tenant_id = str(tenant_id) if tenant_id else None
        self.policy_id = str(policy_id) if policy_id else None
        self.reason = reason
        self.request_id = request_id
        self.additional_context = additional_context or {}

    def to_dict(self) -> dict[str, Any]:
        """Convert metadata to dictionary for logging.

        Returns:
            Dictionary representation of decision metadata
        """
        data: dict[str, Any] = {
            "timestamp": self.timestamp.isoformat(),
            "agent_id": self.agent_id,
            "domain": self.domain,
            "decision": "allow" if self.decision else "deny",
            "latency_ms": round(self.latency_ms, 2),
        }

        if self.tenant_id:
            data["tenant_id"] = self.tenant_id

        if self.policy_id:
            data["policy_id"] = self.policy_id

        if self.reason:
            data["reason"] = self.reason

        if self.request_id:
            data["request_id"] = self.request_id

        if self.additional_context:
            data["context"] = self.additional_context

        return data


class DecisionLogger:
    """Structured logger for OPA policy decisions.

    This logger provides async logging of OPA decisions with structured
    metadata. It supports both individual and batch logging to minimize
    performance impact on policy evaluation.

    Example:
        >>> logger = DecisionLogger()
        >>> metadata = DecisionMetadata(
        ...     timestamp=datetime.now(UTC),
        ...     agent_id="agent-123",
        ...     domain="example.com",
        ...     decision=True,
        ...     latency_ms=5.2
        ... )
        >>> await logger.log_decision(metadata)
    """

    def __init__(
        self,
        logger_name: str = "opa.decisions",
        enable_async_logging: bool = True,
        batch_size: int = 100,
        batch_timeout_seconds: float = 5.0,
    ) -> None:
        """Initialize decision logger.

        Args:
            logger_name: Name for the structured logger
            enable_async_logging: Enable async batch logging
            batch_size: Maximum batch size before auto-flush
            batch_timeout_seconds: Maximum time to wait before auto-flush
        """
        self._logger = StructuredLogger(logger_name)
        self.enable_async_logging = enable_async_logging
        self.batch_size = batch_size
        self.batch_timeout_seconds = batch_timeout_seconds

        # Batch logging state
        self._batch: list[DecisionMetadata] = []
        self._batch_lock = asyncio.Lock()
        self._batch_task: asyncio.Task[None] | None = None
        self._shutdown = False

        logger.debug(
            f"Initialized DecisionLogger: name={logger_name}, "
            f"async={enable_async_logging}, batch_size={batch_size}"
        )

    async def log_decision(self, metadata: DecisionMetadata) -> None:
        """Log a single OPA policy decision.

        Logs the decision immediately if async logging is disabled,
        otherwise adds it to the batch queue for async processing.

        Args:
            metadata: Decision metadata to log

        Example:
            >>> metadata = DecisionMetadata(
            ...     timestamp=datetime.now(UTC),
            ...     agent_id="agent-123",
            ...     domain="example.com",
            ...     decision=True,
            ...     latency_ms=5.2
            ... )
            >>> await logger.log_decision(metadata)
        """
        if not self.enable_async_logging:
            # Synchronous logging
            self._write_log(metadata)
            return

        # Async batch logging
        async with self._batch_lock:
            self._batch.append(metadata)

            # Auto-flush if batch is full
            if len(self._batch) >= self.batch_size:
                await self._flush_batch()

            # Start batch timer if not already running
            if self._batch_task is None or self._batch_task.done():
                self._batch_task = asyncio.create_task(self._batch_timer())

    async def log_batch(self, decisions: Sequence[DecisionMetadata]) -> None:
        """Log multiple OPA policy decisions in batch.

        Efficiently logs multiple decisions at once. If async logging is enabled,
        adds them to the batch queue; otherwise logs them immediately.

        Args:
            decisions: Sequence of decision metadata to log

        Example:
            >>> decisions = [
            ...     DecisionMetadata(...),
            ...     DecisionMetadata(...),
            ... ]
            >>> await logger.log_batch(decisions)
        """
        if not decisions:
            return

        if not self.enable_async_logging:
            # Synchronous batch logging
            for metadata in decisions:
                self._write_log(metadata)
            return

        # Async batch logging
        async with self._batch_lock:
            self._batch.extend(decisions)

            # Auto-flush if batch is full
            if len(self._batch) >= self.batch_size:
                await self._flush_batch()

            # Start batch timer if not already running
            if self._batch_task is None or self._batch_task.done():
                self._batch_task = asyncio.create_task(self._batch_timer())

    async def flush(self) -> None:
        """Force flush of pending batched decisions.

        Immediately writes all pending decisions in the batch queue.
        Useful for ensuring decisions are logged before shutdown.

        Example:
            >>> await logger.flush()
        """
        async with self._batch_lock:
            if self._batch:
                await self._flush_batch()

    async def _flush_batch(self) -> None:
        """Internal method to flush current batch.

        Must be called with _batch_lock held.
        """
        if not self._batch:
            return

        batch_to_log = self._batch[:]
        self._batch.clear()

        # Log batch outside lock to avoid blocking
        for metadata in batch_to_log:
            self._write_log(metadata)

        logger.debug(f"Flushed {len(batch_to_log)} OPA decisions from batch")

    async def _batch_timer(self) -> None:
        """Background task to auto-flush batches after timeout."""
        try:
            await asyncio.sleep(self.batch_timeout_seconds)

            if not self._shutdown:
                async with self._batch_lock:
                    if self._batch:
                        await self._flush_batch()

        except asyncio.CancelledError:
            logger.debug("Batch timer cancelled")

    def _write_log(self, metadata: DecisionMetadata) -> None:
        """Write decision metadata to log.

        Args:
            metadata: Decision metadata to write
        """
        decision_data = metadata.to_dict()

        # Determine log level based on decision
        if metadata.decision:
            # ALLOW decisions at info level
            self._logger.info(
                f"OPA decision: ALLOW {metadata.domain} for agent {metadata.agent_id}",
                **decision_data,
            )
        else:
            # DENY decisions at warning level for visibility
            self._logger.warning(
                f"OPA decision: DENY {metadata.domain} for agent {metadata.agent_id}",
                **decision_data,
            )

    async def shutdown(self) -> None:
        """Shutdown decision logger and flush pending batches.

        Ensures all pending decisions are logged before shutdown.
        Cancels any running batch timers.

        Example:
            >>> await logger.shutdown()
        """
        self._shutdown = True

        # Cancel batch timer
        if self._batch_task and not self._batch_task.done():
            self._batch_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._batch_task

        # Flush remaining batch
        await self.flush()

        logger.info("DecisionLogger shutdown complete")

    async def __aenter__(self) -> DecisionLogger:
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.shutdown()


def create_decision_metadata(
    agent_id: UUID | str,
    domain: str,
    decision: bool,
    latency_ms: float,
    tenant_id: UUID | str | None = None,
    policy_id: UUID | str | None = None,
    reason: str | None = None,
    request_id: str | None = None,
    timestamp: datetime | None = None,
    **kwargs: Any,
) -> DecisionMetadata:
    """Factory function to create decision metadata.

    Convenience function for creating DecisionMetadata instances.

    Args:
        agent_id: Agent that made the request
        domain: Domain being accessed
        decision: Policy decision (True=allow, False=deny)
        latency_ms: Decision latency in milliseconds
        tenant_id: Optional tenant identifier
        policy_id: Optional policy identifier
        reason: Optional decision reason
        request_id: Optional request correlation ID
        timestamp: Optional timestamp (defaults to now)
        **kwargs: Additional context fields

    Returns:
        DecisionMetadata instance

    Example:
        >>> metadata = create_decision_metadata(
        ...     agent_id="agent-123",
        ...     domain="example.com",
        ...     decision=True,
        ...     latency_ms=5.2,
        ...     tenant_id="tenant-456"
        ... )
    """
    if timestamp is None:
        timestamp = datetime.now(UTC)

    return DecisionMetadata(
        timestamp=timestamp,
        agent_id=agent_id,
        domain=domain,
        decision=decision,
        latency_ms=latency_ms,
        tenant_id=tenant_id,
        policy_id=policy_id,
        reason=reason,
        request_id=request_id,
        additional_context=kwargs if kwargs else None,
    )
