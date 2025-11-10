"""Tests for OpenTelemetry integration in domain services."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from domain.audit.entity import AccessDecision
from domain.audit.service import AccessRequest, AuditService
from domain.policy.service import PolicyService


class TestAuditServiceObservability:
    """Test OpenTelemetry integration in AuditService."""

    @pytest.fixture
    def mock_audit_repository(self) -> MagicMock:
        """Create mock audit repository."""
        repo = MagicMock()
        repo.get_latest_entry_for_agent = AsyncMock(return_value=None)
        repo.get_next_sequence_number = AsyncMock(return_value=1)
        repo.save = AsyncMock()
        return repo

    @pytest.fixture
    def audit_service(self, mock_audit_repository: MagicMock) -> AuditService:
        """Create audit service instance."""
        return AuditService(mock_audit_repository)

    async def test_record_access_creates_trace_span(
        self,
        audit_service: AuditService,
    ) -> None:
        """Test that record_access creates OpenTelemetry trace span."""
        request = AccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="example.com",
            decision=AccessDecision.ALLOW,
            reason="Test access",
            timestamp=datetime.now(UTC),
        )

        with patch("domain.audit.service.tracer.start_as_current_span") as mock_span:
            mock_context = MagicMock()
            mock_span.return_value.__enter__ = MagicMock(return_value=mock_context)
            mock_span.return_value.__exit__ = MagicMock(return_value=False)

            entry = await audit_service.record_access(request)

            # Verify span was created with correct name
            mock_span.assert_called_once()
            call_args = mock_span.call_args
            assert call_args[0][0] == "audit.record_access"

            # Verify attributes were set
            assert "tenant.id" in call_args[1]["attributes"]
            assert "agent.id" in call_args[1]["attributes"]
            assert "domain" in call_args[1]["attributes"]

    @pytest.mark.skip(
        reason="Metrics recording moved to infrastructure layer (Phase 1: Clean Domain)"
    )
    async def test_record_access_records_metrics_when_available(
        self,
        audit_service: AuditService,
    ) -> None:
        """Test that record_access records metrics when telemetry is available."""
        request = AccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="example.com",
            decision=AccessDecision.ALLOW,
            reason="Test access",
            timestamp=datetime.now(UTC),
        )

        with patch("domain.audit.service.get_metrics") as mock_get_metrics:
            mock_metrics = MagicMock()
            mock_get_metrics.return_value = mock_metrics

            entry = await audit_service.record_access(request)

            # Verify metrics were recorded
            assert mock_metrics.audit_entries_total.add.called

    @pytest.mark.skip(
        reason="Metrics recording moved to infrastructure layer (Phase 1: Clean Domain)"
    )
    async def test_record_access_handles_no_metrics_gracefully(
        self,
        audit_service: AuditService,
    ) -> None:
        """Test that record_access works even when metrics unavailable."""
        request = AccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="example.com",
            decision=AccessDecision.ALLOW,
            reason="Test access",
            timestamp=datetime.now(UTC),
        )

        with patch("domain.audit.service.get_metrics") as mock_get_metrics:
            mock_get_metrics.return_value = None  # No metrics available

            # Should not raise exception
            entry = await audit_service.record_access(request)
            assert entry is not None


class TestPolicyServiceObservability:
    """Test OpenTelemetry integration in PolicyService."""

    @pytest.fixture
    def mock_policy_repository(self) -> MagicMock:
        """Create mock policy repository."""
        repo = MagicMock()
        repo.find_policies_for_evaluation = AsyncMock(return_value=[])
        return repo

    @pytest.fixture
    def mock_agent_repository(self) -> MagicMock:
        """Create mock agent repository."""
        return MagicMock()

    @pytest.fixture
    def policy_service(
        self, mock_policy_repository: MagicMock, mock_agent_repository: MagicMock
    ) -> PolicyService:
        """Create policy service instance."""
        return PolicyService(mock_policy_repository, mock_agent_repository)

    async def test_evaluate_access_creates_trace_span(
        self,
        policy_service: PolicyService,
    ) -> None:
        """Test that evaluate_access_request creates OpenTelemetry trace span."""
        from domain.policy.service import AccessRequest as PolicyAccessRequest

        request = PolicyAccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="example.com",
            timestamp=datetime.now(UTC),
        )

        with patch("domain.policy.service.tracer.start_as_current_span") as mock_span:
            mock_context = MagicMock()
            mock_span.return_value.__enter__ = MagicMock(return_value=mock_context)
            mock_span.return_value.__exit__ = MagicMock(return_value=False)

            result = await policy_service.evaluate_access_request(request)

            # Verify span was created
            assert mock_span.called
            call_args = mock_span.call_args
            assert call_args[0][0] == "policy.evaluate_access"

    @pytest.mark.skip(
        reason="Metrics recording moved to infrastructure layer (Phase 1: Clean Domain)"
    )
    async def test_evaluate_access_records_metrics_when_available(
        self,
        policy_service: PolicyService,
    ) -> None:
        """Test that evaluate_access_request records metrics."""
        from domain.policy.service import AccessRequest as PolicyAccessRequest

        request = PolicyAccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="example.com",
            timestamp=datetime.now(UTC),
        )

        with patch("domain.policy.service.get_metrics") as mock_get_metrics:
            mock_metrics = MagicMock()
            mock_get_metrics.return_value = mock_metrics

            result = await policy_service.evaluate_access_request(request)

            # Verify metrics were recorded
            assert mock_metrics.policy_evaluations_total.add.called
            assert mock_metrics.policy_evaluation_duration.record.called

    async def test_evaluate_access_error_handling_with_telemetry(
        self,
        mock_policy_repository: MagicMock,
        mock_agent_repository: MagicMock,
    ) -> None:
        """Test that policy evaluation errors are recorded in telemetry."""
        from domain.policy.service import AccessRequest as PolicyAccessRequest

        service = PolicyService(mock_policy_repository, mock_agent_repository)

        # Make repository raise an error
        mock_policy_repository.find_policies_for_evaluation = AsyncMock(
            side_effect=Exception("Database error")
        )

        request = PolicyAccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="example.com",
            timestamp=datetime.now(UTC),
        )

        with patch("domain.policy.service.tracer.start_as_current_span") as mock_span:
            mock_context = MagicMock()
            mock_span.return_value.__enter__ = MagicMock(return_value=mock_context)
            mock_span.return_value.__exit__ = MagicMock(return_value=False)

            with pytest.raises(Exception, match="Database error"):
                await service.evaluate_access_request(request)

            # Verify error was recorded in span
            assert mock_context.record_exception.called
            assert mock_context.set_status.called
