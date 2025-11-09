"""Tests for audit logging integrations with TimeSource, Signer, and OPA."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from domain.audit.entity import AccessDecision, AuditEntry, TimedAccessContext
from domain.audit.service import AccessRequest, AuditService
from domain.common.time import MockTimeSource, SystemTimeSource
from domain.common.value_objects import DomainName
from infrastructure.opa.client import OPAClient
from infrastructure.security.signer import RSASigner


class TestTimeSourceIntegration:
    """Test TimeSource integration in audit logging."""

    @pytest.fixture
    def mock_time_source(self) -> MockTimeSource:
        """Create a mock time source with fixed time."""
        fixed_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        return MockTimeSource(fixed_time=fixed_time, increment_ns=1_000_000_000)

    @pytest.fixture
    def mock_repository(self) -> AsyncMock:
        """Create mock audit repository."""
        repo = AsyncMock()
        repo.get_latest_entry_for_agent.return_value = None
        repo.get_next_sequence_number.return_value = 1
        repo.save.return_value = None
        return repo

    @pytest.mark.asyncio
    async def test_audit_service_uses_time_source_for_timestamps(
        self, mock_time_source: MockTimeSource, mock_repository: AsyncMock
    ) -> None:
        """Test that AuditService uses TimeSource for timestamps."""
        service = AuditService(
            audit_repository=mock_repository,
            time_source=mock_time_source,
        )

        tenant_id = uuid4()
        agent_id = uuid4()

        request = AccessRequest(
            tenant_id=tenant_id,
            agent_id=agent_id,
            domain="example.com",
            decision=AccessDecision.ALLOW,
            time_source=mock_time_source,
        )

        entry = await service.record_access(request)

        # Verify timestamp uses mock time source
        assert entry.timestamp == datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        # Verify timestamp_nanos uses mock time source
        assert isinstance(entry.timestamp_nanos, int)

    @pytest.mark.asyncio
    async def test_timed_access_context_uses_time_source(
        self, mock_time_source: MockTimeSource
    ) -> None:
        """Test TimedAccessContext uses TimeSource for processing timestamp."""
        request_time = datetime(2024, 1, 1, 10, 0, 0, tzinfo=UTC)
        processing_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)

        # Set mock time source to processing time
        mock_time_source = MockTimeSource(fixed_time=processing_time)

        context = TimedAccessContext.create_from_timestamp(
            request_time, time_source=mock_time_source
        )

        assert context.request_timestamp == request_time
        assert context.processing_timestamp == processing_time
        # 2 hour difference
        assert (context.processing_timestamp - context.request_timestamp).total_seconds() == 7200

    @pytest.mark.asyncio
    async def test_access_request_uses_time_source_for_default_timestamp(
        self, mock_time_source: MockTimeSource
    ) -> None:
        """Test AccessRequest uses TimeSource for default timestamp."""
        request = AccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="example.com",
            decision=AccessDecision.ALLOW,
            time_source=mock_time_source,
        )

        assert request.timestamp == datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)

    def test_system_time_source_is_default(self, mock_repository: AsyncMock) -> None:
        """Test that SystemTimeSource is used by default."""
        service = AuditService(audit_repository=mock_repository)
        assert isinstance(service._time_source, SystemTimeSource)


class TestSignerIntegration:
    """Test Signer integration in audit logging."""

    @pytest.fixture
    def mock_repository(self) -> AsyncMock:
        """Create mock audit repository."""
        repo = AsyncMock()
        repo.get_latest_entry_for_agent.return_value = None
        repo.get_next_sequence_number.return_value = 1
        repo.save.return_value = None
        return repo

    @pytest.fixture
    def signer(self) -> RSASigner:
        """Create RSA signer for testing."""
        signer = RSASigner(key_size=2048)
        signer.generate_key()
        return signer

    @pytest.mark.asyncio
    async def test_audit_service_signs_entries_when_signer_provided(
        self, mock_repository: AsyncMock, signer: RSASigner
    ) -> None:
        """Test that AuditService signs entries when Signer is provided."""
        service = AuditService(
            audit_repository=mock_repository,
            signer=signer,
        )

        tenant_id = uuid4()
        agent_id = uuid4()

        request = AccessRequest(
            tenant_id=tenant_id,
            agent_id=agent_id,
            domain="example.com",
            decision=AccessDecision.ALLOW,
        )

        entry = await service.record_access(request)

        # Verify signature is present and not empty
        assert entry.signature != ""
        assert len(entry.signature) > 0
        # Signature should be a hex string
        assert all(c in "0123456789abcdef" for c in entry.signature)

    @pytest.mark.asyncio
    async def test_audit_service_no_signature_when_signer_not_provided(
        self, mock_repository: AsyncMock
    ) -> None:
        """Test that entries are not signed when Signer is not provided."""
        service = AuditService(audit_repository=mock_repository)

        request = AccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="example.com",
            decision=AccessDecision.ALLOW,
        )

        entry = await service.record_access(request)

        # Verify no signature
        assert entry.signature == ""

    @pytest.mark.asyncio
    async def test_signature_verification(
        self, mock_repository: AsyncMock, signer: RSASigner
    ) -> None:
        """Test that signatures can be verified."""
        service = AuditService(
            audit_repository=mock_repository,
            signer=signer,
        )

        request = AccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="example.com",
            decision=AccessDecision.ALLOW,
        )

        entry = await service.record_access(request)

        # Recreate the data that was signed
        data_to_sign = (
            f"{entry.entry_id}|{entry.tenant_id}|{entry.agent_id}|"
            f"{entry.timestamp.isoformat()}|{entry.timestamp_nanos}|"
            f"{entry.domain.value}|{entry.decision.value}|"
            f"{entry.sequence_number}|{entry.current_hash}"
        ).encode()

        # Convert hex signature back to bytes
        signature_bytes = bytes.fromhex(entry.signature)

        # Verify signature
        is_valid = signer.verify(data_to_sign, signature_bytes)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_signature_tamper_detection(
        self, mock_repository: AsyncMock, signer: RSASigner
    ) -> None:
        """Test that signature detects tampering."""
        service = AuditService(
            audit_repository=mock_repository,
            signer=signer,
        )

        request = AccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="example.com",
            decision=AccessDecision.ALLOW,
        )

        entry = await service.record_access(request)

        # Create tampered data (different domain)
        tampered_data = (
            f"{entry.entry_id}|{entry.tenant_id}|{entry.agent_id}|"
            f"{entry.timestamp.isoformat()}|{entry.timestamp_nanos}|"
            f"attacker.com|{entry.decision.value}|"  # Changed domain!
            f"{entry.sequence_number}|{entry.current_hash}"
        ).encode()

        signature_bytes = bytes.fromhex(entry.signature)

        # Verification should fail on tampered data
        is_valid = signer.verify(tampered_data, signature_bytes)
        assert is_valid is False


class TestOPAIntegration:
    """Test OPA client integration in audit logging."""

    @pytest.fixture
    def mock_repository(self) -> AsyncMock:
        """Create mock audit repository."""
        repo = AsyncMock()
        repo.get_latest_entry_for_agent.return_value = None
        repo.get_next_sequence_number.return_value = 1
        repo.save.return_value = None
        return repo

    @pytest.fixture
    def mock_opa_client(self) -> AsyncMock:
        """Create mock OPA client."""
        return AsyncMock(spec=OPAClient)

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="OPA integration moved to infrastructure layer (Phase 1: Clean Domain)")
    async def test_audit_service_checks_opa_policy_before_logging(
        self, mock_repository: AsyncMock, mock_opa_client: AsyncMock
    ) -> None:
        """Test that AuditService checks OPA policy before logging."""
        # Configure OPA to allow logging
        mock_opa_client.check_policy.return_value = True

        service = AuditService(
            audit_repository=mock_repository,
            opa_client=mock_opa_client,
        )

        request = AccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="example.com",
            decision=AccessDecision.ALLOW,
        )

        entry = await service.record_access(request)

        # Verify OPA was called
        mock_opa_client.check_policy.assert_called_once()
        call_args = mock_opa_client.check_policy.call_args

        # Verify policy input structure
        policy_input = call_args[0][0]
        assert "audit" in policy_input
        assert policy_input["audit"]["domain"] == "example.com"
        assert policy_input["audit"]["decision"] == "allow"

        # Verify policy path
        assert call_args[1]["policy_path"] == "chronoguard/audit/should_log"

        # Verify entry was logged
        assert entry.metadata["policy_filtered"] == "true"

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="OPA integration moved to infrastructure layer (Phase 1: Clean Domain)")
    async def test_audit_service_marks_filtered_entries(
        self, mock_repository: AsyncMock, mock_opa_client: AsyncMock
    ) -> None:
        """Test that entries are marked when OPA policy says to filter."""
        # Configure OPA to filter logging
        mock_opa_client.check_policy.return_value = False

        service = AuditService(
            audit_repository=mock_repository,
            opa_client=mock_opa_client,
        )

        request = AccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="example.com",
            decision=AccessDecision.ALLOW,
        )

        entry = await service.record_access(request)

        # Verify entry was still logged but marked as filtered
        assert entry.metadata["policy_filtered"] == "false"

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="OPA integration moved to infrastructure layer (Phase 1: Clean Domain)")
    async def test_opa_check_fails_open_on_error(
        self, mock_repository: AsyncMock, mock_opa_client: AsyncMock
    ) -> None:
        """Test that OPA failures default to logging (fail-open)."""
        # Configure OPA to raise an exception
        mock_opa_client.check_policy.side_effect = Exception("OPA connection failed")

        service = AuditService(
            audit_repository=mock_repository,
            opa_client=mock_opa_client,
        )

        request = AccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="example.com",
            decision=AccessDecision.ALLOW,
        )

        # Should not raise exception, should log anyway
        entry = await service.record_access(request)

        # Verify entry was logged (fail-open)
        assert entry is not None
        assert entry.metadata["policy_filtered"] == "true"

    @pytest.mark.asyncio
    async def test_no_opa_check_when_client_not_provided(self, mock_repository: AsyncMock) -> None:
        """Test that no OPA check is performed when client is not provided."""
        service = AuditService(audit_repository=mock_repository)

        request = AccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="example.com",
            decision=AccessDecision.ALLOW,
        )

        entry = await service.record_access(request)

        # Verify no policy metadata since OPA wasn't used
        assert "policy_filtered" not in entry.metadata


class TestSignerErrorHandling:
    """Test error handling in Signer integration."""

    @pytest.fixture
    def mock_repository(self) -> AsyncMock:
        """Create mock audit repository."""
        repo = AsyncMock()
        repo.get_latest_entry_for_agent.return_value = None
        repo.get_next_sequence_number.return_value = 1
        repo.save.return_value = None
        return repo

    @pytest.fixture
    def mock_signer(self) -> MagicMock:
        """Create a mock signer that can fail."""
        return MagicMock()

    @pytest.mark.asyncio
    async def test_signature_failure_raises_security_violation(
        self, mock_repository: AsyncMock, mock_signer: MagicMock
    ) -> None:
        """Test that signature failures raise SecurityViolationError."""
        from domain.common.exceptions import SecurityViolationError

        # Configure signer to raise an exception
        mock_signer.sign.side_effect = Exception("Signing hardware failure")

        service = AuditService(
            audit_repository=mock_repository,
            signer=mock_signer,
        )

        request = AccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="example.com",
            decision=AccessDecision.ALLOW,
        )

        # Should raise SecurityViolationError
        with pytest.raises(SecurityViolationError, match="Audit entry signing failed"):
            await service.record_access(request)


class TestFullIntegration:
    """Test all three integrations working together."""

    @pytest.fixture
    def mock_repository(self) -> AsyncMock:
        """Create mock audit repository."""
        repo = AsyncMock()
        repo.get_latest_entry_for_agent.return_value = None
        repo.get_next_sequence_number.return_value = 1
        repo.save.return_value = None
        return repo

    @pytest.fixture
    def mock_time_source(self) -> MockTimeSource:
        """Create mock time source."""
        return MockTimeSource(
            fixed_time=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            increment_ns=1_000_000_000,
        )

    @pytest.fixture
    def signer(self) -> RSASigner:
        """Create RSA signer."""
        signer = RSASigner(key_size=2048)
        signer.generate_key()
        return signer

    @pytest.fixture
    def mock_opa_client(self) -> AsyncMock:
        """Create mock OPA client."""
        client = AsyncMock(spec=OPAClient)
        client.check_policy.return_value = True
        return client

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="OPA integration moved to infrastructure layer (Phase 1: Clean Domain)")
    async def test_all_integrations_work_together(
        self,
        mock_repository: AsyncMock,
        mock_time_source: MockTimeSource,
        signer: RSASigner,
        mock_opa_client: AsyncMock,
    ) -> None:
        """Test TimeSource, Signer, and OPA all working together."""
        service = AuditService(
            audit_repository=mock_repository,
            time_source=mock_time_source,
            signer=signer,
            opa_client=mock_opa_client,
        )

        request = AccessRequest(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="example.com",
            decision=AccessDecision.ALLOW,
            time_source=mock_time_source,
        )

        entry = await service.record_access(request)

        # Verify TimeSource was used
        assert entry.timestamp == datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)

        # Verify Signer was used
        assert entry.signature != ""
        assert len(entry.signature) > 0

        # Verify OPA was used
        mock_opa_client.check_policy.assert_called_once()
        assert entry.metadata["policy_filtered"] == "true"

        # Verify all integrations produced a valid entry
        assert entry.current_hash != ""
        assert entry.sequence_number == 1

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="OPA integration moved to infrastructure layer (Phase 1: Clean Domain)")
    async def test_initialization_logging(
        self,
        mock_repository: AsyncMock,
        mock_time_source: MockTimeSource,
        signer: RSASigner,
        mock_opa_client: AsyncMock,
    ) -> None:
        """Test that service initialization logs integration status."""
        # This test verifies the logger.info call in __init__
        service = AuditService(
            audit_repository=mock_repository,
            time_source=mock_time_source,
            signer=signer,
            opa_client=mock_opa_client,
        )

        # Verify service is properly initialized with all components
        assert service._time_source == mock_time_source
        assert service._signer == signer
        assert service._opa_client == mock_opa_client
