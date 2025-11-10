"""Unit tests for audit export functionality."""

import io
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

from application.queries.audit_export import AuditExporter
from domain.audit.entity import AccessDecision, AuditEntry, TimedAccessContext
from domain.audit.repository import AuditRepository
from domain.common.value_objects import DomainName


class TestAuditExporter:
    """Test suite for audit exporter."""

    @pytest.fixture
    def mock_repository(self) -> MagicMock:
        """Create mock audit repository."""
        mock = MagicMock(spec=AuditRepository)
        mock.find_by_tenant_time_range = AsyncMock()
        return mock

    @pytest.fixture
    def exporter(self, mock_repository: MagicMock) -> AuditExporter:
        """Create exporter instance."""
        return AuditExporter(mock_repository)

    @pytest.fixture
    def test_tenant_id(self) -> UUID:
        """Generate test tenant ID."""
        return uuid4()

    @pytest.fixture
    def base_time(self) -> datetime:
        """Generate base timestamp."""
        return datetime(2024, 10, 5, 9, 0, 0, tzinfo=UTC)

    def _create_audit_entry(self, timestamp: datetime, tenant_id: UUID) -> AuditEntry:
        """Create test audit entry."""
        timed_context = TimedAccessContext.create_from_timestamp(timestamp)

        entry = AuditEntry(
            tenant_id=tenant_id,
            agent_id=uuid4(),
            timestamp=timestamp,
            domain=DomainName(value="example.com"),
            decision=AccessDecision.ALLOW,
            reason="Test",
            request_method="GET",
            request_path="/test",
            timed_access_metadata=timed_context,
            sequence_number=0,
        )

        return entry.with_hash("", None)

    @pytest.mark.asyncio
    async def test_export_to_csv_with_entries(
        self,
        exporter: AuditExporter,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
        base_time: datetime,
    ) -> None:
        """Test CSV export with audit entries."""
        entries = [
            self._create_audit_entry(base_time, test_tenant_id),
            self._create_audit_entry(base_time + timedelta(minutes=1), test_tenant_id),
        ]
        mock_repository.find_by_tenant_time_range.return_value = entries

        csv_output = await exporter.export_to_csv(
            test_tenant_id, base_time, base_time + timedelta(hours=1)
        )

        assert "entry_id" in csv_output
        assert "example.com" in csv_output
        lines = csv_output.strip().split("\n")
        assert len(lines) == 3

    @pytest.mark.asyncio
    async def test_export_to_csv_empty(
        self,
        exporter: AuditExporter,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
        base_time: datetime,
    ) -> None:
        """Test CSV export with no entries."""
        mock_repository.find_by_tenant_time_range.return_value = []

        csv_output = await exporter.export_to_csv(
            test_tenant_id, base_time, base_time + timedelta(hours=1)
        )

        lines = csv_output.strip().split("\n")
        assert len(lines) == 1

    @pytest.mark.asyncio
    async def test_export_to_json_with_entries(
        self,
        exporter: AuditExporter,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
        base_time: datetime,
    ) -> None:
        """Test JSON export with audit entries."""
        entries = [self._create_audit_entry(base_time, test_tenant_id)]
        mock_repository.find_by_tenant_time_range.return_value = entries

        json_output = await exporter.export_to_json(
            test_tenant_id, base_time, base_time + timedelta(hours=1)
        )

        assert "metadata" in json_output
        assert "entries" in json_output
        assert str(test_tenant_id) in json_output

    @pytest.mark.asyncio
    async def test_export_to_json_pretty(
        self,
        exporter: AuditExporter,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
        base_time: datetime,
    ) -> None:
        """Test JSON export with pretty printing."""
        entries = [self._create_audit_entry(base_time, test_tenant_id)]
        mock_repository.find_by_tenant_time_range.return_value = entries

        json_output = await exporter.export_to_json(
            test_tenant_id, base_time, base_time + timedelta(hours=1), pretty=True
        )

        assert "\n" in json_output

    @pytest.mark.asyncio
    async def test_export_to_json_not_pretty(
        self,
        exporter: AuditExporter,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
        base_time: datetime,
    ) -> None:
        """Test JSON export without pretty printing."""
        entries = [self._create_audit_entry(base_time, test_tenant_id)]
        mock_repository.find_by_tenant_time_range.return_value = entries

        json_output = await exporter.export_to_json(
            test_tenant_id, base_time, base_time + timedelta(hours=1), pretty=False
        )

        assert isinstance(json_output, str)
        assert "metadata" in json_output

    def test_entry_to_csv_dict_conversion(
        self, exporter: AuditExporter, test_tenant_id: UUID, base_time: datetime
    ) -> None:
        """Test conversion of audit entry to CSV dictionary."""
        entry = self._create_audit_entry(base_time, test_tenant_id)

        csv_dict = exporter._entry_to_csv_dict(entry)

        assert csv_dict["entry_id"] == str(entry.entry_id)
        assert csv_dict["domain"] == "example.com"
        assert csv_dict["decision"] == entry.decision.value
        assert "risk_score" in csv_dict

    def test_entry_to_dict_conversion(
        self, exporter: AuditExporter, test_tenant_id: UUID, base_time: datetime
    ) -> None:
        """Test conversion of audit entry to dictionary."""
        entry = self._create_audit_entry(base_time, test_tenant_id)

        entry_dict = exporter._entry_to_dict(entry)

        assert entry_dict["entry_id"] == str(entry.entry_id)
        assert "timed_access_metadata" in entry_dict
        assert "risk_score" in entry_dict

    @pytest.mark.asyncio
    async def test_export_to_csv_with_output_file(
        self,
        exporter: AuditExporter,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
        base_time: datetime,
    ) -> None:
        """Test CSV export to file object."""
        entries = [self._create_audit_entry(base_time, test_tenant_id)]
        mock_repository.find_by_tenant_time_range.return_value = entries

        output_file = io.StringIO()
        result = await exporter.export_to_csv(
            test_tenant_id, base_time, base_time + timedelta(hours=1), output_file=output_file
        )

        assert result == ""
        csv_content = output_file.getvalue()
        assert "entry_id" in csv_content

    @pytest.mark.asyncio
    async def test_export_to_json_with_output_file(
        self,
        exporter: AuditExporter,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
        base_time: datetime,
    ) -> None:
        """Test JSON export to file object."""
        entries = [self._create_audit_entry(base_time, test_tenant_id)]
        mock_repository.find_by_tenant_time_range.return_value = entries

        output_file = io.StringIO()
        result = await exporter.export_to_json(
            test_tenant_id, base_time, base_time + timedelta(hours=1), output_file=output_file
        )

        assert result == ""
        json_content = output_file.getvalue()
        assert "metadata" in json_content

    @pytest.mark.asyncio
    async def test_export_multiple_entries(
        self,
        exporter: AuditExporter,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
        base_time: datetime,
    ) -> None:
        """Test export with multiple entries."""
        entries = [
            self._create_audit_entry(base_time + timedelta(minutes=i), test_tenant_id)
            for i in range(10)
        ]
        mock_repository.find_by_tenant_time_range.return_value = entries

        csv_output = await exporter.export_to_csv(
            test_tenant_id, base_time, base_time + timedelta(hours=1)
        )

        lines = csv_output.strip().split("\n")
        assert len(lines) == 11
