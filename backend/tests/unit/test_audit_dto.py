"""Tests for Audit DTOs and mappers."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from application.dto import (
    AuditEntryDTO,
    AuditExportRequest,
    AuditMapper,
    AuditQueryRequest,
    TimedAccessContextDTO,
)
from domain.audit.entity import AccessDecision, AuditEntry, TimedAccessContext
from domain.common.value_objects import DomainName


class TestTimedAccessContextDTO:
    """Test TimedAccessContextDTO."""

    def test_timed_access_context_dto_creation(self) -> None:
        """Test creating TimedAccessContextDTO."""
        now = datetime.now(UTC)

        dto = TimedAccessContextDTO(
            request_timestamp=now,
            processing_timestamp=now,
            timezone_offset=0,
            day_of_week=2,
            hour_of_day=14,
            is_business_hours=True,
            is_weekend=False,
            week_of_year=3,
            month_of_year=1,
            quarter_of_year=1,
        )

        assert dto.hour_of_day == 14
        assert dto.is_business_hours is True
        assert dto.quarter_of_year == 1


class TestAuditEntryDTO:
    """Test AuditEntryDTO data transfer object."""

    def test_audit_entry_dto_creation(self) -> None:
        """Test creating AuditEntryDTO."""
        entry_id = uuid4()
        tenant_id = uuid4()
        agent_id = uuid4()
        now = datetime.now(UTC)

        timed_context = TimedAccessContextDTO(
            request_timestamp=now,
            processing_timestamp=now,
            timezone_offset=0,
            day_of_week=2,
            hour_of_day=14,
            is_business_hours=True,
            is_weekend=False,
            week_of_year=3,
            month_of_year=1,
            quarter_of_year=1,
        )

        dto = AuditEntryDTO(
            entry_id=entry_id,
            tenant_id=tenant_id,
            agent_id=agent_id,
            timestamp=now,
            timestamp_nanos=1234567890,
            domain="example.com",
            decision="allow",
            reason="Policy matched",
            request_method="GET",
            request_path="/api",
            timed_access_metadata=timed_context,
            previous_hash="abc123",
            current_hash="def456",
            sequence_number=1,
        )

        assert dto.entry_id == entry_id
        assert dto.domain == "example.com"
        assert dto.decision == "allow"

    def test_audit_entry_dto_is_immutable(self) -> None:
        """Test that AuditEntryDTO is immutable."""
        now = datetime.now(UTC)
        timed_context = TimedAccessContextDTO(
            request_timestamp=now,
            processing_timestamp=now,
            timezone_offset=0,
            day_of_week=2,
            hour_of_day=14,
            is_business_hours=True,
            is_weekend=False,
            week_of_year=3,
            month_of_year=1,
            quarter_of_year=1,
        )

        dto = AuditEntryDTO(
            entry_id=uuid4(),
            tenant_id=uuid4(),
            agent_id=uuid4(),
            timestamp=now,
            timestamp_nanos=1234567890,
            domain="example.com",
            decision="allow",
            reason="",
            request_method="GET",
            request_path="/",
            timed_access_metadata=timed_context,
            previous_hash="",
            current_hash="",
            sequence_number=0,
        )

        with pytest.raises((ValidationError, AttributeError)):
            dto.domain = "new-domain.com"


class TestAuditQueryRequest:
    """Test AuditQueryRequest validation."""

    def test_audit_query_request_with_defaults(self) -> None:
        """Test AuditQueryRequest with default values."""
        request = AuditQueryRequest()
        assert request.page == 1
        assert request.page_size == 50

    def test_audit_query_request_validates_decision(self) -> None:
        """Test decision validation."""
        request = AuditQueryRequest(decision="allow")
        assert request.decision == "allow"

        # Invalid decision
        with pytest.raises(ValidationError) as exc_info:
            AuditQueryRequest(decision="invalid_decision")
        assert "invalid decision" in str(exc_info.value).lower()

    def test_audit_query_request_validates_time_range(self) -> None:
        """Test time range validation."""
        start = datetime.now(UTC)
        end = start - timedelta(hours=1)  # End before start - invalid

        with pytest.raises(ValidationError) as exc_info:
            AuditQueryRequest(start_time=start, end_time=end)
        assert "after start_time" in str(exc_info.value).lower()

    def test_audit_query_request_validates_page_values(self) -> None:
        """Test page validation."""
        # Page must be >= 1
        with pytest.raises(ValidationError):
            AuditQueryRequest(page=0)

        # Page size too large
        with pytest.raises(ValidationError):
            AuditQueryRequest(page_size=2000)


class TestAuditExportRequest:
    """Test AuditExportRequest validation."""

    def test_audit_export_request_with_valid_data(self) -> None:
        """Test valid export request."""
        tenant_id = uuid4()
        start = datetime.now(UTC)
        end = start + timedelta(days=7)

        request = AuditExportRequest(
            tenant_id=tenant_id, start_time=start, end_time=end, format="csv"
        )

        assert request.format == "csv"
        assert request.include_metadata is True

    def test_audit_export_request_validates_time_range(self) -> None:
        """Test time range validation."""
        tenant_id = uuid4()
        start = datetime.now(UTC)
        end = start - timedelta(hours=1)

        with pytest.raises(ValidationError) as exc_info:
            AuditExportRequest(tenant_id=tenant_id, start_time=start, end_time=end)
        assert "after start_time" in str(exc_info.value).lower()

    def test_audit_export_request_validates_max_range(self) -> None:
        """Test maximum export range validation."""
        tenant_id = uuid4()
        start = datetime.now(UTC)
        end = start + timedelta(days=91)  # > 90 days

        with pytest.raises(ValidationError) as exc_info:
            AuditExportRequest(tenant_id=tenant_id, start_time=start, end_time=end)
        assert (
            "too large" in str(exc_info.value).lower()
            or "maximum 90" in str(exc_info.value).lower()
        )

    def test_audit_export_request_validates_format(self) -> None:
        """Test format validation."""
        tenant_id = uuid4()
        start = datetime.now(UTC)
        end = start + timedelta(days=7)

        # Valid formats
        for fmt in ["csv", "json"]:
            request = AuditExportRequest(
                tenant_id=tenant_id, start_time=start, end_time=end, format=fmt
            )
            assert request.format == fmt

        # Invalid format
        with pytest.raises(ValidationError):
            AuditExportRequest(tenant_id=tenant_id, start_time=start, end_time=end, format="xml")


class TestAuditMapper:
    """Test AuditMapper conversion functions."""

    def test_audit_mapper_to_dto(self) -> None:
        """Test mapping AuditEntry entity to AuditEntryDTO."""
        entry = AuditEntry(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain=DomainName(value="example.com"),
            decision=AccessDecision.ALLOW,
            reason="Policy matched",
            timed_access_metadata=TimedAccessContext.create_from_timestamp(datetime.now(UTC)),
        )

        dto = AuditMapper.to_dto(entry)

        assert isinstance(dto, AuditEntryDTO)
        assert dto.entry_id == entry.entry_id
        assert dto.domain == "example.com"
        assert dto.decision == "allow"
        assert isinstance(dto.timed_access_metadata, TimedAccessContextDTO)
