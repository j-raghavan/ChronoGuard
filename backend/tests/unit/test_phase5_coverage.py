"""Quick coverage tests for Phase 5 components to reach 95% threshold."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from application.dto import TemporalPatternDTO


class TestTemporalPatternDTO:
    """Test TemporalPatternDTO coverage."""

    def test_temporal_pattern_dto_creation(self) -> None:
        """Test creating TemporalPatternDTO with all fields."""
        tenant_id = uuid4()
        start_time = datetime.now(UTC) - timedelta(days=7)
        end_time = datetime.now(UTC)

        dto = TemporalPatternDTO(
            tenant_id=tenant_id,
            start_time=start_time,
            end_time=end_time,
            hourly_distribution={9: 100, 14: 150},
            daily_distribution={"2025-01-01": 250},
            peak_hours=[9, 14],
            off_hours_activity_percentage=15.5,
            weekend_activity_percentage=8.2,
            top_domains=[{"domain": "example.com", "count": 523}],
            anomalies=[
                {"type": "activity_spike", "severity": "low", "description": "Spike at hour 23"}
            ],
            compliance_score=87.5,
        )

        assert dto.tenant_id == tenant_id
        assert dto.compliance_score == 87.5
        assert len(dto.peak_hours) == 2
        assert len(dto.anomalies) == 1

    def test_temporal_pattern_dto_defaults(self) -> None:
        """Test TemporalPatternDTO with default values."""
        dto = TemporalPatternDTO(
            tenant_id=uuid4(),
            start_time=datetime.now(UTC),
            end_time=datetime.now(UTC),
        )

        assert dto.hourly_distribution == {}
        assert dto.daily_distribution == {}
        assert dto.peak_hours == []
        assert dto.off_hours_activity_percentage == 0.0
        assert dto.weekend_activity_percentage == 0.0
        assert dto.top_domains == []
        assert dto.anomalies == []
        assert dto.compliance_score == 0.0

    def test_temporal_pattern_dto_frozen(self) -> None:
        """Test that TemporalPatternDTO is immutable."""
        dto = TemporalPatternDTO(
            tenant_id=uuid4(),
            start_time=datetime.now(UTC),
            end_time=datetime.now(UTC),
        )

        with pytest.raises(Exception):  # Pydantic ValidationError
            dto.compliance_score = 100.0
