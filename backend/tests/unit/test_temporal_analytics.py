"""Unit tests for temporal analytics query handler."""

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

from application.queries.temporal_analytics import TemporalAnalyticsQuery, TemporalPattern
from domain.audit.entity import AccessDecision, AuditEntry, TimedAccessContext
from domain.audit.repository import AuditRepository
from domain.common.value_objects import DomainName


class TestTemporalAnalyticsQuery:
    """Test suite for temporal analytics query handler."""

    @pytest.fixture
    def mock_repository(self) -> MagicMock:
        """Create mock audit repository."""
        mock = MagicMock(spec=AuditRepository)
        mock.find_by_tenant_time_range = AsyncMock()
        return mock

    @pytest.fixture
    def analytics_query(self, mock_repository: MagicMock) -> TemporalAnalyticsQuery:
        """Create analytics query instance."""
        return TemporalAnalyticsQuery(mock_repository, cache_service=None)

    @pytest.fixture
    def test_tenant_id(self) -> UUID:
        """Generate test tenant ID."""
        return uuid4()

    @pytest.fixture
    def base_time(self) -> datetime:
        """Generate base timestamp."""
        return datetime(2024, 10, 5, 9, 0, 0, tzinfo=UTC)

    def _create_audit_entry(
        self,
        timestamp: datetime,
        decision: AccessDecision = AccessDecision.ALLOW,
        domain: str = "example.com",
        tenant_id: UUID | None = None,
    ) -> AuditEntry:
        """Create test audit entry."""
        timed_context = TimedAccessContext.create_from_timestamp(timestamp)

        return AuditEntry(
            tenant_id=tenant_id or uuid4(),
            agent_id=uuid4(),
            timestamp=timestamp,
            domain=DomainName(value=domain),
            decision=decision,
            reason="Test entry",
            request_method="GET",
            request_path="/test",
            timed_access_metadata=timed_context,
            sequence_number=0,
        )

    @pytest.mark.asyncio
    async def test_execute_with_empty_entries(
        self,
        analytics_query: TemporalAnalyticsQuery,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
        base_time: datetime,
    ) -> None:
        """Test analytics with no audit entries."""
        mock_repository.find_by_tenant_time_range.return_value = []

        result = await analytics_query.execute(
            test_tenant_id, base_time, base_time + timedelta(hours=1)
        )

        assert isinstance(result, TemporalPattern)
        assert result.tenant_id == test_tenant_id
        assert result.hourly_distribution == {}
        assert result.daily_distribution == {}
        assert result.peak_hours == []
        assert result.off_hours_activity_percentage == 0.0
        assert result.weekend_activity_percentage == 0.0
        assert result.compliance_score == 100.0

    @pytest.mark.asyncio
    async def test_hourly_distribution_analysis(
        self,
        analytics_query: TemporalAnalyticsQuery,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
        base_time: datetime,
    ) -> None:
        """Test hourly distribution calculation."""
        entries = [
            self._create_audit_entry(base_time, tenant_id=test_tenant_id),
            self._create_audit_entry(base_time + timedelta(minutes=30), tenant_id=test_tenant_id),
            self._create_audit_entry(base_time + timedelta(hours=1), tenant_id=test_tenant_id),
            self._create_audit_entry(base_time + timedelta(hours=2), tenant_id=test_tenant_id),
            self._create_audit_entry(
                base_time + timedelta(hours=2, minutes=15), tenant_id=test_tenant_id
            ),
            self._create_audit_entry(
                base_time + timedelta(hours=2, minutes=45), tenant_id=test_tenant_id
            ),
        ]
        mock_repository.find_by_tenant_time_range.return_value = entries

        result = await analytics_query.execute(
            test_tenant_id, base_time, base_time + timedelta(hours=3)
        )

        assert result.hourly_distribution[9] == 2
        assert result.hourly_distribution[10] == 1
        assert result.hourly_distribution[11] == 3

    @pytest.mark.asyncio
    async def test_peak_hours_identification(
        self,
        analytics_query: TemporalAnalyticsQuery,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
        base_time: datetime,
    ) -> None:
        """Test peak hours identification."""
        entries = []
        for i in range(5):
            entries.append(
                self._create_audit_entry(
                    base_time + timedelta(minutes=i * 10), tenant_id=test_tenant_id
                )
            )
        for i in range(3):
            entries.append(
                self._create_audit_entry(
                    base_time + timedelta(hours=1, minutes=i * 10), tenant_id=test_tenant_id
                )
            )
        for i in range(2):
            entries.append(
                self._create_audit_entry(
                    base_time + timedelta(hours=2, minutes=i * 10), tenant_id=test_tenant_id
                )
            )

        mock_repository.find_by_tenant_time_range.return_value = entries

        result = await analytics_query.execute(
            test_tenant_id, base_time, base_time + timedelta(hours=4)
        )

        assert len(result.peak_hours) == 3
        assert result.peak_hours[0] == 9
        assert result.peak_hours[1] == 10
        assert result.peak_hours[2] == 11

    @pytest.mark.asyncio
    async def test_off_hours_activity_percentage(
        self,
        analytics_query: TemporalAnalyticsQuery,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
    ) -> None:
        """Test off-hours activity calculation."""
        business_time = datetime(2024, 10, 7, 14, 0, 0, tzinfo=UTC)
        off_hour_time = datetime(2024, 10, 7, 22, 0, 0, tzinfo=UTC)

        entries = [
            self._create_audit_entry(business_time, tenant_id=test_tenant_id),
            self._create_audit_entry(
                business_time + timedelta(minutes=10), tenant_id=test_tenant_id
            ),
            self._create_audit_entry(
                business_time + timedelta(minutes=20), tenant_id=test_tenant_id
            ),
            self._create_audit_entry(off_hour_time, tenant_id=test_tenant_id),
            self._create_audit_entry(
                off_hour_time + timedelta(minutes=10), tenant_id=test_tenant_id
            ),
        ]
        mock_repository.find_by_tenant_time_range.return_value = entries

        result = await analytics_query.execute(
            test_tenant_id, business_time, off_hour_time + timedelta(hours=1)
        )

        assert result.off_hours_activity_percentage == 40.0

    @pytest.mark.asyncio
    async def test_weekend_activity_percentage(
        self,
        analytics_query: TemporalAnalyticsQuery,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
    ) -> None:
        """Test weekend activity calculation."""
        weekday_time = datetime(2024, 10, 7, 10, 0, 0, tzinfo=UTC)
        weekend_time = datetime(2024, 10, 6, 10, 0, 0, tzinfo=UTC)

        entries = [
            self._create_audit_entry(weekday_time, tenant_id=test_tenant_id),
            self._create_audit_entry(
                weekday_time + timedelta(minutes=10), tenant_id=test_tenant_id
            ),
            self._create_audit_entry(
                weekday_time + timedelta(minutes=20), tenant_id=test_tenant_id
            ),
            self._create_audit_entry(
                weekday_time + timedelta(minutes=30), tenant_id=test_tenant_id
            ),
            self._create_audit_entry(weekend_time, tenant_id=test_tenant_id),
        ]
        mock_repository.find_by_tenant_time_range.return_value = entries

        result = await analytics_query.execute(
            test_tenant_id, weekend_time, weekday_time + timedelta(hours=1)
        )

        assert result.weekend_activity_percentage == 20.0

    @pytest.mark.asyncio
    async def test_anomaly_detection_high_off_hours(
        self,
        analytics_query: TemporalAnalyticsQuery,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
    ) -> None:
        """Test anomaly detection for high off-hours activity."""
        business_time = datetime(2024, 10, 7, 14, 0, 0, tzinfo=UTC)
        off_hours_time = datetime(2024, 10, 7, 22, 0, 0, tzinfo=UTC)

        entries = []
        for i in range(6):
            entries.append(
                self._create_audit_entry(
                    business_time + timedelta(minutes=i * 5), tenant_id=test_tenant_id
                )
            )
        for i in range(4):
            entries.append(
                self._create_audit_entry(
                    off_hours_time + timedelta(minutes=i * 5), tenant_id=test_tenant_id
                )
            )

        mock_repository.find_by_tenant_time_range.return_value = entries

        result = await analytics_query.execute(
            test_tenant_id, business_time, off_hours_time + timedelta(hours=1)
        )

        high_off_hours = next(
            (a for a in result.anomalies if a["type"] == "high_off_hours_activity"), None
        )
        assert high_off_hours is not None
        assert high_off_hours["severity"] == "medium"

    @pytest.mark.asyncio
    async def test_anomaly_detection_high_denial_rate(
        self,
        analytics_query: TemporalAnalyticsQuery,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
        base_time: datetime,
    ) -> None:
        """Test anomaly detection for high denial rate."""
        entries = []
        for i in range(7):
            entries.append(
                self._create_audit_entry(
                    base_time + timedelta(minutes=i),
                    decision=AccessDecision.ALLOW,
                    tenant_id=test_tenant_id,
                )
            )
        for i in range(3):
            entries.append(
                self._create_audit_entry(
                    base_time + timedelta(minutes=10 + i),
                    decision=AccessDecision.DENY,
                    tenant_id=test_tenant_id,
                )
            )

        mock_repository.find_by_tenant_time_range.return_value = entries

        result = await analytics_query.execute(
            test_tenant_id, base_time, base_time + timedelta(hours=1)
        )

        high_denial = next((a for a in result.anomalies if a["type"] == "high_denial_rate"), None)
        assert high_denial is not None
        assert high_denial["severity"] == "high"

    @pytest.mark.asyncio
    async def test_compliance_score_perfect(
        self,
        analytics_query: TemporalAnalyticsQuery,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
    ) -> None:
        """Test compliance score with perfect compliance."""
        business_time = datetime(2024, 10, 7, 14, 0, 0, tzinfo=UTC)

        entries = [
            self._create_audit_entry(
                business_time + timedelta(minutes=i),
                decision=AccessDecision.ALLOW,
                tenant_id=test_tenant_id,
            )
            for i in range(10)
        ]

        mock_repository.find_by_tenant_time_range.return_value = entries

        result = await analytics_query.execute(
            test_tenant_id, business_time, business_time + timedelta(hours=1)
        )

        assert result.compliance_score == 100.0

    @pytest.mark.asyncio
    async def test_top_domains_identification(
        self,
        analytics_query: TemporalAnalyticsQuery,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
        base_time: datetime,
    ) -> None:
        """Test top domains by access count."""
        entries = []
        for i in range(5):
            entries.append(
                self._create_audit_entry(
                    base_time + timedelta(minutes=i), domain="domain1.com", tenant_id=test_tenant_id
                )
            )
        for i in range(3):
            entries.append(
                self._create_audit_entry(
                    base_time + timedelta(minutes=10 + i),
                    domain="domain2.com",
                    tenant_id=test_tenant_id,
                )
            )
        for i in range(2):
            entries.append(
                self._create_audit_entry(
                    base_time + timedelta(minutes=20 + i),
                    domain="domain3.com",
                    tenant_id=test_tenant_id,
                )
            )

        mock_repository.find_by_tenant_time_range.return_value = entries

        result = await analytics_query.execute(
            test_tenant_id, base_time, base_time + timedelta(hours=1)
        )

        assert len(result.top_domains) == 3
        assert result.top_domains[0]["domain"] == "domain1.com"
        assert result.top_domains[0]["count"] == 5

    @pytest.mark.asyncio
    async def test_daily_distribution_analysis(
        self,
        analytics_query: TemporalAnalyticsQuery,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
        base_time: datetime,
    ) -> None:
        """Test daily distribution calculation."""
        day1 = base_time
        day2 = base_time + timedelta(days=1)

        entries = [
            self._create_audit_entry(day1, tenant_id=test_tenant_id),
            self._create_audit_entry(day1 + timedelta(hours=1), tenant_id=test_tenant_id),
            self._create_audit_entry(day2, tenant_id=test_tenant_id),
        ]
        mock_repository.find_by_tenant_time_range.return_value = entries

        result = await analytics_query.execute(test_tenant_id, day1, day2 + timedelta(hours=1))

        assert result.daily_distribution[day1.date().isoformat()] == 2
        assert result.daily_distribution[day2.date().isoformat()] == 1

    @pytest.mark.asyncio
    async def test_execute_with_cache_hit(
        self,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
        base_time: datetime,
    ) -> None:
        """Test analytics with cache hit."""
        mock_cache = MagicMock()
        mock_cache.get = AsyncMock(
            return_value='{"tenant_id": "'
            + str(test_tenant_id)
            + '", "start_time": "2024-10-05T09:00:00+00:00", "end_time": "2024-10-05T10:00:00+00:00", "hourly_distribution": {}, "daily_distribution": {}, "peak_hours": [], "off_hours_activity_percentage": 0.0, "weekend_activity_percentage": 0.0, "top_domains": [], "anomalies": [], "compliance_score": 100.0}'
        )

        analytics_query = TemporalAnalyticsQuery(mock_repository, cache_service=mock_cache)

        result = await analytics_query.execute(
            test_tenant_id, base_time, base_time + timedelta(hours=1)
        )

        assert isinstance(result, TemporalPattern)
        mock_cache.get.assert_called_once()
        mock_repository.find_by_tenant_time_range.assert_not_called()

    @pytest.mark.asyncio
    async def test_execute_with_cache_set(
        self,
        mock_repository: MagicMock,
        test_tenant_id: UUID,
        base_time: datetime,
    ) -> None:
        """Test analytics sets cache after execution."""
        mock_cache = MagicMock()
        mock_cache.get = AsyncMock(return_value=None)
        mock_cache.set = AsyncMock()

        entries = [self._create_audit_entry(base_time, tenant_id=test_tenant_id)]
        mock_repository.find_by_tenant_time_range.return_value = entries

        analytics_query = TemporalAnalyticsQuery(mock_repository, cache_service=mock_cache)

        result = await analytics_query.execute(
            test_tenant_id, base_time, base_time + timedelta(hours=1)
        )

        assert isinstance(result, TemporalPattern)
        mock_cache.set.assert_called_once()
        call_args = mock_cache.set.call_args
        assert call_args[1]["ttl"] == 300

    def test_is_production_domain_true(self, analytics_query: TemporalAnalyticsQuery) -> None:
        """Test production domain detection - positive cases."""
        assert analytics_query._is_production_domain("prod.example.com") is True
        assert analytics_query._is_production_domain("example.production.com") is True
        assert analytics_query._is_production_domain("live.example.com") is True

    def test_is_production_domain_false(self, analytics_query: TemporalAnalyticsQuery) -> None:
        """Test production domain detection - negative cases."""
        assert analytics_query._is_production_domain("dev.example.com") is False
        assert analytics_query._is_production_domain("staging.example.com") is False
        assert analytics_query._is_production_domain("test.example.com") is False
