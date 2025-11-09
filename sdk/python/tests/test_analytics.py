"""Tests for analytics API module."""

from datetime import datetime, timedelta

import pytest
import respx
from httpx import Response

from chronoguard_sdk import ChronoGuard, ChronoGuardSync
from chronoguard_sdk.exceptions import ValidationError
from chronoguard_sdk.models import TemporalPattern


class TestAnalyticsAPI:
    """Tests for async analytics API."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_get_temporal_patterns(self, base_url, tenant_id, sample_temporal_pattern):
        """Test getting temporal patterns."""
        respx.get(f"{base_url}/api/v1/audit/analytics").mock(
            return_value=Response(200, json=sample_temporal_pattern.model_dump(mode="json"))
        )

        now = datetime.utcnow()
        start_time = now - timedelta(days=7)

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.analytics.get_temporal_patterns(
                tenant_id=tenant_id,
                start_time=start_time,
                end_time=now,
            )

            assert isinstance(result, TemporalPattern)
            assert str(result.tenant_id) == tenant_id
            assert result.compliance_score == 87.5
            assert len(result.peak_hours) > 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_get_temporal_patterns_with_distributions(
        self, base_url, tenant_id, sample_temporal_pattern
    ):
        """Test temporal patterns include distribution data."""
        respx.get(f"{base_url}/api/v1/audit/analytics").mock(
            return_value=Response(200, json=sample_temporal_pattern.model_dump(mode="json"))
        )

        now = datetime.utcnow()
        start_time = now - timedelta(days=30)

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.analytics.get_temporal_patterns(
                tenant_id=tenant_id,
                start_time=start_time,
                end_time=now,
            )

            assert len(result.hourly_distribution) > 0
            assert len(result.daily_distribution) > 0
            assert result.off_hours_activity_percentage >= 0
            assert result.weekend_activity_percentage >= 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_get_temporal_patterns_with_top_domains(
        self, base_url, tenant_id, sample_temporal_pattern
    ):
        """Test temporal patterns include top domains."""
        respx.get(f"{base_url}/api/v1/audit/analytics").mock(
            return_value=Response(200, json=sample_temporal_pattern.model_dump(mode="json"))
        )

        now = datetime.utcnow()
        start_time = now - timedelta(days=7)

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.analytics.get_temporal_patterns(
                tenant_id=tenant_id,
                start_time=start_time,
                end_time=now,
            )

            assert len(result.top_domains) > 0
            assert "domain" in result.top_domains[0]
            assert "count" in result.top_domains[0]

    @pytest.mark.asyncio
    @respx.mock
    async def test_get_temporal_patterns_with_anomalies(
        self, base_url, tenant_id, sample_temporal_pattern
    ):
        """Test temporal patterns can include anomalies."""
        pattern_with_anomalies = sample_temporal_pattern.model_copy(
            update={
                "anomalies": [
                    {
                        "type": "activity_spike",
                        "severity": "low",
                        "description": "Unusual activity",
                    }
                ]
            }
        )

        respx.get(f"{base_url}/api/v1/audit/analytics").mock(
            return_value=Response(200, json=pattern_with_anomalies.model_dump(mode="json"))
        )

        now = datetime.utcnow()
        start_time = now - timedelta(days=7)

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.analytics.get_temporal_patterns(
                tenant_id=tenant_id,
                start_time=start_time,
                end_time=now,
            )

            assert len(result.anomalies) > 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_invalid_time_range(self, base_url, tenant_id):
        """Test error handling for invalid time range."""
        respx.get(f"{base_url}/api/v1/audit/analytics").mock(
            return_value=Response(400, json={"detail": "end_time must be after start_time"})
        )

        now = datetime.utcnow()
        start_time = now
        end_time = now - timedelta(days=1)  # End before start

        async with ChronoGuard(api_url=base_url) as client:
            with pytest.raises(ValidationError):
                await client.analytics.get_temporal_patterns(
                    tenant_id=tenant_id,
                    start_time=start_time,
                    end_time=end_time,
                )


class TestAnalyticsSyncAPI:
    """Tests for sync analytics API."""

    @respx.mock
    def test_sync_get_temporal_patterns(self, base_url, tenant_id, sample_temporal_pattern):
        """Test sync getting temporal patterns."""
        respx.get(f"{base_url}/api/v1/audit/analytics").mock(
            return_value=Response(200, json=sample_temporal_pattern.model_dump(mode="json"))
        )

        now = datetime.utcnow()
        start_time = now - timedelta(days=7)

        with ChronoGuardSync(api_url=base_url) as client:
            result = client.analytics.get_temporal_patterns(
                tenant_id=tenant_id,
                start_time=start_time,
                end_time=now,
            )

            assert isinstance(result, TemporalPattern)
            assert result.compliance_score > 0
