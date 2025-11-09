"""Temporal analytics for access pattern analysis."""

from collections import defaultdict
from datetime import datetime
from typing import Any
from uuid import UUID

from domain.audit.entity import AuditEntry
from domain.audit.repository import AuditRepository
from infrastructure.persistence.redis.cache_service import CacheService
from loguru import logger
from pydantic import BaseModel, Field


class TemporalPattern(BaseModel):
    """Access pattern analysis over time."""

    tenant_id: UUID
    start_time: datetime
    end_time: datetime
    hourly_distribution: dict[int, int] = Field(default_factory=dict)
    daily_distribution: dict[str, int] = Field(default_factory=dict)
    peak_hours: list[int] = Field(default_factory=list)
    off_hours_activity_percentage: float = 0.0
    weekend_activity_percentage: float = 0.0
    top_domains: list[dict[str, Any]] = Field(default_factory=list)
    anomalies: list[dict[str, Any]] = Field(default_factory=list)
    compliance_score: float = 0.0


class TemporalAnalyticsQuery:
    """Query handler for temporal analytics."""

    def __init__(
        self, audit_repository: AuditRepository, cache_service: CacheService | None = None
    ) -> None:
        """Initialize temporal analytics query.

        Args:
            audit_repository: Repository for audit data
            cache_service: Optional cache service for results
        """
        self.audit_repository = audit_repository
        self.cache = cache_service

    async def execute(
        self, tenant_id: UUID, start_time: datetime, end_time: datetime
    ) -> TemporalPattern:
        """Execute temporal analytics query.

        Args:
            tenant_id: Tenant to analyze
            start_time: Start of analysis period
            end_time: End of analysis period

        Returns:
            Temporal pattern analysis
        """
        # Check cache if available
        if self.cache:
            cache_key = f"temporal:{tenant_id}:{start_time.isoformat()}:{end_time.isoformat()}"
            cached = await self.cache.get(cache_key)
            if cached:
                return TemporalPattern.model_validate_json(cached)

        entries = await self.audit_repository.find_by_tenant_time_range(
            tenant_id, start_time, end_time, limit=100000
        )

        if not entries:
            return self._empty_pattern(tenant_id, start_time, end_time)

        logger.info(f"Analyzing {len(entries)} audit entries for temporal patterns")

        pattern = TemporalPattern(tenant_id=tenant_id, start_time=start_time, end_time=end_time)

        hourly_dist: dict[int, int] = defaultdict(int)
        daily_dist: dict[str, int] = defaultdict(int)

        self._analyze_hourly_distribution(entries, hourly_dist)
        self._analyze_daily_distribution(entries, daily_dist)

        pattern.hourly_distribution = dict(hourly_dist)
        pattern.daily_distribution = dict(daily_dist)

        self._identify_peak_hours(pattern)
        self._calculate_off_hours_activity(entries, pattern)
        self._calculate_weekend_activity(entries, pattern)
        self._detect_anomalies(entries, pattern)
        self._calculate_compliance_score(entries, pattern)
        self._identify_top_domains(entries, pattern)

        # Cache results if cache is available
        if self.cache:
            cache_key = f"temporal:{tenant_id}:{start_time.isoformat()}:{end_time.isoformat()}"
            await self.cache.set(cache_key, pattern.model_dump_json(), ttl=300)

        return pattern

    def _analyze_hourly_distribution(
        self, entries: list[AuditEntry], hourly_dist: dict[int, int]
    ) -> None:
        """Analyze hourly access distribution."""
        for entry in entries:
            hour = entry.timestamp.hour
            hourly_dist[hour] += 1

    def _analyze_daily_distribution(
        self, entries: list[AuditEntry], daily_dist: dict[str, int]
    ) -> None:
        """Analyze daily access distribution."""
        for entry in entries:
            day = entry.timestamp.date().isoformat()
            daily_dist[day] += 1

    def _identify_peak_hours(self, pattern: TemporalPattern) -> None:
        """Identify peak activity hours."""
        if not pattern.hourly_distribution:
            return

        sorted_hours = sorted(pattern.hourly_distribution.items(), key=lambda x: x[1], reverse=True)
        pattern.peak_hours = [hour for hour, _ in sorted_hours[:3]]

    def _calculate_off_hours_activity(
        self, entries: list[AuditEntry], pattern: TemporalPattern
    ) -> None:
        """Calculate percentage of off-hours activity."""
        if not entries:
            return

        # Business hours: 9 AM - 5 PM (Mon-Fri)
        off_hours_count = sum(
            1
            for entry in entries
            if entry.timestamp.hour < 9
            or entry.timestamp.hour >= 17
            or entry.timestamp.weekday() >= 5
        )
        pattern.off_hours_activity_percentage = (
            (off_hours_count / len(entries)) * 100 if entries else 0
        )

    def _calculate_weekend_activity(
        self, entries: list[AuditEntry], pattern: TemporalPattern
    ) -> None:
        """Calculate percentage of weekend activity."""
        if not entries:
            return

        # Weekend: Saturday (5) and Sunday (6)
        weekend_count = sum(1 for entry in entries if entry.timestamp.weekday() >= 5)
        pattern.weekend_activity_percentage = (weekend_count / len(entries)) * 100 if entries else 0

    def _detect_anomalies(self, entries: list[AuditEntry], pattern: TemporalPattern) -> None:
        """Detect temporal anomalies."""
        anomalies = []

        if pattern.off_hours_activity_percentage > 30:
            desc = f"{pattern.off_hours_activity_percentage:.1f}% during off-hours"
            anomalies.append(
                {"type": "high_off_hours_activity", "severity": "medium", "description": desc}
            )

        if pattern.weekend_activity_percentage > 20:
            desc = f"{pattern.weekend_activity_percentage:.1f}% on weekends"
            anomalies.append(
                {"type": "high_weekend_activity", "severity": "medium", "description": desc}
            )

        if pattern.hourly_distribution:
            avg_hourly = sum(pattern.hourly_distribution.values()) / max(
                len(pattern.hourly_distribution), 1
            )
            for hour, count in pattern.hourly_distribution.items():
                if count > avg_hourly * 3:
                    anomalies.append(
                        {
                            "type": "activity_spike",
                            "severity": "low",
                            "description": f"Unusual activity spike at hour {hour}",
                            "hour": str(hour),
                            "count": str(count),
                        }
                    )

        denied_entries = [e for e in entries if e.is_access_denied()]
        if denied_entries and len(denied_entries) / len(entries) > 0.1:
            anomalies.append(
                {
                    "type": "high_denial_rate",
                    "severity": "high",
                    "description": f"{len(denied_entries)/len(entries)*100:.1f}% denial rate",
                    "denied_count": str(len(denied_entries)),
                }
            )

        pattern.anomalies = anomalies

    def _calculate_compliance_score(
        self, entries: list[AuditEntry], pattern: TemporalPattern
    ) -> None:
        """Calculate compliance score based on temporal patterns."""
        if not entries:
            pattern.compliance_score = 100.0
            return

        score = 100.0
        score -= min(pattern.off_hours_activity_percentage * 0.5, 30)
        score -= min(pattern.weekend_activity_percentage * 0.5, 20)

        denied_count = sum(1 for e in entries if e.is_access_denied())
        denial_rate = (denied_count / len(entries)) * 100
        score -= min(denial_rate * 2, 30)

        high_severity_anomalies = sum(1 for a in pattern.anomalies if a.get("severity") == "high")
        score -= high_severity_anomalies * 10

        pattern.compliance_score = max(score, 0.0)

    def _identify_top_domains(self, entries: list[AuditEntry], pattern: TemporalPattern) -> None:
        """Identify most accessed domains."""
        domain_counts: dict[str, int] = defaultdict(int)

        for entry in entries:
            domain_counts[str(entry.domain)] += 1

        sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)
        pattern.top_domains = [
            {"domain": domain, "count": count} for domain, count in sorted_domains[:10]
        ]

    def _is_production_domain(self, domain: str) -> bool:
        """Check if domain is a production domain.

        Args:
            domain: Domain to check

        Returns:
            True if production domain
        """
        production_indicators = ["prod", "production", "live"]
        return any(indicator in domain.lower() for indicator in production_indicators)

    def _empty_pattern(
        self, tenant_id: UUID, start_time: datetime, end_time: datetime
    ) -> TemporalPattern:
        """Create empty temporal pattern."""
        return TemporalPattern(
            tenant_id=tenant_id,
            start_time=start_time,
            end_time=end_time,
            hourly_distribution={},
            daily_distribution={},
            peak_hours=[],
            off_hours_activity_percentage=0.0,
            weekend_activity_percentage=0.0,
            top_domains=[],
            anomalies=[],
            compliance_score=100.0,
        )
