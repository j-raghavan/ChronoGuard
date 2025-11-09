"""Pytest configuration and fixtures for ChronoGuard SDK tests."""

import uuid
from datetime import datetime, timedelta
from typing import Any

import httpx
import pytest
import respx
from chronoguard_sdk.models import (
    Agent,
    AgentListResponse,
    AuditEntry,
    AuditListResponse,
    Policy,
    PolicyListResponse,
    TemporalPattern,
    TimedAccessContext,
)


@pytest.fixture
def base_url():
    """Base URL for API requests."""
    return "http://test-api.example.com"


@pytest.fixture
def tenant_id():
    """Test tenant ID."""
    return str(uuid.uuid4())


@pytest.fixture
def user_id():
    """Test user ID."""
    return str(uuid.uuid4())


@pytest.fixture
def agent_id():
    """Test agent ID."""
    return str(uuid.uuid4())


@pytest.fixture
def policy_id():
    """Test policy ID."""
    return str(uuid.uuid4())


@pytest.fixture
def sample_agent(agent_id, tenant_id):
    """Sample agent data."""
    now = datetime.utcnow()
    return Agent(
        agent_id=agent_id,
        tenant_id=tenant_id,
        name="test-agent",
        status="active",
        certificate_fingerprint="sha256:abc123",
        certificate_subject="CN=test-agent",
        certificate_expiry=now + timedelta(days=365),
        policy_ids=[],
        created_at=now,
        updated_at=now,
        last_seen_at=now,
        metadata={"env": "test"},
        version=1,
    )


@pytest.fixture
def sample_policy(policy_id, tenant_id, user_id):
    """Sample policy data."""
    now = datetime.utcnow()
    return Policy(
        policy_id=policy_id,
        tenant_id=tenant_id,
        name="test-policy",
        description="Test policy",
        rules=[],
        priority=500,
        status="active",
        allowed_domains=["example.com"],
        blocked_domains=[],
        created_at=now,
        updated_at=now,
        created_by=user_id,
        version=1,
        metadata={},
    )


@pytest.fixture
def sample_audit_entry(tenant_id, agent_id):
    """Sample audit entry data."""
    now = datetime.utcnow()
    return AuditEntry(
        entry_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        agent_id=agent_id,
        timestamp=now,
        timestamp_nanos=int(now.timestamp() * 1e9),
        domain="example.com",
        decision="allow",
        reason="Policy matched",
        request_method="GET",
        request_path="/api/test",
        timed_access_metadata=TimedAccessContext(
            request_timestamp=now,
            processing_timestamp=now,
            timezone_offset=0,
            day_of_week=1,
            hour_of_day=14,
            is_business_hours=True,
            is_weekend=False,
            week_of_year=1,
            month_of_year=1,
            quarter_of_year=1,
        ),
        previous_hash="abc123",
        current_hash="def456",
        sequence_number=1,
    )


@pytest.fixture
def sample_temporal_pattern(tenant_id):
    """Sample temporal pattern data."""
    now = datetime.utcnow()
    return TemporalPattern(
        tenant_id=tenant_id,
        start_time=now - timedelta(days=7),
        end_time=now,
        hourly_distribution={9: 100, 10: 150, 14: 120},
        daily_distribution={"2025-01-01": 45, "2025-01-02": 67},
        peak_hours=[9, 10, 14],
        off_hours_activity_percentage=15.5,
        weekend_activity_percentage=8.2,
        top_domains=[{"domain": "example.com", "count": 500}],
        anomalies=[],
        compliance_score=87.5,
    )


@pytest.fixture
def mock_http():
    """Mock HTTP client for testing."""
    with respx.mock(base_url="http://test-api.example.com") as respx_mock:
        yield respx_mock
