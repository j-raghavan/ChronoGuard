"""Global test configuration and fixtures for ChronoGuard."""

import asyncio
from collections.abc import Callable
from collections.abc import Generator
from datetime import UTC
from datetime import datetime
from unittest.mock import AsyncMock
from uuid import UUID
from uuid import uuid4

import pytest
from faker import Faker

from core.container import DependencyContainer
from core.features import FeatureFlags
from core.features import FeatureManager
from domain.agent.entity import Agent
from domain.agent.entity import AgentStatus
from domain.audit.entity import AccessDecision
from domain.audit.entity import AuditEntry
from domain.audit.entity import TimedAccessContext
from domain.audit.hasher import EnhancedAuditHasher
from domain.common.value_objects import DomainName
from domain.common.value_objects import TimeRange
from domain.common.value_objects import X509Certificate
from domain.policy.entity import Policy
from domain.policy.entity import PolicyRule
from domain.policy.entity import PolicyStatus
from domain.policy.entity import RateLimit
from domain.policy.entity import RuleAction
from domain.policy.entity import RuleCondition
from domain.policy.entity import TimeRestriction

# Initialize Faker
fake = Faker()
Faker.seed(42)  # For reproducible tests


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def fake_instance() -> Faker:
    """Provide a Faker instance for test data generation."""
    return fake


@pytest.fixture
def test_tenant_id() -> UUID:
    """Provide a consistent test tenant ID."""
    return UUID("00000000-0000-0000-0000-000000000001")


@pytest.fixture
def test_agent_id() -> UUID:
    """Provide a consistent test agent ID."""
    return UUID("00000000-0000-0000-0000-000000000002")


@pytest.fixture
def test_policy_id() -> UUID:
    """Provide a consistent test policy ID."""
    return UUID("00000000-0000-0000-0000-000000000003")


@pytest.fixture
def test_user_id() -> UUID:
    """Provide a consistent test user ID."""
    return UUID("00000000-0000-0000-0000-000000000004")


@pytest.fixture
def test_certificate_pem() -> str:
    """Provide a test X.509 certificate in PEM format."""
    return """-----BEGIN CERTIFICATE-----
MIIC+jCCAeKgAwIBAgIJAJYm37SFocjlMA0GCSqGSIb3DQEBBQUAMF4xCzAJBgNV
BAYTAlVTMREwDwYDVQQIEwhOZXcgWW9yazERMA8GA1UEBxMITmV3IFlvcmsxEDAO
BgNVBAoTB0Nocm9ub0dkMRswGQYDVQQDExJjaHJvbm9ndWFyZC10ZXN0LWNhMB4X
DTIzMDkxNDEyMDAwMFoXDTI0MDkxNDEyMDAwMFowXjELMAkGA1UEBhMCVVMxETAP
BgNVBAgTCE5ldyBZb3JrMREwDwYDVQQHEwhOZXcgWW9yazEQMA4GA1UEChMHQ2hy
b25vR2QxGzAZBgNVBAMTEmNocm9ub2d1YXJkLXRlc3QtY2EwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQC5g5jH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH
5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH
5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH
5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH
5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH
5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH
wIDAQABo1AwTjAdBgNVHQ4EFgQU5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8wHQYDVR0j
BBwwGoAU5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8wHQwDAYDVR0TBAUwAwEB/zANBgkq
hkiG9w0BAQUFAAOCAQEAt2YCh8jH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8q
JXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8q
JXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8q
JXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8q
JXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8q
JXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8q
-----END CERTIFICATE-----"""


@pytest.fixture
def test_secret_key() -> bytes:
    """Provide a consistent test secret key for cryptographic operations."""
    return b"test_secret_key_32_bytes_exactly"


@pytest.fixture
def test_feature_flags() -> FeatureFlags:
    """Provide test feature flags configuration."""
    return FeatureFlags(environment="testing")


@pytest.fixture
def test_feature_manager(test_feature_flags: FeatureFlags) -> FeatureManager:
    """Provide test feature manager."""
    return FeatureManager(test_feature_flags)


@pytest.fixture
def test_container(test_feature_manager: FeatureManager) -> DependencyContainer:
    """Provide test dependency injection container."""
    return DependencyContainer(test_feature_manager)


@pytest.fixture
def test_domain_name() -> DomainName:
    """Provide a test domain name."""
    return DomainName(value="example.com")


@pytest.fixture
def test_time_range() -> TimeRange:
    """Provide a test time range (business hours)."""
    return TimeRange.business_hours("UTC")


@pytest.fixture
def test_certificate(test_certificate_pem: str) -> X509Certificate:
    """Provide a test X.509 certificate."""
    return X509Certificate(pem_data=test_certificate_pem)


@pytest.fixture
def test_agent(
    test_tenant_id: UUID,
    test_agent_id: UUID,
    test_certificate: X509Certificate,
) -> Agent:
    """Provide a test agent entity."""
    return Agent(
        agent_id=test_agent_id,
        tenant_id=test_tenant_id,
        name="Test Agent",
        certificate=test_certificate,
        status=AgentStatus.ACTIVE,
    )


@pytest.fixture
def test_rule_condition() -> RuleCondition:
    """Provide a test rule condition."""
    return RuleCondition(
        field="domain",
        operator="equals",
        value="example.com",
    )


@pytest.fixture
def test_policy_rule(test_rule_condition: RuleCondition) -> PolicyRule:
    """Provide a test policy rule."""
    return PolicyRule(
        name="Test Rule",
        description="Test rule description",
        conditions=[test_rule_condition],
        action=RuleAction.ALLOW,
        priority=100,
    )


@pytest.fixture
def test_rate_limit() -> RateLimit:
    """Provide a test rate limit configuration."""
    return RateLimit(
        requests_per_minute=60,
        requests_per_hour=3600,
        requests_per_day=86400,
        burst_limit=10,
    )


@pytest.fixture
def test_time_restriction(test_time_range: TimeRange) -> TimeRestriction:
    """Provide a test time restriction."""
    return TimeRestriction(
        allowed_time_ranges=[test_time_range],
        allowed_days_of_week={0, 1, 2, 3, 4},  # Weekdays only
        timezone="UTC",
    )


@pytest.fixture
def test_policy(
    test_tenant_id: UUID,
    test_policy_id: UUID,
    test_user_id: UUID,
    test_policy_rule: PolicyRule,
) -> Policy:
    """Provide a test policy entity."""
    policy = Policy(
        policy_id=test_policy_id,
        tenant_id=test_tenant_id,
        name="Test Policy",
        description="Test policy description",
        created_by=test_user_id,
        status=PolicyStatus.ACTIVE,
        priority=500,
    )
    policy.add_rule(test_policy_rule)
    return policy


@pytest.fixture
def test_timed_access_context() -> TimedAccessContext:
    """Provide a test timed access context."""
    timestamp = datetime(2023, 9, 14, 10, 0, 0, tzinfo=UTC)  # Thursday 10 AM
    return TimedAccessContext.create_from_timestamp(timestamp)


@pytest.fixture
def test_audit_entry(
    test_tenant_id: UUID,
    test_agent_id: UUID,
    test_domain_name: DomainName,
    test_timed_access_context: TimedAccessContext,
) -> AuditEntry:
    """Provide a test audit entry."""
    return AuditEntry(
        tenant_id=test_tenant_id,
        agent_id=test_agent_id,
        domain=test_domain_name,
        decision=AccessDecision.ALLOW,
        reason="Test access allowed",
        timed_access_metadata=test_timed_access_context,
        sequence_number=1,
    )


@pytest.fixture
def test_audit_hasher(test_secret_key: bytes) -> EnhancedAuditHasher:
    """Provide a test audit hasher."""
    return EnhancedAuditHasher(test_secret_key)


# Factory fixtures for generating test data
@pytest.fixture
def agent_factory() -> Callable:
    """Factory for creating test agents."""

    def _create_agent(
        tenant_id: UUID = None,
        agent_id: UUID = None,
        name: str = None,
        status: AgentStatus = AgentStatus.ACTIVE,
        certificate_pem: str = None,
    ) -> Agent:
        return Agent(
            agent_id=agent_id or uuid4(),
            tenant_id=tenant_id or uuid4(),
            name=name or fake.user_name(),
            certificate=X509Certificate(pem_data=certificate_pem or _get_test_cert_pem()),
            status=status,
        )

    return _create_agent


@pytest.fixture
def policy_factory() -> Callable:
    """Factory for creating test policies."""

    def _create_policy(
        tenant_id: UUID = None,
        policy_id: UUID = None,
        name: str = None,
        status: PolicyStatus = PolicyStatus.ACTIVE,
        priority: int = 500,
        created_by: UUID = None,
    ) -> Policy:
        return Policy(
            policy_id=policy_id or uuid4(),
            tenant_id=tenant_id or uuid4(),
            name=name or fake.sentence(nb_words=3),
            description=fake.text(max_nb_chars=200),
            created_by=created_by or uuid4(),
            status=status,
            priority=priority,
        )

    return _create_policy


@pytest.fixture
def audit_entry_factory() -> Callable:
    """Factory for creating test audit entries."""

    def _create_audit_entry(
        tenant_id: UUID = None,
        agent_id: UUID = None,
        domain: str = None,
        decision: AccessDecision = AccessDecision.ALLOW,
        sequence_number: int = 1,
        timestamp: datetime = None,
    ) -> AuditEntry:
        timestamp = timestamp or datetime.now(UTC)
        return AuditEntry(
            tenant_id=tenant_id or uuid4(),
            agent_id=agent_id or uuid4(),
            domain=DomainName(value=domain or fake.domain_name()),
            decision=decision,
            reason=fake.sentence(),
            timed_access_metadata=TimedAccessContext.create_from_timestamp(timestamp),
            sequence_number=sequence_number,
            timestamp=timestamp,
        )

    return _create_audit_entry


# Mock repository fixtures
@pytest.fixture
def mock_agent_repository() -> AsyncMock:
    """Mock agent repository for testing."""
    from unittest.mock import AsyncMock

    return AsyncMock()


@pytest.fixture
def mock_policy_repository() -> AsyncMock:
    """Mock policy repository for testing."""
    from unittest.mock import AsyncMock

    return AsyncMock()


@pytest.fixture
def mock_audit_repository() -> AsyncMock:
    """Mock audit repository for testing."""
    from unittest.mock import AsyncMock

    return AsyncMock()


# Test data collections
@pytest.fixture
def test_agents_collection(agent_factory: Callable, test_tenant_id: UUID) -> list[Agent]:
    """Provide a collection of test agents."""
    return [
        agent_factory(tenant_id=test_tenant_id, name=f"Agent {i}", status=AgentStatus.ACTIVE)
        for i in range(5)
    ]


@pytest.fixture
def test_policies_collection(policy_factory: Callable, test_tenant_id: UUID) -> list[Policy]:
    """Provide a collection of test policies."""
    return [
        policy_factory(tenant_id=test_tenant_id, name=f"Policy {i}", priority=i * 100)
        for i in range(1, 6)
    ]


@pytest.fixture
def test_audit_entries_collection(
    audit_entry_factory: Callable, test_tenant_id: UUID, test_agent_id: UUID
) -> list[AuditEntry]:
    """Provide a collection of test audit entries."""
    entries = []
    for i in range(10):
        timestamp = datetime(2023, 9, 14, 10, i, 0, tzinfo=UTC)
        entry = audit_entry_factory(
            tenant_id=test_tenant_id,
            agent_id=test_agent_id,
            sequence_number=i + 1,
            timestamp=timestamp,
            decision=AccessDecision.ALLOW if i % 2 == 0 else AccessDecision.DENY,
        )
        entries.append(entry)
    return entries


# Performance test fixtures
@pytest.fixture
def performance_timer() -> Callable:
    """Timer utility for performance testing."""
    import time

    class Timer:
        def __init__(self) -> None:
            self.start_time = None
            self.end_time = None

        def start(self) -> None:
            self.start_time = time.perf_counter()

        def stop(self) -> None:
            self.end_time = time.perf_counter()

        @property
        def elapsed_ms(self) -> float:
            if self.start_time is None or self.end_time is None:
                return 0.0
            return (self.end_time - self.start_time) * 1000

    return Timer()


# Security test fixtures
@pytest.fixture
def security_test_data() -> dict[str, list[str]]:
    """Provide security test data for validation testing."""
    return {
        "malicious_domains": [
            "127.0.0.1",
            "localhost",
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "evil.example.com",
        ],
        "suspicious_user_agents": [
            "curl/7.68.0",
            "python-requests/2.25.1",
            "wget/1.20.3",
            "sqlmap/1.5.0",
            "nikto/2.1.6",
        ],
        "invalid_domains": [
            "",
            " ",
            ".",
            "..",
            "-.example.com",
            "example-.com",
            "too-long-" + "a" * 250 + ".com",
        ],
    }


def _get_test_cert_pem() -> str:
    """Get test certificate PEM data."""
    return """-----BEGIN CERTIFICATE-----
MIIC+jCCAeKgAwIBAgIJAJYm37SFocjlMA0GCSqGSIb3DQEBBQUAMF4xCzAJBgNV
BAYTAlVTMREwDwYDVQQIEwhOZXcgWW9yazERMA0GA1UEBxMITmV3IFlvcmsxEDAO
BgNVBAoTB0NocmBvR2QxGzAZBgNVBAMTEmNocm9ub2d1YXJkLXRlc3QtY2EwHhcN
MjMwOTE0MTIwMDAwWhcNMjQwOTE0MTIwMDAwWjBeMQswCQYDVQQGEwJVUzERMA8G
A1UECBMITmV3IFlvcmsxETAPBgNVBAcTCE5ldyBZb3JrMRAMDgYDVQQKEwdDaHJv
bm9HZDEbMBkGA1UEAxMSY2hyb25vZ3VhcmQtdGVzdC1jYTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBALmDmMfljyolcaZjRDxjR8fljyolcaZjRDxjR8fl
jyolcaZjRDxjR8fljyolcaZjRDxjR8fljyolcaZjRDxjR8fljyolcaZjRDxjR8fl
jyolcaZjRDxjR8fljyolcaZjRDxjR8fljyolcaZjRDxjR8fljyolcaZjRDxjR8fl
jyolcaZjRDxjR8fljyolcaZjRDxjR8fljyolcaZjRDxjR8fljyolcaZjRDxjR8fl
jyolcaZjRDxjR8fljyolcaZjRDxjR8fljyolcaZjRDxjR8fljyolcaZjRDxjR8fl
jyolcaZjRDxjR8fljyolcaZjRDxjR8fljyolcaZjRDxjR8fljyolcaZjRDxjR8fH
wIDAQABo1AwTjAdBgNVHQ4EFgQU5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8wHQYDVR0j
BBwwGoAU5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8wHQwDAYDVR0TBAUwAwEB/zANBgkq
hkiG9w0BAQUFAAOCAQEAt2YCh8jH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8q
JXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8q
JXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8q
JXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8q
JXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8q
JXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8qJXGmY0Q8Y0fH5Y8q
-----END CERTIFICATE-----"""
