"""Global test configuration and fixtures for ChronoGuard."""

import asyncio
from collections.abc import Callable, Generator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest
from faker import Faker


# Global patch to prevent OpenTelemetry shutdown issues during tests
@pytest.fixture(autouse=True)
def disable_telemetry_shutdown() -> Generator[None, None, None]:
    """Prevent OpenTelemetry initialization that causes shutdown errors."""
    with (
        patch("infrastructure.observability.telemetry.TracerProvider") as mock_tracer_provider,
        patch("infrastructure.observability.telemetry.MeterProvider") as mock_meter_provider,
        patch("infrastructure.observability.telemetry.trace.set_tracer_provider"),
        patch("infrastructure.observability.telemetry.metrics.set_meter_provider"),
        patch("infrastructure.observability.telemetry.BatchSpanProcessor"),
        patch("infrastructure.observability.telemetry.ConsoleSpanExporter"),
        patch("infrastructure.observability.telemetry.OTLPSpanExporter"),
        patch("infrastructure.observability.telemetry.PrometheusMetricReader"),
        patch("infrastructure.observability.telemetry.PeriodicExportingMetricReader"),
    ):
        # Mock the providers to return objects that won't cause shutdown issues
        mock_tracer_provider.return_value = None
        mock_meter_provider.return_value = None
        yield


from core.container import DependencyContainer
from core.features import FeatureFlags, FeatureManager
from domain.agent.entity import Agent, AgentStatus
from domain.audit.entity import AccessDecision, AuditEntry, TimedAccessContext
from domain.audit.hasher import EnhancedAuditHasher
from domain.common.value_objects import DomainName, TimeRange, X509Certificate
from domain.policy.entity import (
    Policy,
    PolicyRule,
    PolicyStatus,
    RateLimit,
    RuleAction,
    RuleCondition,
    TimeRestriction,
)


# Initialize Faker
fake = Faker()
Faker.seed(42)  # For reproducible tests


# Removed deprecated event_loop fixture - pytest-asyncio handles this automatically
# with asyncio_default_fixture_loop_scope = "function" in pyproject.toml


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
    # Use a minimal self-signed certificate for testing
    return """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAMlyFqk69v+9MA0GCSqGSIb3DQEBBQUAMBQxEjAQBgNVBAMMCWxv
Y2FsaG9zdDAeFw0yNDA5MTQxMjAwMDBaFw0yNTA5MTQxMjAwMDBaMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDTwqq/iltHMTwV
QMF1dPXLvZ+VYZoLt3MHjt8xQo6Z4Q0hQ6n+7M7l6J8YMK+2HQo6J5N7LQOgX8l
A7NQd3L3AgMBAAEwDQYJKoZIhvcNAQEFBQADQQC/G7lz2J8YMK+2HQo6J5N7LQOg
X8lA7NQd3L3s7L3s7L3s7L3s7L3s7L3s7L3s7L3s7L3s7L3s7L3s7L3s7L3s
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
    # Mock the certificate for testing to avoid parsing issues
    from unittest.mock import MagicMock

    mock_cert = MagicMock(spec=X509Certificate)
    mock_cert.pem_data = test_certificate_pem
    mock_cert.is_valid_now = True
    mock_cert.days_until_expiry = 365
    mock_cert.fingerprint_sha256 = "test_fingerprint_12345"
    mock_cert.subject_common_name = "test.example.com"
    mock_cert.not_valid_after.isoformat.return_value = "2025-09-14T12:00:00Z"
    return mock_cert


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
        status=AgentStatus.PENDING,  # Default to PENDING for tests
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
        tenant_id: UUID | None = None,
        agent_id: UUID | None = None,
        name: str | None = None,
        status: AgentStatus = AgentStatus.ACTIVE,
        certificate_pem: str | None = None,
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
        tenant_id: UUID | None = None,
        policy_id: UUID | None = None,
        name: str | None = None,
        status: PolicyStatus = PolicyStatus.ACTIVE,
        priority: int = 500,
        created_by: UUID | None = None,
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
        tenant_id: UUID | None = None,
        agent_id: UUID | None = None,
        domain: str | None = None,
        decision: AccessDecision = AccessDecision.ALLOW,
        sequence_number: int = 1,
        timestamp: datetime | None = None,
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
def performance_timer() -> Any:
    """Timer utility for performance testing."""
    import time

    class Timer:
        def __init__(self) -> None:
            self.start_time: float | None = None
            self.end_time: float | None = None

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


def create_test_certificate(
    common_name: str = "test.example.com",
    organization: str = "Test Organization",
    days_valid: int = 365,
) -> str:
    """Create a valid self-signed test certificate.

    Args:
        common_name: Certificate common name (CN)
        organization: Organization name (O)
        days_valid: Number of days the certificate is valid

    Returns:
        PEM-encoded certificate string
    """
    from datetime import timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Create subject and issuer (same for self-signed)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )

    # Create certificate
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Return PEM-encoded certificate
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _get_test_cert_pem() -> str:
    """Get test certificate PEM data."""
    return create_test_certificate()
