"""Pytest configuration for integration tests."""

import asyncio
import os
from collections.abc import AsyncGenerator, Generator
from datetime import datetime, timezone, UTC
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient

# Import all models to ensure they're registered with Base.metadata
from domain.agent.entity import Agent, AgentStatus
from domain.policy.entity import Policy, PolicyRule, PolicyStatus
from infrastructure.persistence.models import AgentModel, Base, PolicyModel  # noqa: F401
from infrastructure.persistence.timescale import setup_timescaledb
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def database_url() -> str:
    """Get test database URL from environment."""
    return os.getenv(
        "TEST_DATABASE_URL",
        "postgresql+asyncpg://chronoguard:testpassword@localhost:5433/chronoguard_test",
    )


@pytest.fixture(scope="session")
def redis_url() -> str:
    """Get test Redis URL from environment."""
    return os.getenv("TEST_REDIS_URL", "redis://localhost:6380/1")


@pytest.fixture(scope="session")
async def engine(database_url: str) -> AsyncGenerator[AsyncEngine, None]:
    """Create database engine for tests."""
    engine = create_async_engine(database_url, echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    await setup_timescaledb(engine)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest.fixture
async def clean_database(engine: AsyncEngine) -> AsyncGenerator[None, None]:
    """Clean database between tests."""
    async with engine.begin() as conn:
        # Truncate all tables in correct order (respect foreign keys if any)
        await conn.execute(text("TRUNCATE TABLE audit_entries CASCADE"))
        await conn.execute(text("TRUNCATE TABLE agents CASCADE"))
        await conn.execute(text("TRUNCATE TABLE policies CASCADE"))

    yield


@pytest.fixture
def test_tenant_id() -> UUID:
    """Generate test tenant ID."""
    return uuid4()


@pytest.fixture
def test_agent_id() -> UUID:
    """Generate test agent ID."""
    return uuid4()


@pytest_asyncio.fixture
async def test_db_session(engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session."""
    async with AsyncSession(engine, expire_on_commit=False) as session:
        yield session


@pytest_asyncio.fixture
async def test_client() -> AsyncGenerator[AsyncClient, None]:
    """Create test HTTP client for API calls."""
    async with AsyncClient(base_url="http://localhost:8000", timeout=10.0) as client:
        yield client


@pytest.fixture
def sample_certificate_pem() -> str:
    """Generate sample certificate PEM for testing."""
    return """-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQDJKvZ7qJ3wLjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
UzAeFw0yNTAxMDgwMDAwMDBaFw0yNjAxMDgwMDAwMDBaMA0xCzAJBgNVBAYTAlVT
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest123456789
-----END CERTIFICATE-----"""


@pytest_asyncio.fixture
async def sample_agent(
    test_db_session: AsyncSession, test_tenant_id: UUID, sample_certificate_pem: str
) -> Agent:
    """Create sample agent with certificate for testing."""
    agent_id = uuid4()
    now = datetime.now(UTC)

    agent_model = AgentModel(
        agent_id=agent_id,
        tenant_id=test_tenant_id,
        name="test-agent",
        certificate_pem=sample_certificate_pem,
        status=AgentStatus.ACTIVE,
        policy_ids=[],
        created_at=now,
        updated_at=now,
        last_seen_at=now,
        agent_metadata={},
        version=1,
    )

    test_db_session.add(agent_model)
    await test_db_session.commit()
    await test_db_session.refresh(agent_model)

    return Agent(
        agent_id=agent_model.agent_id,
        tenant_id=agent_model.tenant_id,
        name=agent_model.name,
        certificate_pem=agent_model.certificate_pem,
        status=agent_model.status,
        policy_ids=agent_model.policy_ids,
        created_at=agent_model.created_at,
        updated_at=agent_model.updated_at,
        last_seen_at=agent_model.last_seen_at,
        metadata=agent_model.agent_metadata,
        version=agent_model.version,
    )


@pytest_asyncio.fixture
async def sample_policy(test_db_session: AsyncSession, test_tenant_id: UUID) -> Policy:
    """Create sample policy with domains for testing."""
    policy_id = uuid4()
    now = datetime.now(UTC)
    creator_id = uuid4()

    policy_model = PolicyModel(
        policy_id=policy_id,
        tenant_id=test_tenant_id,
        name="test-policy",
        description="Test policy for integration tests",
        rules=[],
        time_restrictions=None,
        rate_limits=None,
        priority=500,
        status=PolicyStatus.ACTIVE,
        allowed_domains=["example.com", "test.com"],
        blocked_domains=["blocked.com"],
        created_at=now,
        updated_at=now,
        created_by=creator_id,
        version=1,
        policy_metadata={},
    )

    test_db_session.add(policy_model)
    await test_db_session.commit()
    await test_db_session.refresh(policy_model)

    return Policy(
        policy_id=policy_model.policy_id,
        tenant_id=policy_model.tenant_id,
        name=policy_model.name,
        description=policy_model.description,
        rules=[],
        time_restrictions=None,
        rate_limits=None,
        priority=policy_model.priority,
        status=policy_model.status,
        allowed_domains=policy_model.allowed_domains,
        blocked_domains=policy_model.blocked_domains,
        created_at=policy_model.created_at,
        updated_at=policy_model.updated_at,
        created_by=policy_model.created_by,
        version=policy_model.version,
        metadata=policy_model.policy_metadata,
    )


@pytest.fixture
def sample_tenant() -> UUID:
    """Generate sample tenant ID for testing."""
    return UUID("00000000-0000-0000-0000-000000000000")
