"""Pytest configuration for integration tests."""

import asyncio
import os
from collections.abc import AsyncGenerator, Generator
from uuid import UUID, uuid4

import pytest
from infrastructure.persistence.models import Base
from infrastructure.persistence.timescale import setup_timescaledb
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine


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
        "postgresql+asyncpg://chronoguard:testpassword@localhost:5434/chronoguard_test",
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
        await conn.execute(text("TRUNCATE TABLE audit_entries CASCADE"))

    yield


@pytest.fixture
def test_tenant_id() -> UUID:
    """Generate test tenant ID."""
    return uuid4()


@pytest.fixture
def test_agent_id() -> UUID:
    """Generate test agent ID."""
    return uuid4()
