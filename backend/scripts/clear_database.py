"""Clear all database tables for testing."""

import asyncio

from core.database import get_database_url
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine


async def clear_database() -> None:
    """Clear all tables in the database."""
    db_url = get_database_url()
    if db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

    engine = create_async_engine(db_url)

    try:
        async with engine.begin() as conn:
            await conn.execute(text("TRUNCATE TABLE audit_entries, agents, policies CASCADE"))
        print("✅ Database cleared successfully")
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(clear_database())
