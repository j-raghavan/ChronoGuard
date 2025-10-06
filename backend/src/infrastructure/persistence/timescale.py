"""TimescaleDB-specific utilities and setup.

This module provides TimescaleDB hypertable creation and optimization.
Tested via integration tests with real PostgreSQL/TimescaleDB.
"""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine


async def setup_timescaledb(engine: AsyncEngine) -> None:
    """Setup TimescaleDB extension and hypertables.

    Args:
        engine: SQLAlchemy async engine

    Raises:
        Exception: If TimescaleDB extension cannot be created
    """
    async with engine.begin() as conn:
        await conn.execute(text("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE"))

        await conn.execute(
            text(
                """
                SELECT create_hypertable(
                    'audit_entries',
                    'timestamp',
                    chunk_time_interval => INTERVAL '7 days',
                    if_not_exists => TRUE
                )
            """
            )
        )

        await conn.execute(
            text(
                """
                SELECT add_compression_policy(
                    'audit_entries',
                    INTERVAL '30 days',
                    if_not_exists => TRUE
                )
            """
            )
        )

        await conn.execute(
            text(
                """
                SELECT add_retention_policy(
                    'audit_entries',
                    INTERVAL '1 year',
                    if_not_exists => TRUE
                )
            """
            )
        )
