"""Database configuration and session management for ChronoGuard.

This module provides async SQLAlchemy engine, session factory, and database
initialization utilities with connection pooling and health monitoring.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncGenerator
from typing import Any

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import Pool

from core.config import DatabaseSettings, get_settings
from infrastructure.persistence.models import Base


def get_database_url() -> str:
    """Get the synchronous database URL from settings.

    Returns:
        PostgreSQL sync connection string

    Example:
        >>> url = get_database_url()
        >>> assert url.startswith("postgresql://")
    """
    settings = get_settings()
    return settings.database.sync_url


class DatabaseError(Exception):
    """Base exception for database operations."""

    pass


class DatabaseConnectionError(DatabaseError):
    """Raised when database connection fails."""

    pass


class DatabaseInitializationError(DatabaseError):
    """Raised when database initialization fails."""

    pass


def create_engine(
    database_settings: DatabaseSettings | None = None,
    pool_class: type[Pool] | None = None,
    **kwargs: Any,
) -> AsyncEngine:
    """Create async SQLAlchemy engine with configuration.

    Args:
        database_settings: Database settings. Uses global settings if None.
        pool_class: Custom pool class. Uses QueuePool by default.
        **kwargs: Additional engine arguments (override settings)

    Returns:
        Configured AsyncEngine instance

    Example:
        >>> engine = create_engine()
        >>> async with engine.begin() as conn:
        ...     await conn.execute(text("SELECT 1"))
    """
    if database_settings is None:
        database_settings = get_settings().database

    # Default engine arguments
    engine_args: dict[str, Any] = {
        "url": database_settings.async_url,
        "echo": database_settings.echo,
        "pool_pre_ping": True,  # Verify connections before using
        "pool_size": database_settings.pool_size,
        "max_overflow": database_settings.max_overflow,
        "pool_timeout": database_settings.pool_timeout,
        "pool_recycle": database_settings.pool_recycle,
    }

    # Use custom pool class if provided
    if pool_class is not None:
        engine_args["poolclass"] = pool_class

    # Override with any provided kwargs
    engine_args.update(kwargs)

    try:
        engine = create_async_engine(**engine_args)
    except Exception as e:
        raise DatabaseConnectionError(f"Failed to create database engine: {e}") from e

    # Register connection event handlers
    _register_engine_events(engine)

    return engine


def create_session_factory(
    engine: AsyncEngine | None = None,
    expire_on_commit: bool = False,
    **kwargs: Any,
) -> async_sessionmaker[AsyncSession]:
    """Create async session factory.

    Args:
        engine: AsyncEngine instance. Creates new engine if None.
        expire_on_commit: Expire objects on commit. Defaults to False.
        **kwargs: Additional session factory arguments

    Returns:
        Configured async session factory

    Example:
        >>> factory = create_session_factory()
        >>> async with factory() as session:
        ...     result = await session.execute(text("SELECT 1"))
    """
    if engine is None:
        engine = create_engine()

    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=expire_on_commit,
        autoflush=False,
        autocommit=False,
        **kwargs,
    )


async def initialize_database(
    engine: AsyncEngine,
    create_tables: bool = True,
    create_extensions: bool = True,
) -> None:
    """Initialize database with schema and extensions.

    Args:
        engine: AsyncEngine instance
        create_tables: Whether to create tables. Defaults to True.
        create_extensions: Whether to create extensions. Defaults to True.

    Raises:
        DatabaseInitializationError: If initialization fails

    Example:
        >>> engine = create_engine()
        >>> await initialize_database(engine)
    """
    try:
        async with engine.begin() as conn:
            # Create PostgreSQL extensions
            if create_extensions:
                # TimescaleDB for time-series data
                await conn.execute(text("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE"))
                # UUID generation
                await conn.execute(text('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"'))
                # pg_trgm for text search
                await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))

            # Create all tables
            if create_tables:
                await conn.run_sync(Base.metadata.create_all)

                # Convert audit_entries to TimescaleDB hypertable
                await conn.execute(
                    text(
                        """
                        SELECT create_hypertable(
                            'audit_entries',
                            'timestamp',
                            if_not_exists => TRUE,
                            migrate_data => TRUE
                        )
                    """
                    )
                )

                # Create retention policy (optional, commented out by default)
                # Uncomment to automatically delete audit entries older than 90 days
                # await conn.execute(
                #     text("""
                #         SELECT add_retention_policy(
                #             'audit_entries',
                #             INTERVAL '90 days',
                #             if_not_exists => TRUE
                #         )
                #     """)
                # )

    except Exception as e:
        raise DatabaseInitializationError(f"Failed to initialize database: {e}") from e


async def drop_database(engine: AsyncEngine) -> None:
    """Drop all database tables (use with caution!).

    Args:
        engine: AsyncEngine instance

    Raises:
        DatabaseError: If drop fails

    Warning:
        This will delete ALL data. Only use in development/testing.
    """
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    except Exception as e:
        raise DatabaseError(f"Failed to drop database tables: {e}") from e


async def check_database_health(engine: AsyncEngine) -> dict[str, Any]:
    """Check database connection health and statistics.

    Args:
        engine: AsyncEngine instance

    Returns:
        Health check results with connection info

    Example:
        >>> engine = create_engine()
        >>> health = await check_database_health(engine)
        >>> assert health["status"] == "healthy"
    """
    try:
        async with engine.begin() as conn:
            # Check basic connectivity
            result = await conn.execute(text("SELECT 1 as health_check"))
            health_check = result.scalar()

            # Get PostgreSQL version
            result = await conn.execute(text("SELECT version()"))
            pg_version = result.scalar()

            # Get TimescaleDB version (if available)
            try:
                result = await conn.execute(
                    text("SELECT extversion FROM pg_extension WHERE extname='timescaledb'")
                )
                timescale_version = result.scalar()
            except Exception:
                timescale_version = None

            # Get connection pool statistics
            pool = engine.pool
            pool_stats = {
                "size": pool.size() if hasattr(pool, "size") else None,
                "checked_in": pool.checkedin() if hasattr(pool, "checkedin") else None,
                "checked_out": pool.checkedout() if hasattr(pool, "checkedout") else None,
                "overflow": pool.overflow() if hasattr(pool, "overflow") else None,
            }

            return {
                "status": "healthy" if health_check == 1 else "unhealthy",
                "postgresql_version": pg_version,
                "timescaledb_version": timescale_version,
                "pool_statistics": pool_stats,
                "echo_enabled": engine.echo,
            }

    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "error_type": type(e).__name__,
        }


@contextlib.asynccontextmanager
async def get_session(
    factory: async_sessionmaker[AsyncSession] | None = None,
) -> AsyncGenerator[AsyncSession, None]:
    """Get database session as async context manager.

    Args:
        factory: Session factory. Creates new factory if None.

    Yields:
        AsyncSession instance

    Example:
        >>> async with get_session() as session:
        ...     result = await session.execute(text("SELECT 1"))
        ...     await session.commit()
    """
    if factory is None:
        factory = create_session_factory()

    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@contextlib.asynccontextmanager
async def get_readonly_session(
    factory: async_sessionmaker[AsyncSession] | None = None,
) -> AsyncGenerator[AsyncSession, None]:
    """Get readonly database session (automatically rolls back on completion).

    Args:
        factory: Session factory. Creates new factory if None.

    Yields:
        AsyncSession instance in readonly mode

    Example:
        >>> async with get_readonly_session() as session:
        ...     result = await session.execute(text("SELECT * FROM agents"))
    """
    if factory is None:
        factory = create_session_factory()

    async with factory() as session:
        try:
            # Set transaction to readonly
            await session.execute(text("SET TRANSACTION READ ONLY"))
            yield session
        finally:
            await session.rollback()
            await session.close()


def _register_engine_events(engine: AsyncEngine) -> None:
    """Register engine event handlers for monitoring and debugging.

    Args:
        engine: AsyncEngine to register events on
    """

    @event.listens_for(engine.sync_engine, "connect")
    def receive_connect(dbapi_conn: Any, connection_record: Any) -> None:
        """Handle new database connections."""
        # Set connection parameters for better performance
        cursor = dbapi_conn.cursor()
        cursor.execute("SET TIME ZONE 'UTC'")
        cursor.close()

    @event.listens_for(engine.sync_engine, "close")
    def receive_close(dbapi_conn: Any, connection_record: Any) -> None:
        """Handle connection close events."""
        # Can be used for connection cleanup or monitoring
        pass


# Global engine and session factory (lazy initialization)
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine(recreate: bool = False) -> AsyncEngine:
    """Get or create the global database engine.

    Args:
        recreate: Force recreation of engine. Defaults to False.

    Returns:
        Global AsyncEngine instance
    """
    global _engine

    if _engine is None or recreate:
        _engine = create_engine()

    return _engine


def get_session_factory(recreate: bool = False) -> async_sessionmaker[AsyncSession]:
    """Get or create the global session factory.

    Args:
        recreate: Force recreation of factory. Defaults to False.

    Returns:
        Global async session factory
    """
    global _session_factory

    if _session_factory is None or recreate:
        _session_factory = create_session_factory(engine=get_engine())

    return _session_factory


async def close_engine() -> None:
    """Close and dispose of the global database engine.

    Should be called during application shutdown.
    """
    global _engine, _session_factory

    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
