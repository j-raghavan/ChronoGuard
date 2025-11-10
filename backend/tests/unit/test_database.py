"""Unit tests for core database module."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import Pool

from core.config import DatabaseSettings
from core.database import (
    DatabaseConnectionError,
    DatabaseError,
    DatabaseInitializationError,
    check_database_health,
    close_engine,
    create_engine,
    create_session_factory,
    drop_database,
    get_engine,
    get_readonly_session,
    get_session,
    get_session_factory,
    initialize_database,
)


class TestDatabaseExceptions:
    """Tests for database exception hierarchy."""

    def test_database_error_base_exception(self) -> None:
        """Test that DatabaseError is a base exception."""
        error = DatabaseError("test error")
        assert isinstance(error, Exception)
        assert str(error) == "test error"

    def test_database_connection_error(self) -> None:
        """Test DatabaseConnectionError inherits from DatabaseError."""
        error = DatabaseConnectionError("connection failed")
        assert isinstance(error, DatabaseError)
        assert str(error) == "connection failed"

    def test_database_initialization_error(self) -> None:
        """Test DatabaseInitializationError inherits from DatabaseError."""
        error = DatabaseInitializationError("initialization failed")
        assert isinstance(error, DatabaseError)
        assert str(error) == "initialization failed"


class TestCreateEngine:
    """Tests for create_engine function."""

    @patch("core.database._register_engine_events")
    @patch("core.database.create_async_engine")
    def test_create_engine_with_defaults(
        self, mock_create_async_engine: Mock, mock_register_events: Mock
    ) -> None:
        """Test engine creation with default settings."""
        mock_engine = MagicMock(spec=AsyncEngine)
        mock_create_async_engine.return_value = mock_engine

        db_settings = DatabaseSettings(
            host="localhost",
            port=5432,
            user="testuser",
            password="testpass",  # noqa: S106
            database="testdb",
        )

        engine = create_engine(database_settings=db_settings)

        assert engine == mock_engine
        mock_create_async_engine.assert_called_once()
        call_kwargs = mock_create_async_engine.call_args[1]
        assert "postgresql+asyncpg" in call_kwargs["url"]
        assert call_kwargs["pool_pre_ping"] is True
        assert call_kwargs["pool_size"] == 10
        mock_register_events.assert_called_once_with(mock_engine)

    @patch("core.database._register_engine_events")
    @patch("core.database.create_async_engine")
    def test_create_engine_with_custom_pool_class(
        self, mock_create_async_engine: Mock, mock_register_events: Mock
    ) -> None:
        """Test engine creation with custom pool class."""
        mock_engine = MagicMock(spec=AsyncEngine)
        mock_create_async_engine.return_value = mock_engine

        custom_pool_class = MagicMock(spec=Pool)
        db_settings = DatabaseSettings()

        create_engine(database_settings=db_settings, pool_class=custom_pool_class)

        call_kwargs = mock_create_async_engine.call_args[1]
        assert call_kwargs["poolclass"] == custom_pool_class

    @patch("core.database._register_engine_events")
    @patch("core.database.create_async_engine")
    def test_create_engine_with_kwargs_override(
        self, mock_create_async_engine: Mock, mock_register_events: Mock
    ) -> None:
        """Test that kwargs override default settings."""
        mock_engine = MagicMock(spec=AsyncEngine)
        mock_create_async_engine.return_value = mock_engine

        db_settings = DatabaseSettings()

        create_engine(database_settings=db_settings, pool_size=50, echo=True)

        call_kwargs = mock_create_async_engine.call_args[1]
        assert call_kwargs["pool_size"] == 50
        assert call_kwargs["echo"] is True

    @patch("core.database._register_engine_events")
    @patch("core.database.get_settings")
    @patch("core.database.create_async_engine")
    def test_create_engine_uses_global_settings_if_none(
        self, mock_create_async_engine: Mock, mock_get_settings: Mock, mock_register_events: Mock
    ) -> None:
        """Test that global settings are used when database_settings is None."""
        mock_engine = MagicMock(spec=AsyncEngine)
        mock_create_async_engine.return_value = mock_engine

        mock_settings = MagicMock()
        mock_settings.database = DatabaseSettings()
        mock_get_settings.return_value = mock_settings

        create_engine(database_settings=None)

        mock_get_settings.assert_called_once()

    @patch("core.database._register_engine_events")
    @patch("core.database.create_async_engine")
    def test_create_engine_raises_on_connection_error(
        self, mock_create_async_engine: Mock, mock_register_events: Mock
    ) -> None:
        """Test that DatabaseConnectionError is raised on engine creation failure."""
        mock_create_async_engine.side_effect = Exception("Connection refused")

        with pytest.raises(DatabaseConnectionError, match="Failed to create database engine"):
            create_engine()


class TestCreateSessionFactory:
    """Tests for create_session_factory function."""

    @patch("core.database.create_engine")
    def test_create_session_factory_with_engine(self, mock_create_engine: Mock) -> None:
        """Test session factory creation with provided engine."""
        mock_engine = MagicMock(spec=AsyncEngine)

        factory = create_session_factory(engine=mock_engine)

        assert isinstance(factory, async_sessionmaker)
        # Access factory configuration
        assert factory.kw.get("bind") == mock_engine
        assert factory.class_ == AsyncSession
        assert factory.kw["expire_on_commit"] is False
        assert factory.kw["autoflush"] is False
        assert factory.kw["autocommit"] is False
        mock_create_engine.assert_not_called()

    @patch("core.database.create_engine")
    def test_create_session_factory_creates_engine_if_none(self, mock_create_engine: Mock) -> None:
        """Test that engine is created if not provided."""
        mock_engine = MagicMock(spec=AsyncEngine)
        mock_create_engine.return_value = mock_engine

        factory = create_session_factory(engine=None)

        mock_create_engine.assert_called_once()
        assert factory.kw.get("bind") == mock_engine

    @patch("core.database.create_engine")
    def test_create_session_factory_with_custom_kwargs(self, mock_create_engine: Mock) -> None:
        """Test session factory with custom arguments."""
        mock_engine = MagicMock(spec=AsyncEngine)

        factory = create_session_factory(engine=mock_engine, expire_on_commit=True)

        assert factory.kw["expire_on_commit"] is True


class TestInitializeDatabase:
    """Tests for initialize_database function."""

    @pytest.mark.asyncio
    async def test_initialize_database_creates_extensions_and_tables(self) -> None:
        """Test database initialization creates extensions and tables."""
        mock_engine = MagicMock(spec=AsyncEngine)
        mock_conn = AsyncMock()
        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_conn
        mock_context.__aexit__.return_value = None
        mock_engine.begin.return_value = mock_context

        await initialize_database(mock_engine)

        # Verify extensions were created
        execute_calls = mock_conn.execute.call_args_list
        sql_texts = [
            call[0][0].text if hasattr(call[0][0], "text") else str(call[0][0])
            for call in execute_calls
        ]
        assert any("timescaledb" in text for text in sql_texts)
        assert any("uuid-ossp" in text for text in sql_texts)
        assert any("pg_trgm" in text for text in sql_texts)

        # Verify tables were created
        mock_conn.run_sync.assert_called_once()

        # Verify hypertable was created
        assert any("create_hypertable" in text for text in sql_texts)

    @pytest.mark.asyncio
    async def test_initialize_database_skip_extensions(self) -> None:
        """Test database initialization with extensions skipped."""
        mock_engine = MagicMock(spec=AsyncEngine)
        mock_conn = AsyncMock()
        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_conn
        mock_context.__aexit__.return_value = None
        mock_engine.begin.return_value = mock_context

        await initialize_database(mock_engine, create_extensions=False)

        # Verify extensions were NOT created
        execute_calls = mock_conn.execute.call_args_list
        sql_texts = [
            call[0][0].text if hasattr(call[0][0], "text") else str(call[0][0])
            for call in execute_calls
        ]
        assert not any("CREATE EXTENSION" in text for text in sql_texts)

    @pytest.mark.asyncio
    async def test_initialize_database_skip_tables(self) -> None:
        """Test database initialization with tables skipped."""
        mock_engine = MagicMock(spec=AsyncEngine)
        mock_conn = AsyncMock()
        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_conn
        mock_context.__aexit__.return_value = None
        mock_engine.begin.return_value = mock_context

        await initialize_database(mock_engine, create_tables=False)

        # Verify tables were NOT created
        mock_conn.run_sync.assert_not_called()

    @pytest.mark.asyncio
    async def test_initialize_database_raises_on_error(self) -> None:
        """Test that DatabaseInitializationError is raised on failure."""
        mock_engine = MagicMock(spec=AsyncEngine)
        mock_engine.begin.side_effect = Exception("Initialization failed")

        with pytest.raises(DatabaseInitializationError, match="Failed to initialize database"):
            await initialize_database(mock_engine)


class TestDropDatabase:
    """Tests for drop_database function."""

    @pytest.mark.asyncio
    async def test_drop_database_success(self) -> None:
        """Test successful database drop."""
        mock_engine = MagicMock(spec=AsyncEngine)
        mock_conn = AsyncMock()
        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_conn
        mock_context.__aexit__.return_value = None
        mock_engine.begin.return_value = mock_context

        await drop_database(mock_engine)

        mock_conn.run_sync.assert_called_once()

    @pytest.mark.asyncio
    async def test_drop_database_raises_on_error(self) -> None:
        """Test that DatabaseError is raised on drop failure."""
        mock_engine = MagicMock(spec=AsyncEngine)
        mock_engine.begin.side_effect = Exception("Drop failed")

        with pytest.raises(DatabaseError, match="Failed to drop database tables"):
            await drop_database(mock_engine)


class TestCheckDatabaseHealth:
    """Tests for check_database_health function."""

    @pytest.mark.asyncio
    async def test_check_database_health_healthy(self) -> None:
        """Test health check with healthy database."""
        mock_engine = MagicMock(spec=AsyncEngine)
        mock_conn = AsyncMock()
        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_conn
        mock_context.__aexit__.return_value = None
        mock_engine.begin.return_value = mock_context

        # Mock query results - scalar() returns regular values, not awaitable
        mock_health_result = MagicMock()
        mock_health_result.scalar.return_value = 1

        mock_version_result = MagicMock()
        mock_version_result.scalar.return_value = "PostgreSQL 16.1"

        mock_timescale_result = MagicMock()
        mock_timescale_result.scalar.return_value = "2.13.0"

        mock_conn.execute.side_effect = [
            mock_health_result,
            mock_version_result,
            mock_timescale_result,
        ]

        # Mock pool
        mock_pool = MagicMock()
        mock_pool.size.return_value = 10
        mock_pool.checkedin.return_value = 5
        mock_pool.checkedout.return_value = 5
        mock_pool.overflow.return_value = 0
        mock_engine.pool = mock_pool
        mock_engine.echo = False

        health = await check_database_health(mock_engine)

        assert health["status"] == "healthy"
        assert health["postgresql_version"] == "PostgreSQL 16.1"
        assert health["timescaledb_version"] == "2.13.0"
        assert health["pool_statistics"]["size"] == 10
        assert health["echo_enabled"] is False

    @pytest.mark.asyncio
    async def test_check_database_health_without_timescale(self) -> None:
        """Test health check when TimescaleDB is not available."""
        mock_engine = MagicMock(spec=AsyncEngine)
        mock_conn = AsyncMock()
        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_conn
        mock_context.__aexit__.return_value = None
        mock_engine.begin.return_value = mock_context

        mock_health_result = MagicMock()
        mock_health_result.scalar.return_value = 1

        mock_version_result = MagicMock()
        mock_version_result.scalar.return_value = "PostgreSQL 16.1"

        # TimescaleDB query raises exception
        mock_conn.execute.side_effect = [
            mock_health_result,
            mock_version_result,
            Exception("TimescaleDB not installed"),
        ]

        mock_pool = MagicMock()
        mock_pool.size.return_value = 10
        mock_engine.pool = mock_pool

        health = await check_database_health(mock_engine)

        assert health["status"] == "healthy"
        assert health["timescaledb_version"] is None

    @pytest.mark.asyncio
    async def test_check_database_health_unhealthy(self) -> None:
        """Test health check with unhealthy database."""
        mock_engine = MagicMock(spec=AsyncEngine)
        mock_engine.begin.side_effect = Exception("Connection refused")

        health = await check_database_health(mock_engine)

        assert health["status"] == "unhealthy"
        assert "error" in health
        assert health["error_type"] == "Exception"


class TestGetSession:
    """Tests for get_session context manager."""

    @pytest.mark.asyncio
    async def test_get_session_commits_on_success(self) -> None:
        """Test that session commits on successful completion."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_factory = MagicMock()
        mock_factory.return_value.__aenter__.return_value = mock_session
        mock_factory.return_value.__aexit__.return_value = None

        async with get_session(factory=mock_factory) as session:
            assert session == mock_session
            await session.execute(MagicMock())

        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()
        mock_session.rollback.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_session_rolls_back_on_error(self) -> None:
        """Test that session rolls back on exception."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_factory = MagicMock()
        mock_factory.return_value.__aenter__.return_value = mock_session
        mock_factory.return_value.__aexit__.return_value = None

        with pytest.raises(ValueError):
            async with get_session(factory=mock_factory) as session:
                raise ValueError("Test error")

        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()
        mock_session.commit.assert_not_called()

    @pytest.mark.asyncio
    @patch("core.database.create_session_factory")
    async def test_get_session_creates_factory_if_none(self, mock_create_factory: Mock) -> None:
        """Test that factory is created if not provided."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_factory = MagicMock()
        mock_factory.return_value.__aenter__.return_value = mock_session
        mock_factory.return_value.__aexit__.return_value = None
        mock_create_factory.return_value = mock_factory

        async with get_session(factory=None):
            pass

        mock_create_factory.assert_called_once()


class TestGetReadonlySession:
    """Tests for get_readonly_session context manager."""

    @pytest.mark.asyncio
    async def test_get_readonly_session_sets_readonly_mode(self) -> None:
        """Test that readonly session sets transaction to readonly."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_factory = MagicMock()
        mock_factory.return_value.__aenter__.return_value = mock_session
        mock_factory.return_value.__aexit__.return_value = None

        async with get_readonly_session(factory=mock_factory) as session:
            assert session == mock_session

        # Verify SET TRANSACTION READ ONLY was called
        mock_session.execute.assert_called_once()
        call_args = mock_session.execute.call_args
        # The first argument should be a text object with "READ ONLY"
        assert "READ ONLY" in str(call_args[0][0])

    @pytest.mark.asyncio
    async def test_get_readonly_session_always_rolls_back(self) -> None:
        """Test that readonly session always rolls back."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_factory = MagicMock()
        mock_factory.return_value.__aenter__.return_value = mock_session
        mock_factory.return_value.__aexit__.return_value = None

        async with get_readonly_session(factory=mock_factory):
            pass

        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()
        mock_session.commit.assert_not_called()

    @pytest.mark.asyncio
    @patch("core.database.create_session_factory")
    async def test_get_readonly_session_creates_factory_if_none(
        self, mock_create_factory: Mock
    ) -> None:
        """Test that factory is created if not provided."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_factory = MagicMock()
        mock_factory.return_value.__aenter__.return_value = mock_session
        mock_factory.return_value.__aexit__.return_value = None
        mock_create_factory.return_value = mock_factory

        async with get_readonly_session(factory=None):
            pass

        mock_create_factory.assert_called_once()


class TestGlobalEngineAndFactory:
    """Tests for global engine and factory management."""

    @patch("core.database.create_engine")
    def test_get_engine_creates_on_first_call(self, mock_create_engine: Mock) -> None:
        """Test that get_engine creates engine on first call."""
        mock_engine = MagicMock(spec=AsyncEngine)
        mock_create_engine.return_value = mock_engine

        # Reset global state
        import core.database

        core.database._engine = None

        engine = get_engine()

        assert engine == mock_engine
        mock_create_engine.assert_called_once()

    @patch("core.database.create_engine")
    def test_get_engine_returns_cached_instance(self, mock_create_engine: Mock) -> None:
        """Test that get_engine returns cached instance on subsequent calls."""
        mock_engine = MagicMock(spec=AsyncEngine)
        mock_create_engine.return_value = mock_engine

        # Reset and set global state
        import core.database

        core.database._engine = mock_engine

        engine1 = get_engine()
        engine2 = get_engine()

        assert engine1 is engine2
        # create_engine should not be called since engine already exists
        mock_create_engine.assert_not_called()

    @patch("core.database._register_engine_events")
    @patch("core.database.get_settings")
    @patch("core.database.create_async_engine")
    def test_get_engine_recreates_when_requested(
        self, mock_create_async_engine: Mock, mock_get_settings: Mock, mock_register_events: Mock
    ) -> None:
        """Test that get_engine recreates engine when recreate=True."""
        from core.config import DatabaseSettings

        mock_settings = MagicMock()
        mock_settings.database = DatabaseSettings()
        mock_get_settings.return_value = mock_settings

        mock_engine1 = MagicMock(spec=AsyncEngine)
        mock_engine2 = MagicMock(spec=AsyncEngine)
        # Only one call will be made (the recreate call)
        mock_create_async_engine.return_value = mock_engine2

        import core.database

        core.database._engine = mock_engine1

        engine = get_engine(recreate=True)

        assert engine == mock_engine2
        mock_create_async_engine.assert_called_once()

    @patch("core.database.create_session_factory")
    @patch("core.database.get_engine")
    def test_get_session_factory_creates_on_first_call(
        self, mock_get_engine: Mock, mock_create_session_factory: Mock
    ) -> None:
        """Test that get_session_factory creates factory on first call."""
        mock_engine = MagicMock(spec=AsyncEngine)
        mock_factory = MagicMock()
        mock_get_engine.return_value = mock_engine
        mock_create_session_factory.return_value = mock_factory

        # Reset global state
        import core.database

        core.database._session_factory = None

        factory = get_session_factory()

        assert factory == mock_factory
        mock_create_session_factory.assert_called_once_with(engine=mock_engine)

    @patch("core.database.create_session_factory")
    @patch("core.database.get_engine")
    def test_get_session_factory_returns_cached_instance(
        self, mock_get_engine: Mock, mock_create_session_factory: Mock
    ) -> None:
        """Test that get_session_factory returns cached instance."""
        mock_factory = MagicMock()

        # Set global state
        import core.database

        core.database._session_factory = mock_factory

        factory1 = get_session_factory()
        factory2 = get_session_factory()

        assert factory1 is factory2
        mock_create_session_factory.assert_not_called()
        mock_get_engine.assert_not_called()

    @pytest.mark.asyncio
    async def test_close_engine_disposes_and_clears_globals(self) -> None:
        """Test that close_engine disposes engine and clears globals."""
        mock_engine = AsyncMock(spec=AsyncEngine)

        # Set global state
        import core.database

        core.database._engine = mock_engine
        core.database._session_factory = MagicMock()

        await close_engine()

        mock_engine.dispose.assert_called_once()
        assert core.database._engine is None
        assert core.database._session_factory is None

    @pytest.mark.asyncio
    async def test_close_engine_handles_none_engine(self) -> None:
        """Test that close_engine handles case when engine is None."""
        import core.database

        core.database._engine = None

        # Should not raise exception
        await close_engine()


class TestRegisterEngineEvents:
    """Tests for engine event registration."""

    @patch("core.database.event.listens_for")
    @patch("core.database.create_async_engine")
    def test_register_engine_events_called(
        self, mock_create_async_engine: Mock, mock_listens_for: Mock
    ) -> None:
        """Test that engine events are registered."""
        mock_engine = MagicMock(spec=AsyncEngine)
        mock_engine.sync_engine = MagicMock()
        mock_create_async_engine.return_value = mock_engine

        create_engine()

        # Verify event.listens_for was called for connect and close events
        assert mock_listens_for.call_count >= 2

    @patch("core.database.event.listens_for")
    def test_register_engine_events_does_not_raise(self, mock_listens_for: Mock) -> None:
        """Test that _register_engine_events completes without errors."""
        from core.database import _register_engine_events

        mock_engine = MagicMock(spec=AsyncEngine)
        mock_sync_engine = MagicMock()
        mock_engine.sync_engine = mock_sync_engine

        # Should not raise any exceptions
        _register_engine_events(mock_engine)

        # Verify event.listens_for was called for connect and close events
        assert mock_listens_for.call_count >= 2
        # Verify sync_engine was accessed
        assert mock_engine.sync_engine is not None
