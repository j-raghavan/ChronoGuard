"""Unit tests for Redis cache repository module."""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from core.config import RedisSettings
from infrastructure.persistence.redis.cache_repository import (
    CacheInvalidationStrategy,
    CacheRepository,
)


@pytest.fixture
def redis_settings() -> RedisSettings:
    """Create Redis settings for testing."""
    return RedisSettings(
        host="localhost",
        port=6379,
        db=0,
        max_connections=50,
        socket_timeout=5,
        socket_keepalive=True,
        decode_responses=True,
    )


@pytest.fixture
def cache_repository(redis_settings: RedisSettings) -> CacheRepository:
    """Create cache repository instance."""
    return CacheRepository(redis_settings, key_prefix="cache")


@pytest.fixture
def custom_prefix_cache(redis_settings: RedisSettings) -> CacheRepository:
    """Create cache repository with custom prefix."""
    return CacheRepository(redis_settings, key_prefix="custom")


class TestCacheInvalidationStrategy:
    """Tests for CacheInvalidationStrategy helper class."""

    def test_pattern_for_agent(self) -> None:
        """Test pattern generation for agent-related data."""
        pattern = CacheInvalidationStrategy.pattern_for_agent("agent-123")

        assert pattern == "cache:agent:agent-123:*"

    def test_pattern_for_policy(self) -> None:
        """Test pattern generation for policy-related data."""
        pattern = CacheInvalidationStrategy.pattern_for_policy("policy-456")

        assert pattern == "cache:policy:policy-456:*"

    def test_pattern_for_prefix(self) -> None:
        """Test pattern generation for prefix-based invalidation."""
        pattern = CacheInvalidationStrategy.pattern_for_prefix("user")

        assert pattern == "cache:user:*"

    def test_pattern_for_different_agents(self) -> None:
        """Test patterns are different for different agents."""
        pattern1 = CacheInvalidationStrategy.pattern_for_agent("agent-1")
        pattern2 = CacheInvalidationStrategy.pattern_for_agent("agent-2")

        assert pattern1 != pattern2
        assert "agent-1" in pattern1
        assert "agent-2" in pattern2


class TestCacheRepositoryInitialization:
    """Tests for CacheRepository initialization."""

    def test_initialization_with_defaults(self, redis_settings: RedisSettings) -> None:
        """Test initialization with default values."""
        cache = CacheRepository(redis_settings)

        assert cache._redis_settings == redis_settings
        assert cache._key_prefix == "cache"
        assert cache._redis is None
        assert cache._default_ttl == 300

    def test_initialization_with_custom_prefix(self, redis_settings: RedisSettings) -> None:
        """Test initialization with custom key prefix."""
        cache = CacheRepository(redis_settings, key_prefix="custom")

        assert cache._key_prefix == "custom"

    def test_make_key_with_default_prefix(self, cache_repository: CacheRepository) -> None:
        """Test key generation with default prefix."""
        key = cache_repository._make_key("user:123")

        assert key == "cache:user:123"

    def test_make_key_with_custom_prefix(self, custom_prefix_cache: CacheRepository) -> None:
        """Test key generation with custom prefix."""
        key = custom_prefix_cache._make_key("data")

        assert key == "custom:data"


class TestCacheRepositoryConnection:
    """Tests for CacheRepository connection management."""

    @pytest.mark.asyncio
    async def test_connect_establishes_redis_connection(
        self, cache_repository: CacheRepository
    ) -> None:
        """Test connect establishes Redis connection."""
        mock_redis = AsyncMock()

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            await cache_repository.connect()

            assert cache_repository._redis == mock_redis

    @pytest.mark.asyncio
    async def test_connect_uses_correct_settings(
        self, cache_repository: CacheRepository, redis_settings: RedisSettings
    ) -> None:
        """Test connect uses correct Redis settings."""
        with patch("redis.asyncio.from_url") as mock_from_url:
            mock_from_url.return_value = AsyncMock()

            await cache_repository.connect()

            mock_from_url.assert_called_once()
            call_args = mock_from_url.call_args
            assert call_args[0][0] == redis_settings.url

    @pytest.mark.asyncio
    async def test_connect_idempotent(self, cache_repository: CacheRepository) -> None:
        """Test multiple connects don't create new connections."""
        mock_redis = AsyncMock()

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            await cache_repository.connect()
            first_redis = cache_repository._redis

            await cache_repository.connect()
            second_redis = cache_repository._redis

            assert first_redis == second_redis

    @pytest.mark.asyncio
    async def test_disconnect_closes_connection(self, cache_repository: CacheRepository) -> None:
        """Test disconnect closes Redis connection."""
        mock_redis = AsyncMock()
        cache_repository._redis = mock_redis

        await cache_repository.disconnect()

        mock_redis.aclose.assert_called_once()
        assert cache_repository._redis is None

    @pytest.mark.asyncio
    async def test_disconnect_when_not_connected(self, cache_repository: CacheRepository) -> None:
        """Test disconnect when not connected does nothing."""
        await cache_repository.disconnect()

        assert cache_repository._redis is None


class TestCacheRepositoryGet:
    """Tests for cache repository get operation."""

    @pytest.mark.asyncio
    async def test_get_existing_value(self, cache_repository: CacheRepository) -> None:
        """Test getting an existing value from cache."""
        mock_redis = AsyncMock()
        mock_redis.get.return_value = "cached_value"
        cache_repository._redis = mock_redis

        value = await cache_repository.get("test_key")

        assert value == "cached_value"
        mock_redis.get.assert_called_once_with("cache:test_key")

    @pytest.mark.asyncio
    async def test_get_missing_value(self, cache_repository: CacheRepository) -> None:
        """Test getting a non-existent value returns None."""
        mock_redis = AsyncMock()
        mock_redis.get.return_value = None
        cache_repository._redis = mock_redis

        value = await cache_repository.get("missing_key")

        assert value is None

    @pytest.mark.asyncio
    async def test_get_auto_connect(self, cache_repository: CacheRepository) -> None:
        """Test get auto-connects if not connected."""
        mock_redis = AsyncMock()
        mock_redis.get.return_value = "value"

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            value = await cache_repository.get("key")

            assert value == "value"

    @pytest.mark.asyncio
    async def test_get_raises_on_connection_failure(
        self, cache_repository: CacheRepository
    ) -> None:
        """Test get raises error if connection fails."""
        with patch("redis.asyncio.from_url", return_value=None):
            with pytest.raises(RuntimeError, match="Redis connection not established"):
                await cache_repository.get("key")


class TestCacheRepositorySet:
    """Tests for cache repository set operation."""

    @pytest.mark.asyncio
    async def test_set_with_default_ttl(self, cache_repository: CacheRepository) -> None:
        """Test setting value with default TTL."""
        mock_redis = AsyncMock()
        cache_repository._redis = mock_redis

        await cache_repository.set("key", "value")

        mock_redis.setex.assert_called_once_with("cache:key", 300, "value")

    @pytest.mark.asyncio
    async def test_set_with_custom_ttl(self, cache_repository: CacheRepository) -> None:
        """Test setting value with custom TTL."""
        mock_redis = AsyncMock()
        cache_repository._redis = mock_redis

        await cache_repository.set("key", "value", ttl=600)

        mock_redis.setex.assert_called_once_with("cache:key", 600, "value")

    @pytest.mark.asyncio
    async def test_set_auto_connect(self, cache_repository: CacheRepository) -> None:
        """Test set auto-connects if not connected."""
        mock_redis = AsyncMock()

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            await cache_repository.set("key", "value")

            mock_redis.setex.assert_called_once()

    @pytest.mark.asyncio
    async def test_set_raises_on_connection_failure(
        self, cache_repository: CacheRepository
    ) -> None:
        """Test set raises error if connection fails."""
        with patch("redis.asyncio.from_url", return_value=None):
            with pytest.raises(RuntimeError, match="Redis connection not established"):
                await cache_repository.set("key", "value")


class TestCacheRepositoryDelete:
    """Tests for cache repository delete operation."""

    @pytest.mark.asyncio
    async def test_delete_existing_key(self, cache_repository: CacheRepository) -> None:
        """Test deleting an existing key."""
        mock_redis = AsyncMock()
        mock_redis.delete.return_value = 1
        cache_repository._redis = mock_redis

        result = await cache_repository.delete("key")

        assert result is True
        mock_redis.delete.assert_called_once_with("cache:key")

    @pytest.mark.asyncio
    async def test_delete_missing_key(self, cache_repository: CacheRepository) -> None:
        """Test deleting a non-existent key."""
        mock_redis = AsyncMock()
        mock_redis.delete.return_value = 0
        cache_repository._redis = mock_redis

        result = await cache_repository.delete("missing_key")

        assert result is False

    @pytest.mark.asyncio
    async def test_delete_auto_connect(self, cache_repository: CacheRepository) -> None:
        """Test delete auto-connects if not connected."""
        mock_redis = AsyncMock()
        mock_redis.delete.return_value = 1

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            result = await cache_repository.delete("key")

            assert result is True


class TestCacheRepositoryExists:
    """Tests for cache repository exists operation."""

    @pytest.mark.asyncio
    async def test_exists_key_present(self, cache_repository: CacheRepository) -> None:
        """Test exists returns True for existing key."""
        mock_redis = AsyncMock()
        mock_redis.exists.return_value = 1
        cache_repository._redis = mock_redis

        result = await cache_repository.exists("key")

        assert result is True
        mock_redis.exists.assert_called_once_with("cache:key")

    @pytest.mark.asyncio
    async def test_exists_key_absent(self, cache_repository: CacheRepository) -> None:
        """Test exists returns False for non-existent key."""
        mock_redis = AsyncMock()
        mock_redis.exists.return_value = 0
        cache_repository._redis = mock_redis

        result = await cache_repository.exists("missing_key")

        assert result is False


class TestCacheRepositoryBatchOperations:
    """Tests for cache repository batch operations."""

    @pytest.mark.asyncio
    async def test_get_many_existing_keys(self, cache_repository: CacheRepository) -> None:
        """Test getting multiple values at once."""
        mock_redis = AsyncMock()
        mock_redis.mget.return_value = ["value1", "value2", None]
        cache_repository._redis = mock_redis

        result = await cache_repository.get_many(["key1", "key2", "key3"])

        assert result == {"key1": "value1", "key2": "value2", "key3": None}
        mock_redis.mget.assert_called_once_with(["cache:key1", "cache:key2", "cache:key3"])

    @pytest.mark.asyncio
    async def test_get_many_empty_list(self, cache_repository: CacheRepository) -> None:
        """Test get_many with empty list returns empty dict."""
        result = await cache_repository.get_many([])

        assert result == {}

    @pytest.mark.asyncio
    async def test_set_many_with_default_ttl(self, cache_repository: CacheRepository) -> None:
        """Test setting multiple values with default TTL."""
        mock_redis = AsyncMock()
        mock_pipeline = MagicMock()
        mock_pipeline.setex = MagicMock()
        mock_pipeline.execute = AsyncMock()

        async def mock_pipeline_callable(*args, **kwargs):  # type: ignore[no-untyped-def]
            return mock_pipeline

        mock_redis.pipeline = MagicMock()
        mock_redis.pipeline.return_value.__aenter__ = mock_pipeline_callable
        mock_redis.pipeline.return_value.__aexit__ = AsyncMock(return_value=None)
        cache_repository._redis = mock_redis

        items = {"key1": "value1", "key2": "value2"}
        await cache_repository.set_many(items)

        assert mock_pipeline.setex.call_count == 2
        mock_pipeline.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_set_many_with_custom_ttl(self, cache_repository: CacheRepository) -> None:
        """Test setting multiple values with custom TTL."""
        mock_redis = AsyncMock()
        mock_pipeline = MagicMock()
        mock_pipeline.setex = MagicMock()
        mock_pipeline.execute = AsyncMock()

        async def mock_pipeline_callable(*args, **kwargs):  # type: ignore[no-untyped-def]
            return mock_pipeline

        mock_redis.pipeline = MagicMock()
        mock_redis.pipeline.return_value.__aenter__ = mock_pipeline_callable
        mock_redis.pipeline.return_value.__aexit__ = AsyncMock(return_value=None)
        cache_repository._redis = mock_redis

        items = {"key1": "value1", "key2": "value2"}
        await cache_repository.set_many(items, ttl=600)

        assert mock_pipeline.setex.call_count == 2

    @pytest.mark.asyncio
    async def test_set_many_empty_dict(self, cache_repository: CacheRepository) -> None:
        """Test set_many with empty dict does nothing."""
        mock_redis = AsyncMock()
        cache_repository._redis = mock_redis

        await cache_repository.set_many({})

        mock_redis.pipeline.assert_not_called()


class TestCacheRepositoryPatternOperations:
    """Tests for cache repository pattern-based operations."""

    @pytest.mark.asyncio
    async def test_delete_pattern(self, cache_repository: CacheRepository) -> None:
        """Test deleting keys matching a pattern."""
        mock_redis = AsyncMock()

        async def mock_scan_iter(match=None, count=None):  # type: ignore[no-untyped-def]
            """Mock async iterator for scan."""
            for key in ["cache:user:1", "cache:user:2"]:
                yield key

        mock_redis.scan_iter = mock_scan_iter
        cache_repository._redis = mock_redis

        count = await cache_repository.delete_pattern("user:*")

        assert count == 2
        assert mock_redis.delete.call_count == 2

    @pytest.mark.asyncio
    async def test_delete_pattern_no_matches(self, cache_repository: CacheRepository) -> None:
        """Test deleting pattern with no matches."""
        mock_redis = AsyncMock()

        async def mock_scan_iter(match=None, count=None):  # type: ignore[no-untyped-def]
            """Mock empty async iterator."""
            return
            yield  # type: ignore[unreachable]

        mock_redis.scan_iter = mock_scan_iter
        cache_repository._redis = mock_redis

        count = await cache_repository.delete_pattern("nonexistent:*")

        assert count == 0

    @pytest.mark.asyncio
    async def test_get_keys_count(self, cache_repository: CacheRepository) -> None:
        """Test counting keys matching a pattern."""
        mock_redis = AsyncMock()

        async def mock_scan_iter(match=None, count=None):  # type: ignore[no-untyped-def]
            """Mock async iterator for scan."""
            for key in ["cache:user:1", "cache:user:2", "cache:user:3"]:
                yield key

        mock_redis.scan_iter = mock_scan_iter
        cache_repository._redis = mock_redis

        count = await cache_repository.get_keys_count("user:*")

        assert count == 3


class TestCacheRepositoryTTLOperations:
    """Tests for cache repository TTL operations."""

    @pytest.mark.asyncio
    async def test_get_ttl_existing_key(self, cache_repository: CacheRepository) -> None:
        """Test getting TTL for existing key."""
        mock_redis = AsyncMock()
        mock_redis.ttl.return_value = 120
        cache_repository._redis = mock_redis

        ttl = await cache_repository.get_ttl("key")

        assert ttl == 120
        mock_redis.ttl.assert_called_once_with("cache:key")

    @pytest.mark.asyncio
    async def test_get_ttl_no_expiry(self, cache_repository: CacheRepository) -> None:
        """Test getting TTL for key with no expiry."""
        mock_redis = AsyncMock()
        mock_redis.ttl.return_value = -1
        cache_repository._redis = mock_redis

        ttl = await cache_repository.get_ttl("key")

        assert ttl == -1

    @pytest.mark.asyncio
    async def test_get_ttl_missing_key(self, cache_repository: CacheRepository) -> None:
        """Test getting TTL for non-existent key."""
        mock_redis = AsyncMock()
        mock_redis.ttl.return_value = -2
        cache_repository._redis = mock_redis

        ttl = await cache_repository.get_ttl("missing_key")

        assert ttl == -2

    @pytest.mark.asyncio
    async def test_expire_existing_key(self, cache_repository: CacheRepository) -> None:
        """Test setting expiry on existing key."""
        mock_redis = AsyncMock()
        mock_redis.expire.return_value = 1
        cache_repository._redis = mock_redis

        result = await cache_repository.expire("key", 600)

        assert result is True
        mock_redis.expire.assert_called_once_with("cache:key", 600)

    @pytest.mark.asyncio
    async def test_expire_missing_key(self, cache_repository: CacheRepository) -> None:
        """Test setting expiry on non-existent key."""
        mock_redis = AsyncMock()
        mock_redis.expire.return_value = 0
        cache_repository._redis = mock_redis

        result = await cache_repository.expire("missing_key", 600)

        assert result is False


class TestCacheRepositoryCounterOperations:
    """Tests for cache repository counter operations."""

    @pytest.mark.asyncio
    async def test_increment_default_amount(self, cache_repository: CacheRepository) -> None:
        """Test incrementing counter by default amount."""
        mock_redis = AsyncMock()
        mock_pipeline = MagicMock()
        mock_pipeline.incrby = MagicMock()
        mock_pipeline.execute = AsyncMock(return_value=[5, True])

        async def mock_pipeline_callable(*args, **kwargs):  # type: ignore[no-untyped-def]
            return mock_pipeline

        mock_redis.pipeline = MagicMock()
        mock_redis.pipeline.return_value.__aenter__ = mock_pipeline_callable
        mock_redis.pipeline.return_value.__aexit__ = AsyncMock(return_value=None)
        cache_repository._redis = mock_redis

        value = await cache_repository.increment("counter")

        assert value == 5
        mock_pipeline.incrby.assert_called_once_with("cache:counter", 1)

    @pytest.mark.asyncio
    async def test_increment_custom_amount(self, cache_repository: CacheRepository) -> None:
        """Test incrementing counter by custom amount."""
        mock_redis = AsyncMock()
        mock_pipeline = MagicMock()
        mock_pipeline.incrby = MagicMock()
        mock_pipeline.execute = AsyncMock(return_value=[15, True])

        async def mock_pipeline_callable(*args, **kwargs):  # type: ignore[no-untyped-def]
            return mock_pipeline

        mock_redis.pipeline = MagicMock()
        mock_redis.pipeline.return_value.__aenter__ = mock_pipeline_callable
        mock_redis.pipeline.return_value.__aexit__ = AsyncMock(return_value=None)
        cache_repository._redis = mock_redis

        value = await cache_repository.increment("counter", amount=5)

        assert value == 15
        mock_pipeline.incrby.assert_called_once_with("cache:counter", 5)

    @pytest.mark.asyncio
    async def test_increment_with_ttl(self, cache_repository: CacheRepository) -> None:
        """Test incrementing counter with TTL."""
        mock_redis = AsyncMock()
        mock_pipeline = MagicMock()
        mock_pipeline.incrby = MagicMock()
        mock_pipeline.expire = MagicMock()
        mock_pipeline.execute = AsyncMock(return_value=[1, True])

        async def mock_pipeline_callable(*args, **kwargs):  # type: ignore[no-untyped-def]
            return mock_pipeline

        mock_redis.pipeline = MagicMock()
        mock_redis.pipeline.return_value.__aenter__ = mock_pipeline_callable
        mock_redis.pipeline.return_value.__aexit__ = AsyncMock(return_value=None)
        cache_repository._redis = mock_redis

        value = await cache_repository.increment("counter", ttl=300)

        assert value == 1
        mock_pipeline.expire.assert_called_once_with("cache:counter", 300)

    @pytest.mark.asyncio
    async def test_decrement_default_amount(self, cache_repository: CacheRepository) -> None:
        """Test decrementing counter by default amount."""
        mock_redis = AsyncMock()
        mock_pipeline = MagicMock()
        mock_pipeline.decrby = MagicMock()
        mock_pipeline.execute = AsyncMock(return_value=[9, True])

        async def mock_pipeline_callable(*args, **kwargs):  # type: ignore[no-untyped-def]
            return mock_pipeline

        mock_redis.pipeline = MagicMock()
        mock_redis.pipeline.return_value.__aenter__ = mock_pipeline_callable
        mock_redis.pipeline.return_value.__aexit__ = AsyncMock(return_value=None)
        cache_repository._redis = mock_redis

        value = await cache_repository.decrement("counter")

        assert value == 9
        mock_pipeline.decrby.assert_called_once_with("cache:counter", 1)

    @pytest.mark.asyncio
    async def test_decrement_custom_amount(self, cache_repository: CacheRepository) -> None:
        """Test decrementing counter by custom amount."""
        mock_redis = AsyncMock()
        mock_pipeline = MagicMock()
        mock_pipeline.decrby = MagicMock()
        mock_pipeline.execute = AsyncMock(return_value=[5, True])

        async def mock_pipeline_callable(*args, **kwargs):  # type: ignore[no-untyped-def]
            return mock_pipeline

        mock_redis.pipeline = MagicMock()
        mock_redis.pipeline.return_value.__aenter__ = mock_pipeline_callable
        mock_redis.pipeline.return_value.__aexit__ = AsyncMock(return_value=None)
        cache_repository._redis = mock_redis

        value = await cache_repository.decrement("counter", amount=3)

        assert value == 5
        mock_pipeline.decrby.assert_called_once_with("cache:counter", 3)


class TestCacheRepositoryClearOperations:
    """Tests for cache repository clear operations."""

    @pytest.mark.asyncio
    async def test_clear_all(self, cache_repository: CacheRepository) -> None:
        """Test clearing all keys with prefix."""
        mock_redis = AsyncMock()

        async def mock_scan_iter(match=None, count=None):  # type: ignore[no-untyped-def]
            """Mock async iterator for scan."""
            for key in ["cache:key1", "cache:key2"]:
                yield key

        mock_redis.scan_iter = mock_scan_iter
        cache_repository._redis = mock_redis

        count = await cache_repository.clear_all()

        assert count == 2

    @pytest.mark.asyncio
    async def test_clear_all_empty_cache(self, cache_repository: CacheRepository) -> None:
        """Test clearing when cache is empty."""
        mock_redis = AsyncMock()

        async def mock_scan_iter(match=None, count=None):  # type: ignore[no-untyped-def]
            """Mock empty async iterator."""
            return
            yield  # type: ignore[unreachable]

        mock_redis.scan_iter = mock_scan_iter
        cache_repository._redis = mock_redis

        count = await cache_repository.clear_all()

        assert count == 0


class TestCacheRepositoryEdgeCases:
    """Tests for cache repository edge cases."""

    @pytest.mark.asyncio
    async def test_set_empty_value(self, cache_repository: CacheRepository) -> None:
        """Test setting empty string value."""
        mock_redis = AsyncMock()
        cache_repository._redis = mock_redis

        await cache_repository.set("key", "")

        mock_redis.setex.assert_called_once_with("cache:key", 300, "")

    @pytest.mark.asyncio
    async def test_get_many_single_key(self, cache_repository: CacheRepository) -> None:
        """Test get_many with single key."""
        mock_redis = AsyncMock()
        mock_redis.mget.return_value = ["value"]
        cache_repository._redis = mock_redis

        result = await cache_repository.get_many(["key"])

        assert result == {"key": "value"}

    @pytest.mark.asyncio
    async def test_set_many_single_item(self, cache_repository: CacheRepository) -> None:
        """Test set_many with single item."""
        mock_redis = AsyncMock()
        mock_pipeline = MagicMock()
        mock_pipeline.setex = MagicMock()
        mock_pipeline.execute = AsyncMock()

        async def mock_pipeline_callable(*args, **kwargs):  # type: ignore[no-untyped-def]
            return mock_pipeline

        mock_redis.pipeline = MagicMock()
        mock_redis.pipeline.return_value.__aenter__ = mock_pipeline_callable
        mock_redis.pipeline.return_value.__aexit__ = AsyncMock(return_value=None)
        cache_repository._redis = mock_redis

        await cache_repository.set_many({"key": "value"})

        mock_pipeline.setex.assert_called_once()

    @pytest.mark.asyncio
    async def test_increment_negative_amount(self, cache_repository: CacheRepository) -> None:
        """Test incrementing with negative amount."""
        mock_redis = AsyncMock()
        mock_pipeline = MagicMock()
        mock_pipeline.incrby = MagicMock()
        mock_pipeline.execute = AsyncMock(return_value=[3, True])

        async def mock_pipeline_callable(*args, **kwargs):  # type: ignore[no-untyped-def]
            return mock_pipeline

        mock_redis.pipeline = MagicMock()
        mock_redis.pipeline.return_value.__aenter__ = mock_pipeline_callable
        mock_redis.pipeline.return_value.__aexit__ = AsyncMock(return_value=None)
        cache_repository._redis = mock_redis

        value = await cache_repository.increment("counter", amount=-2)

        assert value == 3
        mock_pipeline.incrby.assert_called_once_with("cache:counter", -2)

    @pytest.mark.asyncio
    async def test_special_characters_in_key(self, cache_repository: CacheRepository) -> None:
        """Test handling special characters in keys."""
        mock_redis = AsyncMock()
        mock_redis.get.return_value = "value"
        cache_repository._redis = mock_redis

        value = await cache_repository.get("key:with:colons:and-dashes_123")

        assert value == "value"
        mock_redis.get.assert_called_once()
