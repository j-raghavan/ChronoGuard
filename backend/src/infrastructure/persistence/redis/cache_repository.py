"""Redis-based cache repository implementation.

This module provides a repository pattern abstraction over the cache service,
offering advanced caching capabilities including TTL management, pattern-based
invalidation, and batch operations.
"""

from __future__ import annotations

import redis.asyncio as redis
from core.config import RedisSettings
from loguru import logger


class CacheInvalidationStrategy:
    """Cache invalidation strategies for different use cases."""

    @staticmethod
    def pattern_for_agent(agent_id: str) -> str:
        """Generate cache pattern for agent-related data.

        Args:
            agent_id: Agent identifier

        Returns:
            Redis key pattern for agent data
        """
        return f"cache:agent:{agent_id}:*"

    @staticmethod
    def pattern_for_policy(policy_id: str) -> str:
        """Generate cache pattern for policy-related data.

        Args:
            policy_id: Policy identifier

        Returns:
            Redis key pattern for policy data
        """
        return f"cache:policy:{policy_id}:*"

    @staticmethod
    def pattern_for_prefix(prefix: str) -> str:
        """Generate cache pattern for prefix-based invalidation.

        Args:
            prefix: Key prefix

        Returns:
            Redis key pattern for prefix
        """
        return f"cache:{prefix}:*"


class CacheRepository:
    """Repository pattern abstraction for Redis caching operations.

    Provides high-level caching operations with TTL support, pattern-based
    invalidation, and batch operations. Builds on top of the basic cache
    service to provide domain-specific caching capabilities.

    Example:
        cache = CacheRepository(redis_settings)
        await cache.connect()
        await cache.set("user:123", user_data, ttl=3600)
        cached_user = await cache.get("user:123")
    """

    def __init__(self, redis_settings: RedisSettings, key_prefix: str = "cache") -> None:
        """Initialize cache repository.

        Args:
            redis_settings: Redis configuration settings
            key_prefix: Prefix for all cache keys
        """
        self._redis_settings = redis_settings
        self._key_prefix = key_prefix
        self._redis: redis.Redis | None = None
        self._default_ttl = 300  # 5 minutes

    async def connect(self) -> None:
        """Establish Redis connection."""
        if self._redis is None:
            self._redis = redis.from_url(
                self._redis_settings.url,
                decode_responses=True,
                max_connections=self._redis_settings.max_connections,
                socket_timeout=self._redis_settings.socket_timeout,
                socket_keepalive=self._redis_settings.socket_keepalive,
            )  # type: ignore[no-untyped-call]
            logger.info("Cache repository connected to Redis")

    async def disconnect(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.aclose()
            self._redis = None
            logger.info("Cache repository disconnected from Redis")

    def _make_key(self, key: str) -> str:
        """Generate full Redis key with prefix.

        Args:
            key: Cache key

        Returns:
            Prefixed Redis key
        """
        return f"{self._key_prefix}:{key}"

    async def get(self, key: str) -> str | None:
        """Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found

        Raises:
            RuntimeError: If Redis connection not established
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        full_key = self._make_key(key)
        value = await self._redis.get(full_key)

        if value:
            logger.debug(f"Cache hit: {key}")
        else:
            logger.debug(f"Cache miss: {key}")

        return value

    async def set(self, key: str, value: str, ttl: int | None = None) -> None:
        """Set value in cache with optional TTL.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (None for default)

        Raises:
            RuntimeError: If Redis connection not established
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        full_key = self._make_key(key)
        effective_ttl = ttl if ttl is not None else self._default_ttl

        await self._redis.setex(full_key, effective_ttl, value)
        logger.debug(f"Cached: {key} (TTL: {effective_ttl}s)")

    async def delete(self, key: str) -> bool:
        """Delete value from cache.

        Args:
            key: Cache key to delete

        Returns:
            True if key was deleted, False if key didn't exist

        Raises:
            RuntimeError: If Redis connection not established
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        full_key = self._make_key(key)
        result = await self._redis.delete(full_key)
        deleted = bool(result)

        if deleted:
            logger.debug(f"Deleted cache key: {key}")

        return deleted

    async def exists(self, key: str) -> bool:
        """Check if key exists in cache.

        Args:
            key: Cache key to check

        Returns:
            True if key exists, False otherwise

        Raises:
            RuntimeError: If Redis connection not established
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        full_key = self._make_key(key)
        result = await self._redis.exists(full_key)
        return bool(result)

    async def get_many(self, keys: list[str]) -> dict[str, str | None]:
        """Get multiple values from cache in a single operation.

        Args:
            keys: List of cache keys to retrieve

        Returns:
            Dictionary mapping keys to values (None for missing keys)

        Raises:
            RuntimeError: If Redis connection not established
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        if not keys:
            return {}

        full_keys = [self._make_key(key) for key in keys]
        values = await self._redis.mget(full_keys)

        result = dict(zip(keys, values, strict=True))
        logger.debug(f"Retrieved {len(keys)} keys from cache")

        return result

    async def set_many(self, items: dict[str, str], ttl: int | None = None) -> None:
        """Set multiple values in cache in a single operation.

        Args:
            items: Dictionary of key-value pairs to cache
            ttl: Time-to-live in seconds (None for default)

        Raises:
            RuntimeError: If Redis connection not established
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        if not items:
            return

        effective_ttl = ttl if ttl is not None else self._default_ttl

        # Use pipeline for atomic batch operations
        async with self._redis.pipeline() as pipe:
            for key, value in items.items():
                full_key = self._make_key(key)
                pipe.setex(full_key, effective_ttl, value)

            await pipe.execute()

        logger.debug(f"Cached {len(items)} items (TTL: {effective_ttl}s)")

    async def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching a pattern.

        Args:
            pattern: Redis key pattern (e.g., "user:*")

        Returns:
            Number of keys deleted

        Raises:
            RuntimeError: If Redis connection not established

        Note:
            Use with caution in production as SCAN operations can be expensive.
            Consider using specific key deletion when possible.
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        full_pattern = self._make_key(pattern)
        deleted_count = 0

        # Use SCAN to avoid blocking Redis
        async for key in self._redis.scan_iter(match=full_pattern, count=100):
            await self._redis.delete(key)
            deleted_count += 1

        logger.info(f"Deleted {deleted_count} keys matching pattern: {pattern}")
        return deleted_count

    async def get_ttl(self, key: str) -> int:
        """Get remaining TTL for a key.

        Args:
            key: Cache key

        Returns:
            Remaining TTL in seconds, -1 if no expiry, -2 if key doesn't exist

        Raises:
            RuntimeError: If Redis connection not established
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        full_key = self._make_key(key)
        return await self._redis.ttl(full_key)

    async def expire(self, key: str, ttl: int) -> bool:
        """Set or update TTL for an existing key.

        Args:
            key: Cache key
            ttl: New TTL in seconds

        Returns:
            True if TTL was set, False if key doesn't exist

        Raises:
            RuntimeError: If Redis connection not established
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        full_key = self._make_key(key)
        result = await self._redis.expire(full_key, ttl)
        return bool(result)

    async def increment(self, key: str, amount: int = 1, ttl: int | None = None) -> int:
        """Increment a counter in the cache.

        Args:
            key: Cache key
            amount: Amount to increment by
            ttl: TTL in seconds for the key (only set on first increment)

        Returns:
            New counter value after increment

        Raises:
            RuntimeError: If Redis connection not established
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        full_key = self._make_key(key)

        # Use pipeline for atomic increment and TTL operations
        async with self._redis.pipeline() as pipe:
            pipe.incrby(full_key, amount)

            # Set TTL only if specified and key is new
            if ttl is not None:
                pipe.expire(full_key, ttl)

            results = await pipe.execute()

        new_value = results[0]
        logger.debug(f"Incremented {key} by {amount} to {new_value}")

        return new_value

    async def decrement(self, key: str, amount: int = 1, ttl: int | None = None) -> int:
        """Decrement a counter in the cache.

        Args:
            key: Cache key
            amount: Amount to decrement by
            ttl: TTL in seconds for the key (only set on first decrement)

        Returns:
            New counter value after decrement

        Raises:
            RuntimeError: If Redis connection not established
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        full_key = self._make_key(key)

        # Use pipeline for atomic decrement and TTL operations
        async with self._redis.pipeline() as pipe:
            pipe.decrby(full_key, amount)

            # Set TTL only if specified
            if ttl is not None:
                pipe.expire(full_key, ttl)

            results = await pipe.execute()

        new_value = results[0]
        logger.debug(f"Decremented {key} by {amount} to {new_value}")

        return new_value

    async def clear_all(self) -> int:
        """Clear all keys with the configured prefix.

        Returns:
            Number of keys deleted

        Raises:
            RuntimeError: If Redis connection not established

        Warning:
            This operation deletes all keys with the configured prefix.
            Use with extreme caution in production environments.
        """
        return await self.delete_pattern("*")

    async def get_keys_count(self, pattern: str = "*") -> int:
        """Count keys matching a pattern.

        Args:
            pattern: Redis key pattern (e.g., "user:*")

        Returns:
            Number of matching keys

        Raises:
            RuntimeError: If Redis connection not established
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        full_pattern = self._make_key(pattern)
        count = 0

        async for _ in self._redis.scan_iter(match=full_pattern, count=100):
            count += 1

        return count
