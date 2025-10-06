"""Redis-based cache service implementation.

This implementation is tested via integration tests with real Redis.
See tests/integration/test_cache_service_integration.py
"""

import redis.asyncio as redis
from loguru import logger


class CacheService:
    """Redis-based caching service."""

    def __init__(self, redis_url: str) -> None:
        """Initialize cache service.

        Args:
            redis_url: Redis connection URL
        """
        self._redis_url = redis_url
        self._redis: redis.Redis | None = None

    async def connect(self) -> None:
        """Establish Redis connection."""
        self._redis = redis.from_url(self._redis_url, decode_responses=True)  # type: ignore[no-untyped-call]
        logger.info("Cache service connected to Redis")

    async def disconnect(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.aclose()
            self._redis = None
            logger.info("Cache service disconnected from Redis")

    async def get(self, key: str) -> str | None:
        """Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        return await self._redis.get(key)

    async def set(self, key: str, value: str, ttl: int = 300) -> None:
        """Set value in cache with TTL.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (default 5 minutes)
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        await self._redis.setex(key, ttl, value)

    async def delete(self, key: str) -> None:
        """Delete value from cache.

        Args:
            key: Cache key to delete
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        await self._redis.delete(key)

    async def exists(self, key: str) -> bool:
        """Check if key exists in cache.

        Args:
            key: Cache key to check

        Returns:
            True if key exists
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        result = await self._redis.exists(key)
        return bool(result)
