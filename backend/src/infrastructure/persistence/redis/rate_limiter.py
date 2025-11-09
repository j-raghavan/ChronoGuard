"""Redis-based rate limiter implementation.

This module provides rate limiting functionality using Redis for distributed
rate limiting across multiple instances. Supports both token bucket and
sliding window algorithms for flexible rate limiting strategies.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import NamedTuple

import redis.asyncio as redis
from core.config import RedisSettings
from loguru import logger


class RateLimitAlgorithm(str, Enum):
    """Supported rate limiting algorithms."""

    TOKEN_BUCKET = "token_bucket"  # noqa: S105
    SLIDING_WINDOW = "sliding_window"


class RateLimitResult(NamedTuple):
    """Result of a rate limit check."""

    allowed: bool
    remaining: int
    reset_at: float
    retry_after: int | None = None


class RateLimitExceededError(Exception):
    """Raised when rate limit is exceeded."""

    def __init__(self, retry_after: int) -> None:
        """Initialize rate limit exceeded error.

        Args:
            retry_after: Seconds until rate limit resets
        """
        super().__init__(f"Rate limit exceeded. Retry after {retry_after} seconds")
        self.retry_after = retry_after


class RateLimiter:
    """Redis-based rate limiter with support for multiple algorithms.

    Supports per-agent rate limiting with configurable algorithms and windows.
    Uses Redis for distributed coordination across multiple service instances.

    Example:
        limiter = RateLimiter(redis_settings)
        await limiter.connect()
        result = await limiter.check_rate_limit(
            agent_id="agent-123",
            limit=100,
            window=60
        )
    """

    def __init__(
        self,
        redis_settings: RedisSettings,
        algorithm: RateLimitAlgorithm = RateLimitAlgorithm.TOKEN_BUCKET,
    ) -> None:
        """Initialize rate limiter.

        Args:
            redis_settings: Redis configuration settings
            algorithm: Rate limiting algorithm to use
        """
        self._redis_settings = redis_settings
        self._algorithm = algorithm
        self._redis: redis.Redis | None = None
        self._key_prefix = "rate_limit"

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
            logger.info("Rate limiter connected to Redis")

    async def disconnect(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.aclose()
            self._redis = None
            logger.info("Rate limiter disconnected from Redis")

    def _get_key(self, agent_id: str) -> str:
        """Generate Redis key for agent rate limit.

        Args:
            agent_id: Agent identifier

        Returns:
            Redis key for agent's rate limit data
        """
        return f"{self._key_prefix}:{self._algorithm.value}:{agent_id}"

    async def check_rate_limit(self, agent_id: str, limit: int, window: int) -> RateLimitResult:
        """Check if request is within rate limit.

        Args:
            agent_id: Agent identifier
            limit: Maximum requests allowed in window
            window: Time window in seconds

        Returns:
            Rate limit check result with allowed status and remaining count

        Raises:
            RuntimeError: If Redis connection not established
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        if self._algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
            return await self._check_token_bucket(agent_id, limit, window)

        return await self._check_sliding_window(agent_id, limit, window)

    async def _check_token_bucket(self, agent_id: str, limit: int, window: int) -> RateLimitResult:
        """Check rate limit using token bucket algorithm.

        Args:
            agent_id: Agent identifier
            limit: Maximum tokens (requests) allowed
            window: Token refill window in seconds

        Returns:
            Rate limit check result
        """
        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        key = self._get_key(agent_id)
        current_time = time.time()

        # Lua script for atomic token bucket operations
        lua_script = """
        local key = KEYS[1]
        local limit = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local current_time = tonumber(ARGV[3])

        local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
        local tokens = tonumber(bucket[1]) or limit
        local last_refill = tonumber(bucket[2]) or current_time

        -- Calculate token refill
        local time_passed = current_time - last_refill
        local refill_amount = math.floor(time_passed * (limit / window))
        tokens = math.min(limit, tokens + refill_amount)

        if refill_amount > 0 then
            last_refill = current_time
        end

        local allowed = 0
        local retry_after = 0

        if tokens >= 1 then
            tokens = tokens - 1
            allowed = 1
            redis.call('HMSET', key, 'tokens', tokens, 'last_refill', last_refill)
            redis.call('EXPIRE', key, window * 2)
        else
            retry_after = math.ceil((1 - tokens) * (window / limit))
        end

        return {allowed, math.floor(tokens), last_refill, retry_after}
        """

        result = await self._redis.eval(lua_script, 1, key, limit, window, current_time)

        allowed = bool(result[0])
        remaining = int(result[1])
        reset_at = float(result[2]) + window
        retry_after = int(result[3]) if not allowed else None

        return RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            reset_at=reset_at,
            retry_after=retry_after,
        )

    async def _check_sliding_window(
        self, agent_id: str, limit: int, window: int
    ) -> RateLimitResult:
        """Check rate limit using sliding window algorithm.

        Args:
            agent_id: Agent identifier
            limit: Maximum requests in window
            window: Time window in seconds

        Returns:
            Rate limit check result
        """
        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        key = self._get_key(agent_id)
        current_time = time.time()
        window_start = current_time - window

        # Lua script for atomic sliding window operations
        lua_script = """
        local key = KEYS[1]
        local limit = tonumber(ARGV[1])
        local window_start = tonumber(ARGV[2])
        local current_time = tonumber(ARGV[3])
        local window = tonumber(ARGV[4])

        -- Remove old entries outside the window
        redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

        -- Count current requests in window
        local count = redis.call('ZCARD', key)

        local allowed = 0
        local retry_after = 0

        if count < limit then
            -- Add current request
            redis.call('ZADD', key, current_time, current_time)
            redis.call('EXPIRE', key, window * 2)
            allowed = 1
        else
            -- Calculate retry after based on oldest request
            local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
            if #oldest > 0 then
                retry_after = math.ceil(tonumber(oldest[2]) + window - current_time)
            end
        end

        local remaining = math.max(0, limit - count - (allowed == 1 and 1 or 0))

        return {allowed, remaining, current_time + window, retry_after}
        """

        result = await self._redis.eval(
            lua_script, 1, key, limit, window_start, current_time, window
        )

        allowed = bool(result[0])
        remaining = int(result[1])
        reset_at = float(result[2])
        retry_after = int(result[3]) if not allowed else None

        return RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            reset_at=reset_at,
            retry_after=retry_after,
        )

    async def reset_limit(self, agent_id: str) -> None:
        """Reset rate limit for an agent.

        Args:
            agent_id: Agent identifier to reset

        Raises:
            RuntimeError: If Redis connection not established
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        key = self._get_key(agent_id)
        await self._redis.delete(key)
        logger.debug(f"Reset rate limit for agent: {agent_id}")

    async def get_remaining(self, agent_id: str, limit: int, window: int) -> int:
        """Get remaining requests for an agent without consuming a token.

        Args:
            agent_id: Agent identifier
            limit: Maximum requests allowed in window
            window: Time window in seconds

        Returns:
            Number of remaining requests

        Raises:
            RuntimeError: If Redis connection not established
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        key = self._get_key(agent_id)
        current_time = time.time()

        if self._algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
            # Get current tokens without decrementing
            bucket = await self._redis.hmget(key, "tokens", "last_refill")
            tokens = int(bucket[0]) if bucket[0] else limit
            last_refill = float(bucket[1]) if bucket[1] else current_time

            # Calculate refilled tokens
            time_passed = current_time - last_refill
            refill_amount = int(time_passed * (limit / window))
            tokens = min(limit, tokens + refill_amount)

            return max(0, tokens)

        # Sliding window: count requests in current window
        window_start = current_time - window
        await self._redis.zremrangebyscore(key, "-inf", window_start)
        count = await self._redis.zcard(key)
        return max(0, limit - count)

    async def get_reset_time(self, agent_id: str, window: int) -> float:
        """Get timestamp when rate limit will reset.

        Args:
            agent_id: Agent identifier
            window: Time window in seconds

        Returns:
            Unix timestamp when rate limit resets

        Raises:
            RuntimeError: If Redis connection not established
        """
        if not self._redis:
            await self.connect()

        if self._redis is None:
            raise RuntimeError("Redis connection not established")

        key = self._get_key(agent_id)
        current_time = time.time()

        if self._algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
            bucket = await self._redis.hmget(key, "last_refill")
            last_refill = float(bucket[0]) if bucket[0] else current_time
            return last_refill + window

        return current_time + window
