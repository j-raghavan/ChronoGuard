"""Unit tests for Redis rate limiter module."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from core.config import RedisSettings
from infrastructure.persistence.redis.rate_limiter import (
    RateLimitAlgorithm,
    RateLimiter,
    RateLimitExceededError,
    RateLimitResult,
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
def token_bucket_limiter(redis_settings: RedisSettings) -> RateLimiter:
    """Create token bucket rate limiter instance."""
    return RateLimiter(redis_settings, algorithm=RateLimitAlgorithm.TOKEN_BUCKET)


@pytest.fixture
def sliding_window_limiter(redis_settings: RedisSettings) -> RateLimiter:
    """Create sliding window rate limiter instance."""
    return RateLimiter(redis_settings, algorithm=RateLimitAlgorithm.SLIDING_WINDOW)


class TestRateLimitAlgorithm:
    """Tests for RateLimitAlgorithm enum."""

    def test_token_bucket_algorithm(self) -> None:
        """Test token bucket algorithm enum value."""
        assert RateLimitAlgorithm.TOKEN_BUCKET == "token_bucket"
        assert RateLimitAlgorithm.TOKEN_BUCKET.value == "token_bucket"

    def test_sliding_window_algorithm(self) -> None:
        """Test sliding window algorithm enum value."""
        assert RateLimitAlgorithm.SLIDING_WINDOW == "sliding_window"
        assert RateLimitAlgorithm.SLIDING_WINDOW.value == "sliding_window"


class TestRateLimitResult:
    """Tests for RateLimitResult named tuple."""

    def test_rate_limit_result_allowed(self) -> None:
        """Test rate limit result when request is allowed."""
        result = RateLimitResult(
            allowed=True, remaining=99, reset_at=1234567890.0, retry_after=None
        )

        assert result.allowed is True
        assert result.remaining == 99
        assert result.reset_at == 1234567890.0
        assert result.retry_after is None

    def test_rate_limit_result_denied(self) -> None:
        """Test rate limit result when request is denied."""
        result = RateLimitResult(allowed=False, remaining=0, reset_at=1234567890.0, retry_after=30)

        assert result.allowed is False
        assert result.remaining == 0
        assert result.reset_at == 1234567890.0
        assert result.retry_after == 30

    def test_rate_limit_result_default_retry_after(self) -> None:
        """Test rate limit result with default retry_after."""
        result = RateLimitResult(allowed=True, remaining=50, reset_at=1234567890.0)

        assert result.retry_after is None


class TestRateLimitExceededError:
    """Tests for RateLimitExceededError exception."""

    def test_exception_message(self) -> None:
        """Test exception message formatting."""
        error = RateLimitExceededError(retry_after=30)

        assert str(error) == "Rate limit exceeded. Retry after 30 seconds"
        assert error.retry_after == 30

    def test_exception_inheritance(self) -> None:
        """Test exception inherits from Exception."""
        error = RateLimitExceededError(retry_after=60)

        assert isinstance(error, Exception)


class TestRateLimiterInitialization:
    """Tests for RateLimiter initialization."""

    def test_initialization_with_token_bucket(self, redis_settings: RedisSettings) -> None:
        """Test initialization with token bucket algorithm."""
        limiter = RateLimiter(redis_settings, algorithm=RateLimitAlgorithm.TOKEN_BUCKET)

        assert limiter._redis_settings == redis_settings
        assert limiter._algorithm == RateLimitAlgorithm.TOKEN_BUCKET
        assert limiter._redis is None
        assert limiter._key_prefix == "rate_limit"

    def test_initialization_with_sliding_window(self, redis_settings: RedisSettings) -> None:
        """Test initialization with sliding window algorithm."""
        limiter = RateLimiter(redis_settings, algorithm=RateLimitAlgorithm.SLIDING_WINDOW)

        assert limiter._redis_settings == redis_settings
        assert limiter._algorithm == RateLimitAlgorithm.SLIDING_WINDOW
        assert limiter._redis is None

    def test_default_algorithm(self, redis_settings: RedisSettings) -> None:
        """Test default algorithm is token bucket."""
        limiter = RateLimiter(redis_settings)

        assert limiter._algorithm == RateLimitAlgorithm.TOKEN_BUCKET


class TestRateLimiterConnection:
    """Tests for RateLimiter connection management."""

    @pytest.mark.asyncio
    async def test_connect_establishes_redis_connection(
        self, token_bucket_limiter: RateLimiter
    ) -> None:
        """Test connect establishes Redis connection."""
        mock_redis = AsyncMock()

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            await token_bucket_limiter.connect()

            assert token_bucket_limiter._redis == mock_redis

    @pytest.mark.asyncio
    async def test_connect_uses_correct_settings(
        self, token_bucket_limiter: RateLimiter, redis_settings: RedisSettings
    ) -> None:
        """Test connect uses correct Redis settings."""
        with patch("redis.asyncio.from_url") as mock_from_url:
            mock_from_url.return_value = AsyncMock()

            await token_bucket_limiter.connect()

            mock_from_url.assert_called_once()
            call_args = mock_from_url.call_args
            assert call_args[0][0] == redis_settings.url

    @pytest.mark.asyncio
    async def test_connect_idempotent(self, token_bucket_limiter: RateLimiter) -> None:
        """Test multiple connects don't create new connections."""
        mock_redis = AsyncMock()

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            await token_bucket_limiter.connect()
            first_redis = token_bucket_limiter._redis

            await token_bucket_limiter.connect()
            second_redis = token_bucket_limiter._redis

            assert first_redis == second_redis

    @pytest.mark.asyncio
    async def test_disconnect_closes_connection(self, token_bucket_limiter: RateLimiter) -> None:
        """Test disconnect closes Redis connection."""
        mock_redis = AsyncMock()
        token_bucket_limiter._redis = mock_redis

        await token_bucket_limiter.disconnect()

        mock_redis.aclose.assert_called_once()
        assert token_bucket_limiter._redis is None

    @pytest.mark.asyncio
    async def test_disconnect_when_not_connected(self, token_bucket_limiter: RateLimiter) -> None:
        """Test disconnect when not connected does nothing."""
        await token_bucket_limiter.disconnect()

        assert token_bucket_limiter._redis is None


class TestRateLimiterKeyGeneration:
    """Tests for rate limiter Redis key generation."""

    def test_get_key_for_agent(self, token_bucket_limiter: RateLimiter) -> None:
        """Test key generation for agent."""
        key = token_bucket_limiter._get_key("agent-123")

        assert key == "rate_limit:token_bucket:agent-123"

    def test_get_key_for_different_agents(self, token_bucket_limiter: RateLimiter) -> None:
        """Test key generation for different agents."""
        key1 = token_bucket_limiter._get_key("agent-1")
        key2 = token_bucket_limiter._get_key("agent-2")

        assert key1 != key2
        assert "agent-1" in key1
        assert "agent-2" in key2

    def test_get_key_sliding_window(self, sliding_window_limiter: RateLimiter) -> None:
        """Test key generation for sliding window algorithm."""
        key = sliding_window_limiter._get_key("agent-123")

        assert key == "rate_limit:sliding_window:agent-123"


class TestTokenBucketRateLimiting:
    """Tests for token bucket rate limiting algorithm."""

    @pytest.mark.asyncio
    async def test_check_rate_limit_allowed(self, token_bucket_limiter: RateLimiter) -> None:
        """Test rate limit check when request is allowed."""
        mock_redis = AsyncMock()
        current_time = time.time()
        mock_redis.eval.return_value = [1, 99, current_time, 0]
        token_bucket_limiter._redis = mock_redis

        result = await token_bucket_limiter.check_rate_limit("agent-123", limit=100, window=60)

        assert result.allowed is True
        assert result.remaining == 99
        assert result.retry_after is None

    @pytest.mark.asyncio
    async def test_check_rate_limit_denied(self, token_bucket_limiter: RateLimiter) -> None:
        """Test rate limit check when request is denied."""
        mock_redis = AsyncMock()
        current_time = time.time()
        mock_redis.eval.return_value = [0, 0, current_time, 30]
        token_bucket_limiter._redis = mock_redis

        result = await token_bucket_limiter.check_rate_limit("agent-123", limit=100, window=60)

        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after == 30

    @pytest.mark.asyncio
    async def test_check_rate_limit_auto_connect(self, token_bucket_limiter: RateLimiter) -> None:
        """Test rate limit check auto-connects if not connected."""
        mock_redis = AsyncMock()
        current_time = time.time()
        mock_redis.eval.return_value = [1, 99, current_time, 0]

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            result = await token_bucket_limiter.check_rate_limit("agent-123", limit=100, window=60)

            assert result.allowed is True

    @pytest.mark.asyncio
    async def test_check_rate_limit_uses_lua_script(
        self, token_bucket_limiter: RateLimiter
    ) -> None:
        """Test rate limit check uses Lua script for atomic operations."""
        mock_redis = AsyncMock()
        current_time = time.time()
        mock_redis.eval.return_value = [1, 99, current_time, 0]
        token_bucket_limiter._redis = mock_redis

        await token_bucket_limiter.check_rate_limit("agent-123", limit=100, window=60)

        mock_redis.eval.assert_called_once()
        call_args = mock_redis.eval.call_args[0]
        assert "HMGET" in call_args[0]  # Lua script contains HMGET
        assert call_args[1] == 1  # Number of keys
        assert "rate_limit:token_bucket:agent-123" in call_args[2]  # Key


class TestSlidingWindowRateLimiting:
    """Tests for sliding window rate limiting algorithm."""

    @pytest.mark.asyncio
    async def test_check_rate_limit_allowed(self, sliding_window_limiter: RateLimiter) -> None:
        """Test sliding window rate limit when allowed."""
        mock_redis = AsyncMock()
        current_time = time.time()
        mock_redis.eval.return_value = [1, 99, current_time + 60, 0]
        sliding_window_limiter._redis = mock_redis

        result = await sliding_window_limiter.check_rate_limit("agent-123", limit=100, window=60)

        assert result.allowed is True
        assert result.remaining == 99
        assert result.retry_after is None

    @pytest.mark.asyncio
    async def test_check_rate_limit_denied(self, sliding_window_limiter: RateLimiter) -> None:
        """Test sliding window rate limit when denied."""
        mock_redis = AsyncMock()
        current_time = time.time()
        mock_redis.eval.return_value = [0, 0, current_time + 60, 45]
        sliding_window_limiter._redis = mock_redis

        result = await sliding_window_limiter.check_rate_limit("agent-123", limit=100, window=60)

        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after == 45

    @pytest.mark.asyncio
    async def test_check_rate_limit_uses_sorted_set(
        self, sliding_window_limiter: RateLimiter
    ) -> None:
        """Test sliding window uses sorted set operations."""
        mock_redis = AsyncMock()
        current_time = time.time()
        mock_redis.eval.return_value = [1, 99, current_time + 60, 0]
        sliding_window_limiter._redis = mock_redis

        await sliding_window_limiter.check_rate_limit("agent-123", limit=100, window=60)

        mock_redis.eval.assert_called_once()
        call_args = mock_redis.eval.call_args[0]
        assert "ZREMRANGEBYSCORE" in call_args[0]  # Lua script uses sorted set
        assert "ZCARD" in call_args[0]


class TestRateLimiterOperations:
    """Tests for rate limiter operations."""

    @pytest.mark.asyncio
    async def test_reset_limit(self, token_bucket_limiter: RateLimiter) -> None:
        """Test reset rate limit for agent."""
        mock_redis = AsyncMock()
        token_bucket_limiter._redis = mock_redis

        await token_bucket_limiter.reset_limit("agent-123")

        mock_redis.delete.assert_called_once_with("rate_limit:token_bucket:agent-123")

    @pytest.mark.asyncio
    async def test_reset_limit_auto_connect(self, token_bucket_limiter: RateLimiter) -> None:
        """Test reset auto-connects if not connected."""
        mock_redis = AsyncMock()

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            await token_bucket_limiter.reset_limit("agent-123")

            mock_redis.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_remaining_token_bucket(self, token_bucket_limiter: RateLimiter) -> None:
        """Test get remaining tokens for token bucket."""
        mock_redis = AsyncMock()
        current_time = time.time()
        mock_redis.hmget.return_value = ["50", str(current_time - 10)]
        token_bucket_limiter._redis = mock_redis

        remaining = await token_bucket_limiter.get_remaining("agent-123", limit=100, window=60)

        assert remaining >= 50
        mock_redis.hmget.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_remaining_no_existing_data(self, token_bucket_limiter: RateLimiter) -> None:
        """Test get remaining when no existing data."""
        mock_redis = AsyncMock()
        mock_redis.hmget.return_value = [None, None]
        token_bucket_limiter._redis = mock_redis

        remaining = await token_bucket_limiter.get_remaining("agent-123", limit=100, window=60)

        assert remaining == 100

    @pytest.mark.asyncio
    async def test_get_remaining_sliding_window(self, sliding_window_limiter: RateLimiter) -> None:
        """Test get remaining for sliding window."""
        mock_redis = AsyncMock()
        mock_redis.zremrangebyscore.return_value = None
        mock_redis.zcard.return_value = 25
        sliding_window_limiter._redis = mock_redis

        remaining = await sliding_window_limiter.get_remaining("agent-123", limit=100, window=60)

        assert remaining == 75

    @pytest.mark.asyncio
    async def test_get_reset_time_token_bucket(self, token_bucket_limiter: RateLimiter) -> None:
        """Test get reset time for token bucket."""
        mock_redis = AsyncMock()
        last_refill = time.time() - 30
        mock_redis.hmget.return_value = [str(last_refill)]
        token_bucket_limiter._redis = mock_redis

        reset_time = await token_bucket_limiter.get_reset_time("agent-123", window=60)

        assert reset_time == pytest.approx(last_refill + 60, rel=0.1)

    @pytest.mark.asyncio
    async def test_get_reset_time_no_data(self, token_bucket_limiter: RateLimiter) -> None:
        """Test get reset time when no existing data."""
        mock_redis = AsyncMock()
        mock_redis.hmget.return_value = [None]
        token_bucket_limiter._redis = mock_redis

        current_time = time.time()
        reset_time = await token_bucket_limiter.get_reset_time("agent-123", window=60)

        assert reset_time >= current_time
        assert reset_time <= current_time + 61  # Allow 1 second tolerance

    @pytest.mark.asyncio
    async def test_get_reset_time_sliding_window(self, sliding_window_limiter: RateLimiter) -> None:
        """Test get reset time for sliding window."""
        mock_redis = AsyncMock()
        sliding_window_limiter._redis = mock_redis

        current_time = time.time()
        reset_time = await sliding_window_limiter.get_reset_time("agent-123", window=60)

        assert reset_time >= current_time
        assert reset_time <= current_time + 61  # Allow 1 second tolerance


class TestRateLimiterErrorHandling:
    """Tests for rate limiter error handling."""

    @pytest.mark.asyncio
    async def test_check_rate_limit_raises_on_no_connection(
        self, token_bucket_limiter: RateLimiter
    ) -> None:
        """Test check rate limit raises error if connection fails."""
        with patch("redis.asyncio.from_url", return_value=None):
            with pytest.raises(RuntimeError, match="Redis connection not established"):
                await token_bucket_limiter.check_rate_limit("agent-123", limit=100, window=60)

    @pytest.mark.asyncio
    async def test_reset_limit_raises_on_no_connection(
        self, token_bucket_limiter: RateLimiter
    ) -> None:
        """Test reset limit raises error if connection fails."""
        with patch("redis.asyncio.from_url", return_value=None):
            with pytest.raises(RuntimeError, match="Redis connection not established"):
                await token_bucket_limiter.reset_limit("agent-123")

    @pytest.mark.asyncio
    async def test_get_remaining_raises_on_no_connection(
        self, token_bucket_limiter: RateLimiter
    ) -> None:
        """Test get remaining raises error if connection fails."""
        with patch("redis.asyncio.from_url", return_value=None):
            with pytest.raises(RuntimeError, match="Redis connection not established"):
                await token_bucket_limiter.get_remaining("agent-123", limit=100, window=60)

    @pytest.mark.asyncio
    async def test_get_reset_time_raises_on_no_connection(
        self, token_bucket_limiter: RateLimiter
    ) -> None:
        """Test get reset time raises error if connection fails."""
        with patch("redis.asyncio.from_url", return_value=None):
            with pytest.raises(RuntimeError, match="Redis connection not established"):
                await token_bucket_limiter.get_reset_time("agent-123", window=60)


class TestRateLimiterEdgeCases:
    """Tests for rate limiter edge cases."""

    @pytest.mark.asyncio
    async def test_zero_limit(self, token_bucket_limiter: RateLimiter) -> None:
        """Test rate limiting with zero limit."""
        mock_redis = AsyncMock()
        current_time = time.time()
        mock_redis.eval.return_value = [0, 0, current_time, 60]
        token_bucket_limiter._redis = mock_redis

        result = await token_bucket_limiter.check_rate_limit("agent-123", limit=0, window=60)

        assert result.allowed is False

    @pytest.mark.asyncio
    async def test_very_short_window(self, token_bucket_limiter: RateLimiter) -> None:
        """Test rate limiting with very short window."""
        mock_redis = AsyncMock()
        current_time = time.time()
        mock_redis.eval.return_value = [1, 9, current_time, 0]
        token_bucket_limiter._redis = mock_redis

        result = await token_bucket_limiter.check_rate_limit("agent-123", limit=10, window=1)

        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_multiple_agents_independent(self, token_bucket_limiter: RateLimiter) -> None:
        """Test rate limits are independent per agent."""
        mock_redis = AsyncMock()
        current_time = time.time()
        mock_redis.eval.return_value = [1, 99, current_time, 0]
        token_bucket_limiter._redis = mock_redis

        result1 = await token_bucket_limiter.check_rate_limit("agent-1", limit=100, window=60)
        result2 = await token_bucket_limiter.check_rate_limit("agent-2", limit=100, window=60)

        assert result1.allowed is True
        assert result2.allowed is True
        # Verify different keys were used
        assert mock_redis.eval.call_count == 2
