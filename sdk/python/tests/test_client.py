"""Tests for ChronoGuard client."""

import pytest
import respx
from chronoguard_sdk import ChronoGuard, ChronoGuardSync
from chronoguard_sdk.exceptions import (
    APIError,
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    NotFoundError,
    RateLimitError,
    ValidationError,
)
from httpx import Response


class TestChronoGuard:
    """Tests for async ChronoGuard client."""

    @pytest.mark.asyncio
    async def test_client_initialization(self, base_url, tenant_id, user_id):
        """Test client initializes correctly."""
        client = ChronoGuard(
            api_url=base_url,
            tenant_id=tenant_id,
            user_id=user_id,
            timeout=60.0,
        )

        assert client._api_url == base_url
        assert client._tenant_id == tenant_id
        assert client._user_id == user_id
        assert client._timeout == 60.0
        assert client.agents is not None
        assert client.policies is not None
        assert client.audit is not None
        assert client.analytics is not None

        await client.close()

    @pytest.mark.asyncio
    async def test_client_context_manager(self, base_url):
        """Test client works as async context manager."""
        async with ChronoGuard(api_url=base_url) as client:
            assert client is not None

    @pytest.mark.asyncio
    async def test_client_strips_trailing_slash(self):
        """Test client strips trailing slash from API URL."""
        client = ChronoGuard(api_url="http://test.com/")
        assert client._api_url == "http://test.com"
        await client.close()

    @pytest.mark.asyncio
    async def test_client_custom_headers(self, base_url):
        """Test client includes custom headers."""
        custom_headers = {"X-Custom-Header": "custom-value"}
        client = ChronoGuard(api_url=base_url, headers=custom_headers)

        assert "X-Custom-Header" in client._http_client.headers
        assert client._http_client.headers["X-Custom-Header"] == "custom-value"

        await client.close()

    @pytest.mark.asyncio
    @respx.mock
    async def test_error_handling_400(self, base_url):
        """Test handling of 400 Bad Request errors."""
        respx.get(f"{base_url}/api/v1/agents/test").mock(
            return_value=Response(400, json={"detail": "Invalid request"})
        )

        client = ChronoGuard(api_url=base_url)

        with pytest.raises(ValidationError) as exc_info:
            await client.agents.get("test")

        assert "Invalid request" in str(exc_info.value)
        await client.close()

    @pytest.mark.asyncio
    @respx.mock
    async def test_error_handling_401(self, base_url):
        """Test handling of 401 Unauthorized errors."""
        respx.get(f"{base_url}/api/v1/agents/test").mock(
            return_value=Response(401, json={"detail": "Unauthorized"})
        )

        client = ChronoGuard(api_url=base_url)

        with pytest.raises(AuthenticationError):
            await client.agents.get("test")

        await client.close()

    @pytest.mark.asyncio
    @respx.mock
    async def test_error_handling_403(self, base_url):
        """Test handling of 403 Forbidden errors."""
        respx.get(f"{base_url}/api/v1/agents/test").mock(
            return_value=Response(403, json={"detail": "Forbidden"})
        )

        client = ChronoGuard(api_url=base_url)

        with pytest.raises(AuthorizationError):
            await client.agents.get("test")

        await client.close()

    @pytest.mark.asyncio
    @respx.mock
    async def test_error_handling_404(self, base_url):
        """Test handling of 404 Not Found errors."""
        respx.get(f"{base_url}/api/v1/agents/test").mock(
            return_value=Response(404, json={"detail": "Not found"})
        )

        client = ChronoGuard(api_url=base_url)

        with pytest.raises(NotFoundError):
            await client.agents.get("test")

        await client.close()

    @pytest.mark.asyncio
    @respx.mock
    async def test_error_handling_409(self, base_url):
        """Test handling of 409 Conflict errors."""
        respx.post(f"{base_url}/api/v1/agents/").mock(
            return_value=Response(409, json={"detail": "Duplicate agent"})
        )

        client = ChronoGuard(api_url=base_url)

        with pytest.raises(ConflictError):
            await client.agents.create(
                name="test",
                certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            )

        await client.close()

    @pytest.mark.asyncio
    @respx.mock
    async def test_error_handling_429(self, base_url):
        """Test handling of 429 Rate Limit errors."""
        respx.get(f"{base_url}/api/v1/agents/").mock(
            return_value=Response(
                429,
                json={"detail": "Rate limit exceeded"},
                headers={"Retry-After": "60"},
            )
        )

        client = ChronoGuard(api_url=base_url)

        with pytest.raises(RateLimitError) as exc_info:
            await client.agents.list()

        assert exc_info.value.retry_after == 60
        await client.close()

    @pytest.mark.asyncio
    @respx.mock
    async def test_error_handling_500(self, base_url):
        """Test handling of 500 Internal Server Error."""
        respx.get(f"{base_url}/api/v1/agents/").mock(
            return_value=Response(500, json={"detail": "Internal server error"})
        )

        client = ChronoGuard(api_url=base_url)

        with pytest.raises(APIError) as exc_info:
            await client.agents.list()

        assert exc_info.value.status_code == 500
        await client.close()


class TestChronoGuardSync:
    """Tests for sync ChronoGuard client."""

    def test_sync_client_initialization(self, base_url, tenant_id, user_id):
        """Test sync client initializes correctly."""
        client = ChronoGuardSync(
            api_url=base_url,
            tenant_id=tenant_id,
            user_id=user_id,
            timeout=60.0,
        )

        assert client._api_url == base_url
        assert client._tenant_id == tenant_id
        assert client._user_id == user_id
        assert client._timeout == 60.0
        assert client.agents is not None
        assert client.policies is not None
        assert client.audit is not None
        assert client.analytics is not None

        client.close()

    def test_sync_client_context_manager(self, base_url):
        """Test sync client works as context manager."""
        with ChronoGuardSync(api_url=base_url) as client:
            assert client is not None

    @respx.mock
    def test_sync_error_handling_404(self, base_url):
        """Test sync client handles 404 errors."""
        respx.get(f"{base_url}/api/v1/agents/test").mock(
            return_value=Response(404, json={"detail": "Not found"})
        )

        client = ChronoGuardSync(api_url=base_url)

        with pytest.raises(NotFoundError):
            client.agents.get("test")

        client.close()
