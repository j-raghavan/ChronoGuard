"""Comprehensive tests for OPA client."""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import aiohttp
import pytest
from infrastructure.opa.client import (
    OPAClient,
    OPAClientError,
    OPAConnectionError,
    OPAEvaluationError,
    OPAPolicyError,
)


def create_async_context_manager_mock(return_value: Any) -> MagicMock:
    """Create a mock async context manager.

    Args:
        return_value: The value to return from __aenter__

    Returns:
        A MagicMock configured as an async context manager
    """
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=return_value)
    mock_cm.__aexit__ = AsyncMock(return_value=None)
    return mock_cm


class TestOPAClient:
    """Test suite for OPAClient."""

    @pytest.fixture
    def mock_settings(self) -> MagicMock:
        """Create mock proxy settings."""
        settings = MagicMock()
        settings.opa_url = "http://localhost:8181"
        settings.opa_policy_path = "/v1/data/chronoguard/allow"
        settings.opa_timeout = 5
        return settings

    @pytest.fixture
    def client(self, mock_settings: MagicMock) -> OPAClient:
        """Create OPA client instance."""
        return OPAClient(settings=mock_settings, max_retries=3, retry_delay=0.1)

    @pytest.fixture
    def client_with_defaults(self) -> OPAClient:
        """Create OPA client with default settings."""
        return OPAClient()

    def test_init_with_settings(self, mock_settings: MagicMock) -> None:
        """Test client initialization with settings."""
        client = OPAClient(settings=mock_settings, max_retries=5, retry_delay=2.0)

        assert client.opa_url == "http://localhost:8181"
        assert client.policy_path == "v1/data/chronoguard/allow"
        assert client.timeout == 5
        assert client.max_retries == 5
        assert client.retry_delay == 2.0
        assert client.session is None

    def test_init_with_defaults(self, client_with_defaults: OPAClient) -> None:
        """Test client initialization with default settings."""
        assert client_with_defaults.opa_url == "http://localhost:8181"
        assert client_with_defaults.max_retries == 3
        assert client_with_defaults.retry_delay == 1.0

    def test_init_strips_trailing_slash(self) -> None:
        """Test that trailing slash is stripped from OPA URL."""
        settings = MagicMock()
        settings.opa_url = "http://localhost:8181/"
        settings.opa_policy_path = "/v1/data/chronoguard/allow"
        settings.opa_timeout = 5

        client = OPAClient(settings=settings)
        assert client.opa_url == "http://localhost:8181"

    @pytest.mark.asyncio
    async def test_get_session_creates_new(self, client: OPAClient) -> None:
        """Test that _get_session creates a new session."""
        session = await client._get_session()

        assert session is not None
        assert isinstance(session, aiohttp.ClientSession)
        assert client.session is session

        await client.close()

    @pytest.mark.asyncio
    async def test_get_session_reuses_existing(self, client: OPAClient) -> None:
        """Test that _get_session reuses existing session."""
        session1 = await client._get_session()
        session2 = await client._get_session()

        assert session1 is session2

        await client.close()

    @pytest.mark.asyncio
    async def test_check_policy_success_allow(self, client: OPAClient) -> None:
        """Test successful policy check with allow decision."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"result": True})

        mock_session = MagicMock()
        mock_session.post.return_value = create_async_context_manager_mock(mock_response)

        with patch.object(
            client, "_get_session", new_callable=AsyncMock, return_value=mock_session
        ):
            result = await client.check_policy({"domain": "example.com"})

            assert result is True
            mock_session.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_policy_success_deny(self, client: OPAClient) -> None:
        """Test successful policy check with deny decision."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"result": False})

        mock_session = MagicMock()
        mock_session.post.return_value = create_async_context_manager_mock(mock_response)

        with patch.object(
            client, "_get_session", new_callable=AsyncMock, return_value=mock_session
        ):
            result = await client.check_policy({"domain": "example.com"})

            assert result is False

    @pytest.mark.asyncio
    async def test_check_policy_custom_path(self, client: OPAClient) -> None:
        """Test policy check with custom policy path."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"result": True})

        mock_session = MagicMock()
        mock_session.post.return_value = create_async_context_manager_mock(mock_response)

        with patch.object(
            client, "_get_session", new_callable=AsyncMock, return_value=mock_session
        ):
            await client.check_policy({"domain": "example.com"}, policy_path="custom/path")

            call_args = mock_session.post.call_args
            assert "custom/path" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_check_policy_retry_on_500(self, client: OPAClient) -> None:
        """Test that policy check retries on server errors."""
        client.retry_delay = 0.01  # Speed up test

        # First two calls fail with 500, third succeeds
        mock_responses = [
            AsyncMock(status=500, text=AsyncMock(return_value="Server error")),
            AsyncMock(status=500, text=AsyncMock(return_value="Server error")),
            AsyncMock(status=200, json=AsyncMock(return_value={"result": True})),
        ]

        mock_session = MagicMock()
        mock_session.post.side_effect = [
            create_async_context_manager_mock(r) for r in mock_responses
        ]

        with patch.object(
            client, "_get_session", new_callable=AsyncMock, return_value=mock_session
        ):
            result = await client.check_policy({"domain": "example.com"})

            assert result is True
            assert mock_session.post.call_count == 3

    @pytest.mark.asyncio
    async def test_check_policy_retry_on_429(self, client: OPAClient) -> None:
        """Test that policy check retries on rate limiting."""
        client.retry_delay = 0.01

        mock_responses = [
            AsyncMock(status=429, text=AsyncMock(return_value="Too many requests")),
            AsyncMock(status=200, json=AsyncMock(return_value={"result": True})),
        ]

        mock_session = MagicMock()
        mock_session.post.side_effect = [
            create_async_context_manager_mock(r) for r in mock_responses
        ]

        with patch.object(
            client, "_get_session", new_callable=AsyncMock, return_value=mock_session
        ):
            result = await client.check_policy({"domain": "example.com"})

            assert result is True
            assert mock_session.post.call_count == 2

    @pytest.mark.asyncio
    async def test_check_policy_no_retry_on_400(self, client: OPAClient) -> None:
        """Test that policy check does not retry on client errors."""
        mock_response = MagicMock()
        mock_response.status = 400
        mock_response.text = AsyncMock(return_value="Bad request")

        mock_session = MagicMock()
        mock_session.post.return_value = create_async_context_manager_mock(mock_response)

        with patch.object(
            client, "_get_session", new_callable=AsyncMock, return_value=mock_session
        ):
            with pytest.raises(OPAEvaluationError, match="Policy evaluation failed"):
                await client.check_policy({"domain": "example.com"})

            assert mock_session.post.call_count == 1

    @pytest.mark.asyncio
    async def test_check_policy_connection_error_retry(self, client: OPAClient) -> None:
        """Test that policy check retries on connection errors."""
        client.retry_delay = 0.01

        with patch.object(client, "_get_session", new_callable=AsyncMock) as mock_get_session:
            mock_session = MagicMock()
            # First two calls raise connection error, third succeeds
            mock_success_resp = MagicMock(status=200, json=AsyncMock(return_value={"result": True}))
            mock_session.post.side_effect = [
                aiohttp.ClientError("Connection failed"),
                aiohttp.ClientError("Connection failed"),
                create_async_context_manager_mock(mock_success_resp),
            ]
            mock_get_session.return_value = mock_session

            result = await client.check_policy({"domain": "example.com"})

            assert result is True
            assert mock_session.post.call_count == 3

    @pytest.mark.asyncio
    async def test_check_policy_max_retries_exceeded(self, client: OPAClient) -> None:
        """Test that policy check fails after max retries."""
        client.retry_delay = 0.01

        with patch.object(client, "_get_session", new_callable=AsyncMock) as mock_get_session:
            mock_session = MagicMock()
            mock_session.post.side_effect = aiohttp.ClientError("Connection failed")
            mock_get_session.return_value = mock_session

            with pytest.raises(OPAConnectionError, match="Failed to connect to OPA"):
                await client.check_policy({"domain": "example.com"})

            assert mock_session.post.call_count == client.max_retries

    @pytest.mark.asyncio
    async def test_update_policy_success(self, client: OPAClient) -> None:
        """Test successful policy update."""
        mock_response = MagicMock()
        mock_response.status = 200

        mock_session = MagicMock()
        mock_session.put.return_value = create_async_context_manager_mock(mock_response)

        with patch.object(
            client, "_get_session", new_callable=AsyncMock, return_value=mock_session
        ):
            await client.update_policy("test_policy", "package chronoguard")

            mock_session.put.assert_called_once()
            call_args = mock_session.put.call_args
            assert "test_policy" in call_args[0][0]
            assert call_args[1]["data"] == "package chronoguard"

    @pytest.mark.asyncio
    async def test_update_policy_created(self, client: OPAClient) -> None:
        """Test policy update returns 201 Created."""
        mock_response = MagicMock()
        mock_response.status = 201

        mock_session = MagicMock()
        mock_session.put.return_value = create_async_context_manager_mock(mock_response)

        with patch.object(
            client, "_get_session", new_callable=AsyncMock, return_value=mock_session
        ):
            await client.update_policy("test_policy", "package chronoguard")

            mock_session.put.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_policy_retry_on_500(self, client: OPAClient) -> None:
        """Test that policy update retries on server errors."""
        client.retry_delay = 0.01

        mock_responses = [
            AsyncMock(status=500, text=AsyncMock(return_value="Server error")),
            AsyncMock(status=200),
        ]

        mock_session = MagicMock()
        mock_session.put.side_effect = [
            create_async_context_manager_mock(r) for r in mock_responses
        ]

        with patch.object(
            client, "_get_session", new_callable=AsyncMock, return_value=mock_session
        ):
            await client.update_policy("test_policy", "package chronoguard")

            assert mock_session.put.call_count == 2

    @pytest.mark.asyncio
    async def test_update_policy_no_retry_on_400(self, client: OPAClient) -> None:
        """Test that policy update does not retry on client errors."""
        mock_response = MagicMock()
        mock_response.status = 400
        mock_response.text = AsyncMock(return_value="Bad request")

        mock_session = MagicMock()
        mock_session.put.return_value = create_async_context_manager_mock(mock_response)

        with patch.object(
            client, "_get_session", new_callable=AsyncMock, return_value=mock_session
        ):
            with pytest.raises(OPAPolicyError, match="Policy update failed"):
                await client.update_policy("test_policy", "package chronoguard")

            assert mock_session.put.call_count == 1

    @pytest.mark.asyncio
    async def test_update_policy_connection_error(self, client: OPAClient) -> None:
        """Test policy update handles connection errors."""
        client.retry_delay = 0.01

        with patch.object(client, "_get_session", new_callable=AsyncMock) as mock_get_session:
            mock_session = MagicMock()
            mock_session.put.side_effect = aiohttp.ClientError("Connection failed")
            mock_get_session.return_value = mock_session

            with pytest.raises(OPAConnectionError, match="Failed to connect to OPA"):
                await client.update_policy("test_policy", "package chronoguard")

    @pytest.mark.asyncio
    async def test_health_check_success(self, client: OPAClient) -> None:
        """Test successful health check."""
        health_data = {"status": "ok", "version": "0.50.0"}
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value=health_data)

        mock_session = MagicMock()
        mock_session.get.return_value = create_async_context_manager_mock(mock_response)

        with patch.object(
            client, "_get_session", new_callable=AsyncMock, return_value=mock_session
        ):
            result = await client.health_check()

            assert result == health_data
            mock_session.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_failure(self, client: OPAClient) -> None:
        """Test health check failure."""
        mock_response = MagicMock()
        mock_response.status = 500
        mock_response.text = AsyncMock(return_value="Server error")

        mock_session = MagicMock()
        mock_session.get.return_value = create_async_context_manager_mock(mock_response)

        with patch.object(
            client, "_get_session", new_callable=AsyncMock, return_value=mock_session
        ):
            with pytest.raises(OPAConnectionError, match="OPA health check failed"):
                await client.health_check()

    @pytest.mark.asyncio
    async def test_health_check_connection_error(self, client: OPAClient) -> None:
        """Test health check connection error."""
        with patch.object(client, "_get_session", new_callable=AsyncMock) as mock_get_session:
            mock_session = MagicMock()
            mock_session.get.side_effect = aiohttp.ClientError("Connection failed")
            mock_get_session.return_value = mock_session

            with pytest.raises(OPAConnectionError, match="OPA health check failed"):
                await client.health_check()

    @pytest.mark.asyncio
    async def test_get_policy_success(self, client: OPAClient) -> None:
        """Test successful policy retrieval."""
        rego_code = "package chronoguard\\nallow { true }"
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"result": {"raw": rego_code}})

        mock_session = MagicMock()
        mock_session.get.return_value = create_async_context_manager_mock(mock_response)

        with patch.object(
            client, "_get_session", new_callable=AsyncMock, return_value=mock_session
        ):
            result = await client.get_policy("test_policy")

            assert result == rego_code

    @pytest.mark.asyncio
    async def test_get_policy_not_found(self, client: OPAClient) -> None:
        """Test policy retrieval when policy not found."""
        mock_response = MagicMock()
        mock_response.status = 404

        mock_session = MagicMock()
        mock_session.get.return_value = create_async_context_manager_mock(mock_response)

        with patch.object(
            client, "_get_session", new_callable=AsyncMock, return_value=mock_session
        ):
            with pytest.raises(OPAPolicyError, match="not found"):
                await client.get_policy("test_policy")

    @pytest.mark.asyncio
    async def test_get_policy_connection_error(self, client: OPAClient) -> None:
        """Test policy retrieval connection error."""
        with patch.object(client, "_get_session", new_callable=AsyncMock) as mock_get_session:
            mock_session = MagicMock()
            mock_session.get.side_effect = aiohttp.ClientError("Connection failed")
            mock_get_session.return_value = mock_session

            with pytest.raises(OPAConnectionError, match="Failed to connect to OPA"):
                await client.get_policy("test_policy")

    @pytest.mark.asyncio
    async def test_delete_policy_success(self, client: OPAClient) -> None:
        """Test successful policy deletion."""
        mock_response = MagicMock()
        mock_response.status = 200

        mock_session = MagicMock()
        mock_session.delete.return_value = create_async_context_manager_mock(mock_response)

        with patch.object(
            client, "_get_session", new_callable=AsyncMock, return_value=mock_session
        ):
            await client.delete_policy("test_policy")

            mock_session.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_policy_no_content(self, client: OPAClient) -> None:
        """Test policy deletion with 204 No Content."""
        mock_response = MagicMock()
        mock_response.status = 204

        mock_session = MagicMock()
        mock_session.delete.return_value = create_async_context_manager_mock(mock_response)

        with patch.object(
            client, "_get_session", new_callable=AsyncMock, return_value=mock_session
        ):
            await client.delete_policy("test_policy")

            mock_session.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_policy_not_found(self, client: OPAClient) -> None:
        """Test policy deletion when policy not found (should not raise)."""
        mock_response = MagicMock()
        mock_response.status = 404

        mock_session = MagicMock()
        mock_session.delete.return_value = create_async_context_manager_mock(mock_response)

        with patch.object(
            client, "_get_session", new_callable=AsyncMock, return_value=mock_session
        ):
            # Should not raise
            await client.delete_policy("test_policy")

    @pytest.mark.asyncio
    async def test_delete_policy_error(self, client: OPAClient) -> None:
        """Test policy deletion error."""
        mock_response = MagicMock()
        mock_response.status = 500
        mock_response.text = AsyncMock(return_value="Server error")

        mock_session = MagicMock()
        mock_session.delete.return_value = create_async_context_manager_mock(mock_response)

        with patch.object(
            client, "_get_session", new_callable=AsyncMock, return_value=mock_session
        ):
            with pytest.raises(OPAPolicyError, match="Policy deletion failed"):
                await client.delete_policy("test_policy")

    @pytest.mark.asyncio
    async def test_close(self, client: OPAClient) -> None:
        """Test closing client session."""
        # Create session first
        await client._get_session()
        assert client.session is not None

        # Close it
        await client.close()
        assert client.session is None

    @pytest.mark.asyncio
    async def test_close_when_no_session(self, client: OPAClient) -> None:
        """Test closing when no session exists."""
        assert client.session is None
        await client.close()
        assert client.session is None

    @pytest.mark.asyncio
    async def test_context_manager(self, mock_settings: MagicMock) -> None:
        """Test client as async context manager."""
        async with OPAClient(settings=mock_settings) as client:
            assert client is not None
            await client._get_session()
            assert client.session is not None

        # Session should be closed after exiting context
        assert client.session is None

    @pytest.mark.asyncio
    async def test_unexpected_error_in_check_policy(self, client: OPAClient) -> None:
        """Test handling of unexpected errors in check_policy."""
        with patch.object(client, "_get_session", new_callable=AsyncMock) as mock_get_session:
            mock_get_session.side_effect = RuntimeError("Unexpected error")

            with pytest.raises(OPAEvaluationError, match="Policy evaluation failed"):
                await client.check_policy({"domain": "example.com"})

    @pytest.mark.asyncio
    async def test_unexpected_error_in_update_policy(self, client: OPAClient) -> None:
        """Test handling of unexpected errors in update_policy."""
        with patch.object(client, "_get_session", new_callable=AsyncMock) as mock_get_session:
            mock_get_session.side_effect = RuntimeError("Unexpected error")

            with pytest.raises(OPAPolicyError, match="Policy update failed"):
                await client.update_policy("test_policy", "package chronoguard")

    @pytest.mark.asyncio
    async def test_unexpected_error_in_health_check(self, client: OPAClient) -> None:
        """Test handling of unexpected errors in health_check."""
        with patch.object(client, "_get_session", new_callable=AsyncMock) as mock_get_session:
            mock_get_session.side_effect = RuntimeError("Unexpected error")

            with pytest.raises(OPAConnectionError, match="OPA health check failed"):
                await client.health_check()


class TestOPAClientExceptions:
    """Test OPA client exception hierarchy."""

    def test_opa_client_error_base(self) -> None:
        """Test OPAClientError is base exception."""
        error = OPAClientError("Test error")
        assert isinstance(error, Exception)
        assert str(error) == "Test error"

    def test_opa_connection_error(self) -> None:
        """Test OPAConnectionError inherits from base."""
        error = OPAConnectionError("Connection failed")
        assert isinstance(error, OPAClientError)
        assert str(error) == "Connection failed"

    def test_opa_policy_error(self) -> None:
        """Test OPAPolicyError inherits from base."""
        error = OPAPolicyError("Policy error")
        assert isinstance(error, OPAClientError)
        assert str(error) == "Policy error"

    def test_opa_evaluation_error(self) -> None:
        """Test OPAEvaluationError inherits from base."""
        error = OPAEvaluationError("Evaluation failed")
        assert isinstance(error, OPAClientError)
        assert str(error) == "Evaluation failed"
