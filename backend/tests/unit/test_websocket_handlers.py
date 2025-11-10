"""Comprehensive tests for WebSocket handlers."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from presentation.websocket.handlers import WebSocketHandlers


@pytest.fixture
def mock_websocket() -> MagicMock:
    """Create a mock WebSocket."""
    ws = MagicMock()
    ws.accept = AsyncMock()
    ws.send_text = AsyncMock()
    ws.close = AsyncMock()
    return ws


@pytest.fixture
def mock_manager() -> MagicMock:
    """Create a mock WebSocket manager."""
    manager = MagicMock()
    manager.register = AsyncMock()
    manager.unregister = AsyncMock()
    manager.subscribe = AsyncMock()
    manager.unsubscribe = AsyncMock()
    return manager


@pytest.fixture
def mock_auth_service() -> MagicMock:
    """Create a mock authentication service."""
    auth = MagicMock()
    auth.validate = AsyncMock(return_value=True)
    return auth


@pytest.fixture
def handlers(mock_manager: MagicMock) -> WebSocketHandlers:
    """Create WebSocket handlers instance."""
    return WebSocketHandlers(mock_manager)


@pytest.fixture
def handlers_with_auth(
    mock_manager: MagicMock,
    mock_auth_service: MagicMock,
) -> WebSocketHandlers:
    """Create WebSocket handlers with auth service."""
    return WebSocketHandlers(mock_manager, mock_auth_service)


class TestWebSocketHandlersInit:
    """Test WebSocketHandlers initialization."""

    def test_initialization(self, mock_manager: MagicMock) -> None:
        """Test handler initialization."""
        handlers = WebSocketHandlers(mock_manager)

        assert handlers._manager == mock_manager
        assert handlers._auth_service is None

    def test_initialization_with_auth(
        self,
        mock_manager: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Test handler initialization with auth service."""
        handlers = WebSocketHandlers(mock_manager, mock_auth_service)

        assert handlers._manager == mock_manager
        assert handlers._auth_service == mock_auth_service


class TestOnConnect:
    """Test on_connect handler."""

    async def test_on_connect_success(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
        mock_manager: MagicMock,
    ) -> None:
        """Test successful connection."""
        await handlers.on_connect(mock_websocket, "client-1")

        # Verify WebSocket was accepted
        mock_websocket.accept.assert_called_once()

        # Verify registration with manager
        mock_manager.register.assert_called_once()
        call_args = mock_manager.register.call_args[0]
        assert call_args[0] == mock_websocket
        assert call_args[1] == "client-1"

        # Verify welcome message was sent
        mock_websocket.send_text.assert_called_once()
        sent_message = json.loads(mock_websocket.send_text.call_args[0][0])
        assert sent_message["type"] == "connection_established"
        assert sent_message["client_id"] == "client-1"

    async def test_on_connect_with_metadata(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
        mock_manager: MagicMock,
    ) -> None:
        """Test connection with metadata."""
        metadata = {"user_id": "user-1", "tenant_id": "tenant-1"}
        await handlers.on_connect(mock_websocket, "client-1", metadata)

        # Verify metadata was passed to manager
        call_args = mock_manager.register.call_args[0]
        assert call_args[2] == metadata

    async def test_on_connect_empty_client_id_raises_error(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
    ) -> None:
        """Test that empty client_id raises error."""
        with pytest.raises(ValueError, match="client_id cannot be empty"):
            await handlers.on_connect(mock_websocket, "")


class TestOnDisconnect:
    """Test on_disconnect handler."""

    async def test_on_disconnect_success(
        self,
        handlers: WebSocketHandlers,
        mock_manager: MagicMock,
    ) -> None:
        """Test successful disconnection."""
        await handlers.on_disconnect("client-1")

        mock_manager.unregister.assert_called_once_with("client-1")

    async def test_on_disconnect_with_reason(
        self,
        handlers: WebSocketHandlers,
        mock_manager: MagicMock,
    ) -> None:
        """Test disconnection with reason."""
        await handlers.on_disconnect("client-1", "timeout")

        mock_manager.unregister.assert_called_once_with("client-1")


class TestOnMessage:
    """Test on_message handler."""

    async def test_on_message_subscribe(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
    ) -> None:
        """Test handling subscribe message."""
        message = json.dumps(
            {
                "type": "subscribe",
                "topics": ["agent-events"],
            }
        )

        with patch.object(handlers, "handle_subscribe", new=AsyncMock()) as mock_sub:
            await handlers.on_message(mock_websocket, "client-1", message)

            mock_sub.assert_called_once()

    async def test_on_message_unsubscribe(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
    ) -> None:
        """Test handling unsubscribe message."""
        message = json.dumps(
            {
                "type": "unsubscribe",
                "topics": ["agent-events"],
            }
        )

        with patch.object(handlers, "handle_unsubscribe", new=AsyncMock()) as mock_unsub:
            await handlers.on_message(mock_websocket, "client-1", message)

            mock_unsub.assert_called_once()

    async def test_on_message_ping(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
    ) -> None:
        """Test handling ping message."""
        message = json.dumps({"type": "ping"})

        await handlers.on_message(mock_websocket, "client-1", message)

        # Verify pong was sent
        mock_websocket.send_text.assert_called_once()
        sent_message = json.loads(mock_websocket.send_text.call_args[0][0])
        assert sent_message["type"] == "pong"

    async def test_on_message_invalid_json(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
    ) -> None:
        """Test handling invalid JSON."""
        await handlers.on_message(mock_websocket, "client-1", "invalid json")

        # Verify error was sent
        mock_websocket.send_text.assert_called_once()
        sent_message = json.loads(mock_websocket.send_text.call_args[0][0])
        assert sent_message["type"] == "error"
        assert sent_message["error_code"] == "invalid_json"

    async def test_on_message_missing_type(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
    ) -> None:
        """Test handling message without type field."""
        message = json.dumps({"data": "test"})

        await handlers.on_message(mock_websocket, "client-1", message)

        # Verify error was sent
        mock_websocket.send_text.assert_called_once()
        sent_message = json.loads(mock_websocket.send_text.call_args[0][0])
        assert sent_message["type"] == "error"
        assert sent_message["error_code"] == "invalid_message"

    async def test_on_message_unknown_type(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
    ) -> None:
        """Test handling unknown message type."""
        message = json.dumps({"type": "unknown"})

        await handlers.on_message(mock_websocket, "client-1", message)

        # Verify error was sent
        mock_websocket.send_text.assert_called_once()
        sent_message = json.loads(mock_websocket.send_text.call_args[0][0])
        assert sent_message["type"] == "error"
        assert sent_message["error_code"] == "unknown_message_type"


class TestHandleSubscribe:
    """Test handle_subscribe method."""

    async def test_handle_subscribe_success(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
        mock_manager: MagicMock,
    ) -> None:
        """Test successful subscription."""
        data = {
            "type": "subscribe",
            "topics": ["agent-events", "policy-events"],
        }

        await handlers.handle_subscribe(mock_websocket, "client-1", data)

        # Verify subscriptions were made
        assert mock_manager.subscribe.call_count == 2
        mock_manager.subscribe.assert_any_call("client-1", "agent-events")
        mock_manager.subscribe.assert_any_call("client-1", "policy-events")

        # Verify confirmation was sent
        mock_websocket.send_text.assert_called_once()
        sent_message = json.loads(mock_websocket.send_text.call_args[0][0])
        assert sent_message["type"] == "subscribed"
        assert set(sent_message["topics"]) == {"agent-events", "policy-events"}

    async def test_handle_subscribe_missing_topics(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
    ) -> None:
        """Test subscription without topics."""
        data = {"type": "subscribe"}

        await handlers.handle_subscribe(mock_websocket, "client-1", data)

        # Verify error was sent
        mock_websocket.send_text.assert_called_once()
        sent_message = json.loads(mock_websocket.send_text.call_args[0][0])
        assert sent_message["type"] == "error"
        assert sent_message["error_code"] == "invalid_subscribe"

    async def test_handle_subscribe_invalid_topics_type(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
    ) -> None:
        """Test subscription with invalid topics type."""
        data = {"type": "subscribe", "topics": "not-a-list"}

        await handlers.handle_subscribe(mock_websocket, "client-1", data)

        # Verify error was sent
        mock_websocket.send_text.assert_called_once()
        sent_message = json.loads(mock_websocket.send_text.call_args[0][0])
        assert sent_message["type"] == "error"

    async def test_handle_subscribe_partial_failure(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
        mock_manager: MagicMock,
    ) -> None:
        """Test subscription with some topics failing."""
        # Make second subscription fail
        mock_manager.subscribe.side_effect = [None, Exception("Failed"), None]

        data = {
            "type": "subscribe",
            "topics": ["topic-1", "topic-2", "topic-3"],
        }

        await handlers.handle_subscribe(mock_websocket, "client-1", data)

        # Verify only successful topics in confirmation
        sent_message = json.loads(mock_websocket.send_text.call_args[0][0])
        assert sent_message["type"] == "subscribed"
        assert "topic-2" not in sent_message["topics"]


class TestHandleUnsubscribe:
    """Test handle_unsubscribe method."""

    async def test_handle_unsubscribe_success(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
        mock_manager: MagicMock,
    ) -> None:
        """Test successful unsubscription."""
        data = {
            "type": "unsubscribe",
            "topics": ["agent-events", "policy-events"],
        }

        await handlers.handle_unsubscribe(mock_websocket, "client-1", data)

        # Verify unsubscriptions were made
        assert mock_manager.unsubscribe.call_count == 2
        mock_manager.unsubscribe.assert_any_call("client-1", "agent-events")
        mock_manager.unsubscribe.assert_any_call("client-1", "policy-events")

        # Verify confirmation was sent
        mock_websocket.send_text.assert_called_once()
        sent_message = json.loads(mock_websocket.send_text.call_args[0][0])
        assert sent_message["type"] == "unsubscribed"

    async def test_handle_unsubscribe_missing_topics(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
    ) -> None:
        """Test unsubscription without topics."""
        data = {"type": "unsubscribe"}

        await handlers.handle_unsubscribe(mock_websocket, "client-1", data)

        # Verify error was sent
        mock_websocket.send_text.assert_called_once()
        sent_message = json.loads(mock_websocket.send_text.call_args[0][0])
        assert sent_message["type"] == "error"
        assert sent_message["error_code"] == "invalid_unsubscribe"

    async def test_handle_unsubscribe_invalid_topics_type(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
    ) -> None:
        """Test unsubscription with invalid topics type."""
        data = {"type": "unsubscribe", "topics": "not-a-list"}

        await handlers.handle_unsubscribe(mock_websocket, "client-1", data)

        # Verify error was sent
        sent_message = json.loads(mock_websocket.send_text.call_args[0][0])
        assert sent_message["type"] == "error"


class TestHelperMethods:
    """Test helper methods."""

    async def test_send_message(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
    ) -> None:
        """Test sending message."""
        data = {"type": "test", "value": 123}

        await handlers._send_message(mock_websocket, data)

        mock_websocket.send_text.assert_called_once()
        sent_message = json.loads(mock_websocket.send_text.call_args[0][0])
        assert sent_message == data

    async def test_send_error(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
    ) -> None:
        """Test sending error message."""
        await handlers._send_error(mock_websocket, "test_error", "Test error message")

        mock_websocket.send_text.assert_called_once()
        sent_message = json.loads(mock_websocket.send_text.call_args[0][0])
        assert sent_message["type"] == "error"
        assert sent_message["error_code"] == "test_error"
        assert sent_message["error_message"] == "Test error message"

    def test_get_timestamp(self, handlers: WebSocketHandlers) -> None:
        """Test getting timestamp."""
        timestamp = handlers._get_timestamp()

        assert isinstance(timestamp, float)
        assert timestamp > 0

    async def test_handle_ping(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
    ) -> None:
        """Test ping handler."""
        await handlers._handle_ping(mock_websocket, "client-1")

        mock_websocket.send_text.assert_called_once()
        sent_message = json.loads(mock_websocket.send_text.call_args[0][0])
        assert sent_message["type"] == "pong"


class TestSetAuthService:
    """Test authentication service management."""

    def test_set_auth_service(
        self,
        handlers: WebSocketHandlers,
        mock_auth_service: MagicMock,
    ) -> None:
        """Test setting auth service."""
        assert handlers._auth_service is None

        handlers.set_auth_service(mock_auth_service)

        assert handlers._auth_service == mock_auth_service


class TestGetManager:
    """Test getting manager instance."""

    def test_get_manager(
        self,
        handlers: WebSocketHandlers,
        mock_manager: MagicMock,
    ) -> None:
        """Test getting manager."""
        manager = handlers.get_manager()

        assert manager == mock_manager


class TestErrorHandling:
    """Test error handling scenarios."""

    async def test_send_message_error(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
    ) -> None:
        """Test handling error when sending message."""
        mock_websocket.send_text.side_effect = Exception("Connection closed")

        # Should not raise
        await handlers._send_message(mock_websocket, {"type": "test"})

    async def test_on_message_handler_exception(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
        mock_manager: MagicMock,
    ) -> None:
        """Test handling exception in message handler."""
        mock_manager.subscribe.side_effect = Exception("Database error")

        message = json.dumps(
            {
                "type": "subscribe",
                "topics": ["test"],
            }
        )

        # Should not raise, but send error
        await handlers.on_message(mock_websocket, "client-1", message)

        # Verify error was sent
        assert mock_websocket.send_text.call_count >= 1


class TestEdgeCases:
    """Test edge cases."""

    async def test_subscribe_empty_topics_list(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
        mock_manager: MagicMock,
    ) -> None:
        """Test subscribing with empty topics list."""
        data = {"type": "subscribe", "topics": []}

        await handlers.handle_subscribe(mock_websocket, "client-1", data)

        # Should send error
        sent_message = json.loads(mock_websocket.send_text.call_args[0][0])
        assert sent_message["type"] == "error"

    async def test_multiple_pings(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
    ) -> None:
        """Test handling multiple ping messages."""
        for _ in range(5):
            message = json.dumps({"type": "ping"})
            await handlers.on_message(mock_websocket, "client-1", message)

        # Verify 5 pongs were sent
        assert mock_websocket.send_text.call_count == 5

    async def test_subscribe_with_tenant_id(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
        mock_manager: MagicMock,
    ) -> None:
        """Test subscription with tenant_id for authorization."""
        data = {
            "type": "subscribe",
            "topics": ["agent-events"],
            "tenant_id": "tenant-123",
        }

        await handlers.handle_subscribe(mock_websocket, "client-1", data)

        # Should still subscribe successfully
        mock_manager.subscribe.assert_called_once_with("client-1", "agent-events")

    async def test_unsubscribe_with_exception_in_topic(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
        mock_manager: MagicMock,
    ) -> None:
        """Test unsubscribe when topic raises exception."""
        mock_manager.unsubscribe.side_effect = Exception("Unsubscribe failed")

        data = {
            "type": "unsubscribe",
            "topics": ["topic-1"],
        }

        await handlers.handle_unsubscribe(mock_websocket, "client-1", data)

        # Should send confirmation even if unsubscribe failed
        sent_message = json.loads(mock_websocket.send_text.call_args[0][0])
        assert sent_message["type"] == "unsubscribed"
        assert sent_message["topics"] == []

    async def test_on_message_generic_exception(
        self,
        handlers: WebSocketHandlers,
        mock_websocket: MagicMock,
    ) -> None:
        """Test on_message handling generic exception."""
        # Patch handle_subscribe to raise a non-JSON exception
        with patch.object(
            handlers, "handle_subscribe", side_effect=RuntimeError("Unexpected error")
        ):
            message = json.dumps({"type": "subscribe", "topics": ["test"]})

            # Should not raise, but send error
            await handlers.on_message(mock_websocket, "client-1", message)

            # Verify error was sent
            sent_message = json.loads(mock_websocket.send_text.call_args[0][0])
            assert sent_message["type"] == "error"
            assert sent_message["error_code"] == "internal_error"
