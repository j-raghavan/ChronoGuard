"""Comprehensive tests for WebSocket manager."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from presentation.websocket.manager import ConnectionInfo, WebSocketManager


@pytest.fixture
def mock_websocket() -> MagicMock:
    """Create a mock WebSocket."""
    ws = MagicMock()
    ws.send_text = AsyncMock()
    ws.close = AsyncMock()
    return ws


@pytest.fixture
def manager() -> WebSocketManager:
    """Create a WebSocket manager instance."""
    return WebSocketManager()


@pytest.fixture
def sample_metadata() -> dict[str, Any]:
    """Create sample connection metadata."""
    return {
        "user_id": "user-1",
        "tenant_id": "tenant-1",
        "ip_address": "192.168.1.1",
    }


class TestConnectionInfo:
    """Test ConnectionInfo class."""

    def test_connection_info_creation(self, mock_websocket: MagicMock) -> None:
        """Test creating ConnectionInfo."""
        metadata = {"user_id": "user-1"}
        conn_info = ConnectionInfo("client-1", mock_websocket, metadata)

        assert conn_info.client_id == "client-1"
        assert conn_info.websocket == mock_websocket
        assert conn_info.metadata == metadata
        assert conn_info.subscriptions == set()


class TestWebSocketManagerInit:
    """Test WebSocketManager initialization."""

    def test_initialization(self) -> None:
        """Test manager initialization."""
        manager = WebSocketManager()

        assert manager._connections == {}
        assert manager._topic_subscribers == {}


class TestRegister:
    """Test connection registration."""

    async def test_register_success(
        self,
        manager: WebSocketManager,
        mock_websocket: MagicMock,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test successful registration."""
        await manager.register(mock_websocket, "client-1", sample_metadata)

        assert manager.is_registered("client-1")
        assert manager.get_connection_count() == 1

    async def test_register_empty_client_id_raises_error(
        self,
        manager: WebSocketManager,
        mock_websocket: MagicMock,
    ) -> None:
        """Test that empty client_id raises error."""
        with pytest.raises(ValueError, match="client_id cannot be empty"):
            await manager.register(mock_websocket, "", {})

    async def test_register_multiple_clients(
        self,
        manager: WebSocketManager,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test registering multiple clients."""
        for i in range(5):
            ws = MagicMock()
            ws.send_text = AsyncMock()
            await manager.register(ws, f"client-{i}", sample_metadata)

        assert manager.get_connection_count() == 5

    async def test_register_overwrites_existing(
        self,
        manager: WebSocketManager,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test that re-registering overwrites existing connection."""
        ws1 = MagicMock()
        ws1.send_text = AsyncMock()
        ws2 = MagicMock()
        ws2.send_text = AsyncMock()

        await manager.register(ws1, "client-1", sample_metadata)
        await manager.register(ws2, "client-1", sample_metadata)

        # Should still have 1 connection
        assert manager.get_connection_count() == 1
        # But with the new WebSocket
        conn_info = manager._connections["client-1"]
        assert conn_info.websocket == ws2


class TestUnregister:
    """Test connection unregistration."""

    async def test_unregister_success(
        self,
        manager: WebSocketManager,
        mock_websocket: MagicMock,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test successful unregistration."""
        await manager.register(mock_websocket, "client-1", sample_metadata)
        await manager.unregister("client-1")

        assert not manager.is_registered("client-1")
        assert manager.get_connection_count() == 0

    async def test_unregister_not_registered_raises_error(
        self,
        manager: WebSocketManager,
    ) -> None:
        """Test unregistering non-existent client raises error."""
        with pytest.raises(ValueError, match="is not registered"):
            await manager.unregister("non-existent")

    async def test_unregister_cleans_up_subscriptions(
        self,
        manager: WebSocketManager,
        mock_websocket: MagicMock,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test that unregister removes all subscriptions."""
        await manager.register(mock_websocket, "client-1", sample_metadata)
        await manager.subscribe("client-1", "topic-1")
        await manager.subscribe("client-1", "topic-2")

        await manager.unregister("client-1")

        # Topics should be cleaned up
        assert manager.get_topic_subscriber_count("topic-1") == 0
        assert manager.get_topic_subscriber_count("topic-2") == 0
        assert len(manager.get_all_topics()) == 0


class TestSubscribe:
    """Test topic subscription."""

    async def test_subscribe_success(
        self,
        manager: WebSocketManager,
        mock_websocket: MagicMock,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test successful subscription."""
        await manager.register(mock_websocket, "client-1", sample_metadata)
        await manager.subscribe("client-1", "agent-events")

        assert manager.get_topic_subscriber_count("agent-events") == 1
        subscriptions = manager.get_client_subscriptions("client-1")
        assert "agent-events" in subscriptions

    async def test_subscribe_empty_topic_raises_error(
        self,
        manager: WebSocketManager,
        mock_websocket: MagicMock,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test that empty topic raises error."""
        await manager.register(mock_websocket, "client-1", sample_metadata)

        with pytest.raises(ValueError, match="topic cannot be empty"):
            await manager.subscribe("client-1", "")

    async def test_subscribe_unregistered_client_raises_error(
        self,
        manager: WebSocketManager,
    ) -> None:
        """Test subscribing unregistered client raises error."""
        with pytest.raises(ValueError, match="is not registered"):
            await manager.subscribe("non-existent", "topic-1")

    async def test_subscribe_multiple_topics(
        self,
        manager: WebSocketManager,
        mock_websocket: MagicMock,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test subscribing to multiple topics."""
        await manager.register(mock_websocket, "client-1", sample_metadata)

        topics = ["topic-1", "topic-2", "topic-3"]
        for topic in topics:
            await manager.subscribe("client-1", topic)

        subscriptions = manager.get_client_subscriptions("client-1")
        assert subscriptions == set(topics)

    async def test_subscribe_multiple_clients_same_topic(
        self,
        manager: WebSocketManager,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test multiple clients subscribing to same topic."""
        for i in range(3):
            ws = MagicMock()
            ws.send_text = AsyncMock()
            await manager.register(ws, f"client-{i}", sample_metadata)
            await manager.subscribe(f"client-{i}", "shared-topic")

        assert manager.get_topic_subscriber_count("shared-topic") == 3


class TestUnsubscribe:
    """Test topic unsubscription."""

    async def test_unsubscribe_success(
        self,
        manager: WebSocketManager,
        mock_websocket: MagicMock,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test successful unsubscription."""
        await manager.register(mock_websocket, "client-1", sample_metadata)
        await manager.subscribe("client-1", "topic-1")
        await manager.unsubscribe("client-1", "topic-1")

        subscriptions = manager.get_client_subscriptions("client-1")
        assert "topic-1" not in subscriptions
        assert manager.get_topic_subscriber_count("topic-1") == 0

    async def test_unsubscribe_unregistered_client_raises_error(
        self,
        manager: WebSocketManager,
    ) -> None:
        """Test unsubscribing unregistered client raises error."""
        with pytest.raises(ValueError, match="is not registered"):
            await manager.unsubscribe("non-existent", "topic-1")

    async def test_unsubscribe_not_subscribed_raises_error(
        self,
        manager: WebSocketManager,
        mock_websocket: MagicMock,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test unsubscribing from non-subscribed topic raises error."""
        await manager.register(mock_websocket, "client-1", sample_metadata)

        with pytest.raises(ValueError, match="is not subscribed"):
            await manager.unsubscribe("client-1", "topic-1")

    async def test_unsubscribe_removes_empty_topic(
        self,
        manager: WebSocketManager,
        mock_websocket: MagicMock,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test that unsubscribing last client removes topic."""
        await manager.register(mock_websocket, "client-1", sample_metadata)
        await manager.subscribe("client-1", "topic-1")
        await manager.unsubscribe("client-1", "topic-1")

        # Topic should be removed from registry
        assert "topic-1" not in manager.get_all_topics()


class TestBroadcast:
    """Test broadcasting messages."""

    async def test_broadcast_success(
        self,
        manager: WebSocketManager,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test successful broadcast."""
        # Register 3 clients
        websockets = []
        for i in range(3):
            ws = MagicMock()
            ws.send_text = AsyncMock()
            websockets.append(ws)
            await manager.register(ws, f"client-{i}", sample_metadata)
            await manager.subscribe(f"client-{i}", "topic-1")

        message = {"type": "event", "data": "test"}
        sent_count = await manager.broadcast("topic-1", message)

        assert sent_count == 3
        # Verify all clients received the message
        for ws in websockets:
            ws.send_text.assert_called_once()

    async def test_broadcast_empty_topic_raises_error(
        self,
        manager: WebSocketManager,
    ) -> None:
        """Test that empty topic raises error."""
        with pytest.raises(ValueError, match="topic cannot be empty"):
            await manager.broadcast("", {"test": "data"})

    async def test_broadcast_no_subscribers(
        self,
        manager: WebSocketManager,
    ) -> None:
        """Test broadcasting to topic with no subscribers."""
        sent_count = await manager.broadcast("empty-topic", {"test": "data"})

        assert sent_count == 0

    async def test_broadcast_exclude_client(
        self,
        manager: WebSocketManager,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test broadcasting with excluded client."""
        # Register 3 clients
        for i in range(3):
            ws = MagicMock()
            ws.send_text = AsyncMock()
            await manager.register(ws, f"client-{i}", sample_metadata)
            await manager.subscribe(f"client-{i}", "topic-1")

        message = {"type": "event", "data": "test"}
        sent_count = await manager.broadcast("topic-1", message, exclude_client="client-1")

        # Should only send to 2 clients (excluding client-1)
        assert sent_count == 2


class TestSendTo:
    """Test sending message to specific client."""

    async def test_send_to_success(
        self,
        manager: WebSocketManager,
        mock_websocket: MagicMock,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test successful send."""
        await manager.register(mock_websocket, "client-1", sample_metadata)

        message = {"type": "notification", "content": "test"}
        result = await manager.send_to("client-1", message)

        assert result is True
        mock_websocket.send_text.assert_called_once()

        # Verify message content
        sent_data = json.loads(mock_websocket.send_text.call_args[0][0])
        assert sent_data == message

    async def test_send_to_unregistered_client(
        self,
        manager: WebSocketManager,
    ) -> None:
        """Test sending to unregistered client returns False."""
        result = await manager.send_to("non-existent", {"test": "data"})

        assert result is False

    async def test_send_to_websocket_error(
        self,
        manager: WebSocketManager,
        mock_websocket: MagicMock,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test handling WebSocket error during send."""
        await manager.register(mock_websocket, "client-1", sample_metadata)
        mock_websocket.send_text.side_effect = Exception("Connection lost")

        result = await manager.send_to("client-1", {"test": "data"})

        assert result is False
        # Client should be unregistered after error
        assert not manager.is_registered("client-1")


class TestGetConnectionCount:
    """Test getting connection count."""

    async def test_get_connection_count_empty(
        self,
        manager: WebSocketManager,
    ) -> None:
        """Test count with no connections."""
        assert manager.get_connection_count() == 0

    async def test_get_connection_count_populated(
        self,
        manager: WebSocketManager,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test count with connections."""
        for i in range(5):
            ws = MagicMock()
            ws.send_text = AsyncMock()
            await manager.register(ws, f"client-{i}", sample_metadata)

        assert manager.get_connection_count() == 5


class TestGetTopicSubscriberCount:
    """Test getting topic subscriber count."""

    async def test_get_subscriber_count_no_topic(
        self,
        manager: WebSocketManager,
    ) -> None:
        """Test count for non-existent topic."""
        assert manager.get_topic_subscriber_count("non-existent") == 0

    async def test_get_subscriber_count_with_subscribers(
        self,
        manager: WebSocketManager,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test count with subscribers."""
        for i in range(3):
            ws = MagicMock()
            ws.send_text = AsyncMock()
            await manager.register(ws, f"client-{i}", sample_metadata)
            await manager.subscribe(f"client-{i}", "popular-topic")

        assert manager.get_topic_subscriber_count("popular-topic") == 3


class TestGetClientSubscriptions:
    """Test getting client subscriptions."""

    async def test_get_subscriptions_success(
        self,
        manager: WebSocketManager,
        mock_websocket: MagicMock,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test getting subscriptions for client."""
        await manager.register(mock_websocket, "client-1", sample_metadata)
        await manager.subscribe("client-1", "topic-1")
        await manager.subscribe("client-1", "topic-2")

        subscriptions = manager.get_client_subscriptions("client-1")

        assert subscriptions == {"topic-1", "topic-2"}

    def test_get_subscriptions_unregistered_client_raises_error(
        self,
        manager: WebSocketManager,
    ) -> None:
        """Test getting subscriptions for unregistered client raises error."""
        with pytest.raises(ValueError, match="is not registered"):
            manager.get_client_subscriptions("non-existent")


class TestIsRegistered:
    """Test checking if client is registered."""

    async def test_is_registered_true(
        self,
        manager: WebSocketManager,
        mock_websocket: MagicMock,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test checking registered client."""
        await manager.register(mock_websocket, "client-1", sample_metadata)

        assert manager.is_registered("client-1") is True

    def test_is_registered_false(
        self,
        manager: WebSocketManager,
    ) -> None:
        """Test checking unregistered client."""
        assert manager.is_registered("non-existent") is False


class TestGetAllTopics:
    """Test getting all topics."""

    def test_get_all_topics_empty(
        self,
        manager: WebSocketManager,
    ) -> None:
        """Test with no topics."""
        assert manager.get_all_topics() == []

    async def test_get_all_topics_populated(
        self,
        manager: WebSocketManager,
        mock_websocket: MagicMock,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test with multiple topics."""
        await manager.register(mock_websocket, "client-1", sample_metadata)

        topics = ["topic-1", "topic-2", "topic-3"]
        for topic in topics:
            await manager.subscribe("client-1", topic)

        all_topics = manager.get_all_topics()
        assert set(all_topics) == set(topics)


class TestGetConnectionMetadata:
    """Test getting connection metadata."""

    async def test_get_metadata_success(
        self,
        manager: WebSocketManager,
        mock_websocket: MagicMock,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test getting metadata for connection."""
        await manager.register(mock_websocket, "client-1", sample_metadata)

        metadata = manager.get_connection_metadata("client-1")

        assert metadata == sample_metadata

    def test_get_metadata_unregistered_client_raises_error(
        self,
        manager: WebSocketManager,
    ) -> None:
        """Test getting metadata for unregistered client raises error."""
        with pytest.raises(ValueError, match="is not registered"):
            manager.get_connection_metadata("non-existent")


class TestBroadcastToAll:
    """Test broadcasting to all clients."""

    async def test_broadcast_to_all_success(
        self,
        manager: WebSocketManager,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test broadcasting to all clients."""
        # Register 5 clients
        for i in range(5):
            ws = MagicMock()
            ws.send_text = AsyncMock()
            await manager.register(ws, f"client-{i}", sample_metadata)

        message = {"type": "announcement", "content": "test"}
        sent_count = await manager.broadcast_to_all(message)

        assert sent_count == 5

    async def test_broadcast_to_all_empty(
        self,
        manager: WebSocketManager,
    ) -> None:
        """Test broadcasting with no clients."""
        sent_count = await manager.broadcast_to_all({"test": "data"})

        assert sent_count == 0


class TestGetStats:
    """Test getting manager statistics."""

    def test_get_stats_empty(
        self,
        manager: WebSocketManager,
    ) -> None:
        """Test stats with no connections."""
        stats = manager.get_stats()

        assert stats["total_connections"] == 0
        assert stats["total_topics"] == 0
        assert stats["topics"] == []

    async def test_get_stats_populated(
        self,
        manager: WebSocketManager,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test stats with connections and topics."""
        # Register clients and subscribe to topics
        for i in range(3):
            ws = MagicMock()
            ws.send_text = AsyncMock()
            await manager.register(ws, f"client-{i}", sample_metadata)
            await manager.subscribe(f"client-{i}", "topic-1")

        stats = manager.get_stats()

        assert stats["total_connections"] == 3
        assert stats["total_topics"] == 1
        assert len(stats["topics"]) == 1
        assert stats["topics"][0]["topic"] == "topic-1"
        assert stats["topics"][0]["subscriber_count"] == 3


class TestEdgeCases:
    """Test edge cases."""

    async def test_multiple_subscribe_same_topic(
        self,
        manager: WebSocketManager,
        mock_websocket: MagicMock,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test subscribing to same topic multiple times."""
        await manager.register(mock_websocket, "client-1", sample_metadata)

        # Subscribe twice to same topic
        await manager.subscribe("client-1", "topic-1")
        await manager.subscribe("client-1", "topic-1")

        # Should still be subscribed only once
        subscriptions = manager.get_client_subscriptions("client-1")
        assert len(subscriptions) == 1
        assert manager.get_topic_subscriber_count("topic-1") == 1

    async def test_broadcast_with_send_failures(
        self,
        manager: WebSocketManager,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test broadcast with some send failures."""
        # Register 3 clients, make one fail
        for i in range(3):
            ws = MagicMock()
            if i == 1:
                ws.send_text = AsyncMock(side_effect=Exception("Failed"))
            else:
                ws.send_text = AsyncMock()
            await manager.register(ws, f"client-{i}", sample_metadata)
            await manager.subscribe(f"client-{i}", "topic-1")

        sent_count = await manager.broadcast("topic-1", {"test": "data"})

        # Should send to 2 clients successfully
        assert sent_count == 2
        # Failed client should be unregistered
        assert not manager.is_registered("client-1")

    async def test_send_to_with_unregister_failure(
        self,
        manager: WebSocketManager,
        sample_metadata: dict[str, Any],
    ) -> None:
        """Test send_to when unregister also fails during cleanup."""
        ws = MagicMock()
        ws.send_text = AsyncMock(side_effect=Exception("Connection failed"))
        await manager.register(ws, "client-1", sample_metadata)
        await manager.subscribe("client-1", "topic-1")

        # Patch unregister to also fail (to test the cleanup exception handling)
        original_unregister = manager.unregister

        async def failing_unregister(client_id: str) -> None:
            # Call original to do cleanup first
            await original_unregister(client_id)
            # This won't be reached, but simulates the scenario where
            # unregister might have issues after cleanup

        with patch.object(manager, "unregister", side_effect=Exception("Cleanup failed")):
            result = await manager.send_to("client-1", {"test": "data"})

            # Should return False when send fails
            assert result is False
