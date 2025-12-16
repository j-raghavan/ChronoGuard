"""WebSocket connection manager for pub/sub and connection tracking.

This module implements connection registry, subscription management, and
real-time event broadcasting for WebSocket connections.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from loguru import logger


if TYPE_CHECKING:
    from fastapi import WebSocket


class ConnectionInfo:
    """Information about an active WebSocket connection.

    Attributes:
        client_id: Unique client identifier
        websocket: WebSocket connection instance
        subscriptions: Set of topics the client is subscribed to
        metadata: Additional connection metadata
    """

    def __init__(
        self,
        client_id: str,
        websocket: WebSocket,
        metadata: dict[str, Any],
    ) -> None:
        """Initialize connection info.

        Args:
            client_id: Unique client identifier
            websocket: WebSocket connection instance
            metadata: Connection metadata
        """
        self.client_id = client_id
        self.websocket = websocket
        self.subscriptions: set[str] = set()
        self.metadata = metadata


class WebSocketManager:
    """Manages WebSocket connections and pub/sub functionality.

    This manager maintains a registry of active WebSocket connections,
    handles subscription management, and provides broadcast capabilities
    for real-time event delivery.

    Features:
    - Connection registration and lifecycle management
    - Topic-based subscription system
    - Targeted and broadcast message delivery
    - Connection metadata tracking

    Example:
        >>> manager = WebSocketManager()
        >>> await manager.register(websocket, "client-1", {})
        >>> await manager.subscribe("client-1", "agent-events")
        >>> await manager.broadcast("agent-events", {"event": "agent_created"})
        >>> await manager.unregister("client-1")
    """

    def __init__(self) -> None:
        """Initialize the WebSocket manager."""
        self._connections: dict[str, ConnectionInfo] = {}
        self._topic_subscribers: dict[str, set[str]] = {}

    async def register(
        self,
        websocket: WebSocket,
        client_id: str,
        metadata: dict[str, Any],
    ) -> None:
        """Register a new WebSocket connection.

        Args:
            websocket: WebSocket connection instance
            client_id: Unique identifier for the client
            metadata: Connection metadata (user info, tenant, etc.)

        Raises:
            ValueError: If client_id is empty
        """
        if not client_id:
            raise ValueError("client_id cannot be empty")

        # Create connection info
        conn_info = ConnectionInfo(client_id, websocket, metadata)

        # Store connection
        self._connections[client_id] = conn_info

        logger.info(
            f"Registered WebSocket connection for client '{client_id}' "
            f"(total connections: {len(self._connections)})"
        )

    async def unregister(self, client_id: str) -> None:
        """Unregister a WebSocket connection.

        Removes the connection and cleans up all subscriptions.

        Args:
            client_id: Identifier for the client to unregister

        Raises:
            ValueError: If client is not registered
        """
        if client_id not in self._connections:
            raise ValueError(f"Client '{client_id}' is not registered")

        # Get connection info
        conn_info = self._connections[client_id]

        # Remove from all topic subscriptions
        for topic in list(conn_info.subscriptions):
            await self._remove_from_topic(client_id, topic)

        # Remove connection
        del self._connections[client_id]

        logger.info(
            f"Unregistered client '{client_id}' (remaining connections: {len(self._connections)})"
        )

    async def subscribe(self, client_id: str, topic: str) -> None:
        """Subscribe a client to a topic.

        Args:
            client_id: Identifier for the client
            topic: Topic name to subscribe to

        Raises:
            ValueError: If client is not registered or topic is empty
        """
        if not topic:
            raise ValueError("topic cannot be empty")

        if client_id not in self._connections:
            raise ValueError(f"Client '{client_id}' is not registered")

        conn_info = self._connections[client_id]

        # Add to connection's subscriptions
        conn_info.subscriptions.add(topic)

        # Add to topic's subscribers
        if topic not in self._topic_subscribers:
            self._topic_subscribers[topic] = set()
        self._topic_subscribers[topic].add(client_id)

        logger.debug(
            f"Client '{client_id}' subscribed to topic '{topic}' "
            f"(topic subscribers: {len(self._topic_subscribers[topic])})"
        )

    async def unsubscribe(self, client_id: str, topic: str) -> None:
        """Unsubscribe a client from a topic.

        Args:
            client_id: Identifier for the client
            topic: Topic name to unsubscribe from

        Raises:
            ValueError: If client is not registered or not subscribed to topic
        """
        if client_id not in self._connections:
            raise ValueError(f"Client '{client_id}' is not registered")

        conn_info = self._connections[client_id]

        if topic not in conn_info.subscriptions:
            raise ValueError(f"Client '{client_id}' is not subscribed to topic '{topic}'")

        await self._remove_from_topic(client_id, topic)

        logger.debug(f"Client '{client_id}' unsubscribed from topic '{topic}'")

    async def broadcast(
        self,
        topic: str,
        message: dict[str, Any],
        exclude_client: str | None = None,
    ) -> int:
        """Broadcast a message to all subscribers of a topic.

        Args:
            topic: Topic to broadcast to
            message: Message data to send
            exclude_client: Optional client ID to exclude from broadcast

        Returns:
            Number of clients the message was sent to

        Raises:
            ValueError: If topic is empty
        """
        if not topic:
            raise ValueError("topic cannot be empty")

        # Get subscribers for topic
        subscribers = self._topic_subscribers.get(topic, set())

        # Filter out excluded client
        if exclude_client:
            subscribers = subscribers - {exclude_client}

        # Send to all subscribers (use list to avoid set modification during iteration)
        sent_count = 0
        for client_id in list(subscribers):
            if await self.send_to(client_id, message):
                sent_count += 1

        logger.debug(
            f"Broadcast message to topic '{topic}': "
            f"sent to {sent_count}/{len(subscribers)} subscribers"
        )

        return sent_count

    async def send_to(
        self,
        client_id: str,
        message: dict[str, Any],
    ) -> bool:
        """Send a message to a specific client.

        Args:
            client_id: Identifier for the client
            message: Message data to send

        Returns:
            True if message was sent successfully, False otherwise
        """
        if client_id not in self._connections:
            logger.warning(f"Cannot send to unregistered client '{client_id}'")
            return False

        conn_info = self._connections[client_id]

        try:
            # Convert message to JSON
            json_message = json.dumps(message)

            # Send via WebSocket
            await conn_info.websocket.send_text(json_message)

            logger.debug(f"Sent message to client '{client_id}'")
            return True

        except Exception as e:
            logger.error(
                f"Failed to send message to client '{client_id}': {e}",
                exc_info=True,
            )
            # Connection might be dead, unregister it
            try:
                await self.unregister(client_id)
            except Exception as cleanup_error:
                logger.debug(f"Failed to unregister dead connection '{client_id}': {cleanup_error}")
            return False

    def get_connection_count(self) -> int:
        """Get the total number of active connections.

        Returns:
            Number of active connections
        """
        return len(self._connections)

    def get_topic_subscriber_count(self, topic: str) -> int:
        """Get the number of subscribers for a topic.

        Args:
            topic: Topic name

        Returns:
            Number of subscribers for the topic
        """
        return len(self._topic_subscribers.get(topic, set()))

    def get_client_subscriptions(self, client_id: str) -> set[str]:
        """Get all topics a client is subscribed to.

        Args:
            client_id: Identifier for the client

        Returns:
            Set of topic names the client is subscribed to

        Raises:
            ValueError: If client is not registered
        """
        if client_id not in self._connections:
            raise ValueError(f"Client '{client_id}' is not registered")

        return self._connections[client_id].subscriptions.copy()

    def is_registered(self, client_id: str) -> bool:
        """Check if a client is registered.

        Args:
            client_id: Identifier for the client

        Returns:
            True if client is registered, False otherwise
        """
        return client_id in self._connections

    def get_all_topics(self) -> list[str]:
        """Get all active topics.

        Returns:
            List of topic names that have at least one subscriber
        """
        return list(self._topic_subscribers.keys())

    def get_connection_metadata(self, client_id: str) -> dict[str, Any]:
        """Get metadata for a connection.

        Args:
            client_id: Identifier for the client

        Returns:
            Connection metadata

        Raises:
            ValueError: If client is not registered
        """
        if client_id not in self._connections:
            raise ValueError(f"Client '{client_id}' is not registered")

        return self._connections[client_id].metadata.copy()

    async def broadcast_to_all(self, message: dict[str, Any]) -> int:
        """Broadcast a message to all connected clients.

        Args:
            message: Message data to send

        Returns:
            Number of clients the message was sent to
        """
        sent_count = 0
        for client_id in list(self._connections.keys()):
            if await self.send_to(client_id, message):
                sent_count += 1

        logger.debug(f"Broadcast message to all clients: sent to {sent_count} clients")

        return sent_count

    async def _remove_from_topic(self, client_id: str, topic: str) -> None:
        """Remove a client from a topic's subscribers.

        Args:
            client_id: Identifier for the client
            topic: Topic name
        """
        # Remove from connection's subscriptions
        conn_info = self._connections.get(client_id)
        if conn_info:
            conn_info.subscriptions.discard(topic)

        # Remove from topic's subscribers
        if topic in self._topic_subscribers:
            self._topic_subscribers[topic].discard(client_id)

            # Clean up empty topic
            if not self._topic_subscribers[topic]:
                del self._topic_subscribers[topic]
                logger.debug(f"Topic '{topic}' removed (no subscribers)")

    def get_stats(self) -> dict[str, Any]:
        """Get statistics about the WebSocket manager.

        Returns:
            Dictionary containing manager statistics
        """
        return {
            "total_connections": len(self._connections),
            "total_topics": len(self._topic_subscribers),
            "topics": [
                {
                    "topic": topic,
                    "subscriber_count": len(subscribers),
                }
                for topic, subscribers in self._topic_subscribers.items()
            ],
        }
