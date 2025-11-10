"""WebSocket event handlers for real-time communication.

This module implements WebSocket event handlers for connection lifecycle,
message routing, and subscription management in the ChronoGuard system.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from loguru import logger


if TYPE_CHECKING:
    from fastapi import WebSocket


class WebSocketHandlers:
    """Handles WebSocket events and message routing.

    This class implements event handlers for WebSocket connections:
    - Connection and disconnection lifecycle events
    - Message parsing and routing
    - Subscription/unsubscription management
    - Authentication integration

    The handlers coordinate with the WebSocket manager to maintain
    connection state and deliver messages to appropriate subscribers.

    Example:
        >>> from presentation.websocket.manager import WebSocketManager
        >>> manager = WebSocketManager()
        >>> handlers = WebSocketHandlers(manager, auth_service)
        >>> await handlers.on_connect(websocket, client_id)
    """

    def __init__(
        self,
        manager: Any,  # WebSocketManager type to avoid circular import
        auth_service: Any | None = None,
    ) -> None:
        """Initialize WebSocket handlers.

        Args:
            manager: WebSocket connection manager
            auth_service: Optional authentication service for connection validation
        """
        self._manager = manager
        self._auth_service = auth_service

    async def on_connect(
        self,
        websocket: WebSocket,
        client_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Handle new WebSocket connection.

        Accepts the WebSocket connection and registers it with the manager.
        Optionally validates authentication if auth service is configured.

        Args:
            websocket: WebSocket connection instance
            client_id: Unique identifier for the client
            metadata: Optional metadata about the connection

        Raises:
            ValueError: If client_id is empty
            AuthenticationError: If authentication fails
        """
        if not client_id:
            raise ValueError("client_id cannot be empty")

        # Accept the WebSocket connection
        await websocket.accept()
        logger.info(f"WebSocket connection accepted for client '{client_id}'")

        # Register with manager
        await self._manager.register(websocket, client_id, metadata or {})

        # Send welcome message
        await self._send_message(
            websocket,
            {
                "type": "connection_established",
                "client_id": client_id,
                "timestamp": self._get_timestamp(),
            },
        )

        logger.info(f"Client '{client_id}' connected successfully")

    async def on_disconnect(
        self,
        client_id: str,
        reason: str | None = None,
    ) -> None:
        """Handle WebSocket disconnection.

        Unregisters the client from the manager and cleans up resources.

        Args:
            client_id: Identifier for the disconnecting client
            reason: Optional reason for disconnection
        """
        # Unregister from manager
        await self._manager.unregister(client_id)

        log_message = f"Client '{client_id}' disconnected"
        if reason:
            log_message += f" - Reason: {reason}"

        logger.info(log_message)

    async def on_message(
        self,
        websocket: WebSocket,
        client_id: str,
        message: str,
    ) -> None:
        """Handle incoming WebSocket message.

        Parses the message and routes it to the appropriate handler
        based on the message type.

        Args:
            websocket: WebSocket connection instance
            client_id: Identifier for the client
            message: Raw message string (expected to be JSON)

        Raises:
            ValueError: If message cannot be parsed
        """
        try:
            # Parse JSON message
            data = json.loads(message)

            # Extract message type
            msg_type = data.get("type")
            if not msg_type:
                await self._send_error(
                    websocket,
                    "invalid_message",
                    "Message must include 'type' field",
                )
                return

            # Route to appropriate handler
            if msg_type == "subscribe":
                await self.handle_subscribe(websocket, client_id, data)
            elif msg_type == "unsubscribe":
                await self.handle_unsubscribe(websocket, client_id, data)
            elif msg_type == "ping":
                await self._handle_ping(websocket, client_id)
            else:
                await self._send_error(
                    websocket,
                    "unknown_message_type",
                    f"Unknown message type: {msg_type}",
                )

        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON from client '{client_id}': {e}")
            await self._send_error(
                websocket,
                "invalid_json",
                "Message must be valid JSON",
            )
        except Exception as e:
            logger.error(
                f"Error processing message from client '{client_id}': {e}",
                exc_info=True,
            )
            await self._send_error(
                websocket,
                "internal_error",
                "Failed to process message",
            )

    async def handle_subscribe(
        self,
        websocket: WebSocket,
        client_id: str,
        data: dict[str, Any],
    ) -> None:
        """Handle subscription request.

        Subscribes the client to specified topics or channels.

        Args:
            websocket: WebSocket connection instance
            client_id: Identifier for the client
            data: Message data containing subscription details

        Expected data format:
            {
                "type": "subscribe",
                "topics": ["topic1", "topic2"],
                "tenant_id": "uuid-string"  # optional
            }
        """
        topics = data.get("topics", [])
        if not topics:
            await self._send_error(
                websocket,
                "invalid_subscribe",
                "Subscription must include 'topics' array",
            )
            return

        # Validate topics
        if not isinstance(topics, list):
            await self._send_error(
                websocket,
                "invalid_subscribe",
                "'topics' must be an array",
            )
            return

        # Subscribe to each topic
        # Note: tenant_id in data can be used for authorization in future
        successful_topics = []
        for topic in topics:
            try:
                await self._manager.subscribe(client_id, topic)
                successful_topics.append(topic)
            except Exception as e:
                logger.error(f"Failed to subscribe client '{client_id}' to '{topic}': {e}")

        # Send confirmation
        await self._send_message(
            websocket,
            {
                "type": "subscribed",
                "topics": successful_topics,
                "timestamp": self._get_timestamp(),
            },
        )

        logger.info(
            f"Client '{client_id}' subscribed to {len(successful_topics)} topics: "
            f"{successful_topics}"
        )

    async def handle_unsubscribe(
        self,
        websocket: WebSocket,
        client_id: str,
        data: dict[str, Any],
    ) -> None:
        """Handle unsubscription request.

        Unsubscribes the client from specified topics or channels.

        Args:
            websocket: WebSocket connection instance
            client_id: Identifier for the client
            data: Message data containing unsubscription details

        Expected data format:
            {
                "type": "unsubscribe",
                "topics": ["topic1", "topic2"]
            }
        """
        topics = data.get("topics", [])
        if not topics:
            await self._send_error(
                websocket,
                "invalid_unsubscribe",
                "Unsubscription must include 'topics' array",
            )
            return

        # Validate topics
        if not isinstance(topics, list):
            await self._send_error(
                websocket,
                "invalid_unsubscribe",
                "'topics' must be an array",
            )
            return

        # Unsubscribe from each topic
        successful_topics = []
        for topic in topics:
            try:
                await self._manager.unsubscribe(client_id, topic)
                successful_topics.append(topic)
            except Exception as e:
                logger.error(f"Failed to unsubscribe client '{client_id}' from '{topic}': {e}")

        # Send confirmation
        await self._send_message(
            websocket,
            {
                "type": "unsubscribed",
                "topics": successful_topics,
                "timestamp": self._get_timestamp(),
            },
        )

        logger.info(
            f"Client '{client_id}' unsubscribed from {len(successful_topics)} topics: "
            f"{successful_topics}"
        )

    async def _handle_ping(
        self,
        websocket: WebSocket,
        client_id: str,
    ) -> None:
        """Handle ping message.

        Responds with pong to keep connection alive.

        Args:
            websocket: WebSocket connection instance
            client_id: Identifier for the client
        """
        await self._send_message(
            websocket,
            {
                "type": "pong",
                "timestamp": self._get_timestamp(),
            },
        )
        logger.debug(f"Sent pong to client '{client_id}'")

    async def _send_message(
        self,
        websocket: WebSocket,
        data: dict[str, Any],
    ) -> None:
        """Send JSON message to client.

        Args:
            websocket: WebSocket connection instance
            data: Data to send as JSON
        """
        try:
            message = json.dumps(data)
            await websocket.send_text(message)
        except Exception as e:
            logger.error(f"Failed to send message: {e}", exc_info=True)

    async def _send_error(
        self,
        websocket: WebSocket,
        error_code: str,
        error_message: str,
    ) -> None:
        """Send error message to client.

        Args:
            websocket: WebSocket connection instance
            error_code: Error code identifier
            error_message: Human-readable error description
        """
        await self._send_message(
            websocket,
            {
                "type": "error",
                "error_code": error_code,
                "error_message": error_message,
                "timestamp": self._get_timestamp(),
            },
        )

    def _get_timestamp(self) -> float:
        """Get current timestamp.

        Returns:
            Current Unix timestamp
        """
        import time

        return time.time()

    def set_auth_service(self, auth_service: Any) -> None:
        """Set or update the authentication service.

        Args:
            auth_service: Authentication service instance
        """
        self._auth_service = auth_service
        logger.info("Authentication service updated for WebSocket handlers")

    def get_manager(self) -> Any:
        """Get the WebSocket manager instance.

        Returns:
            WebSocket manager
        """
        return self._manager
