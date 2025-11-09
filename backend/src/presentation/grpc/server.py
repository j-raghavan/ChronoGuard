"""gRPC server implementation for ChronoGuard agent management.

This module implements the gRPC service for agent management operations,
providing protocol buffer integration and method implementations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

import grpc
from loguru import logger

if TYPE_CHECKING:
    pass


class AgentServiceError(Exception):
    """Base exception for agent service errors."""

    pass


class AgentNotFoundError(AgentServiceError):
    """Raised when an agent is not found."""

    pass


class InvalidRequestError(AgentServiceError):
    """Raised when a request is invalid."""

    pass


class GRPCAgentService:
    """gRPC service implementation for agent management.

    This service implements the agent management operations via gRPC:
    - GetAgent: Retrieve a single agent by ID
    - ListAgents: List agents with optional filtering
    - CreateAgent: Create a new agent
    - UpdateAgent: Update an existing agent

    The service uses command/query handlers from the application layer
    and translates between protobuf messages and domain objects.

    Example:
        >>> service = GRPCAgentService(command_handler, query_handler)
        >>> await service.start(port=50051)
    """

    def __init__(
        self,
        command_handler: Any,
        query_handler: Any,
    ) -> None:
        """Initialize the gRPC service.

        Args:
            command_handler: Handler for agent commands (create, update)
            query_handler: Handler for agent queries (get, list)
        """
        self._command_handler = command_handler
        self._query_handler = query_handler
        self._server: grpc.aio.Server | None = None
        self._port: int = 50051

    async def GetAgent(  # noqa: N802
        self,
        request: dict[str, Any],
        context: grpc.aio.ServicerContext,
    ) -> dict[str, Any]:
        """Retrieve a single agent by ID.

        Args:
            request: gRPC request containing agent_id
            context: gRPC service context

        Returns:
            Agent data as dictionary

        Raises:
            grpc.StatusCode.NOT_FOUND: If agent is not found
            grpc.StatusCode.INVALID_ARGUMENT: If request is invalid
        """
        try:
            # Extract agent_id from request
            agent_id_str = request.get("agent_id")
            if not agent_id_str:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT,
                    "agent_id is required",
                )
                return {}

            # Parse UUID
            try:
                agent_id = UUID(agent_id_str)
            except ValueError as e:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT,
                    f"Invalid agent_id format: {e}",
                )
                return {}

            # Execute query
            query = {"agent_id": agent_id}
            agent = await self._query_handler.get_agent(query)

            if not agent:
                await context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"Agent with ID {agent_id} not found",
                )
                return {}

            logger.info(f"Retrieved agent {agent_id} via gRPC")

            # Convert to response format
            return self._agent_to_dict(agent)

        except Exception as e:
            logger.error(f"Error in GetAgent: {e}", exc_info=True)
            await context.abort(
                grpc.StatusCode.INTERNAL,
                "Internal server error",
            )
            return {}

    async def ListAgents(  # noqa: N802
        self,
        request: dict[str, Any],
        context: grpc.aio.ServicerContext,
    ) -> dict[str, Any]:
        """List agents with optional filtering.

        Args:
            request: gRPC request containing optional filters
            context: gRPC service context

        Returns:
            Dictionary containing list of agents and pagination info

        Raises:
            grpc.StatusCode.INVALID_ARGUMENT: If request parameters are invalid
        """
        try:
            # Extract query parameters
            tenant_id_str = request.get("tenant_id")
            status = request.get("status")
            limit = request.get("limit", 100)
            offset = request.get("offset", 0)

            # Build query
            query: dict[str, Any] = {
                "limit": min(limit, 1000),  # Cap at 1000
                "offset": max(offset, 0),
            }

            # Add optional filters
            if tenant_id_str:
                try:
                    query["tenant_id"] = UUID(tenant_id_str)
                except ValueError as e:
                    await context.abort(
                        grpc.StatusCode.INVALID_ARGUMENT,
                        f"Invalid tenant_id format: {e}",
                    )
                    return {}

            if status:
                query["status"] = status

            # Execute query
            result = await self._query_handler.list_agents(query)

            agents = result.get("agents", [])
            total = result.get("total", len(agents))

            logger.info(
                f"Listed {len(agents)} agents via gRPC "
                f"(total: {total}, limit: {limit}, offset: {offset})"
            )

            # Convert to response format
            return {
                "agents": [self._agent_to_dict(agent) for agent in agents],
                "total": total,
                "limit": limit,
                "offset": offset,
            }

        except Exception as e:
            logger.error(f"Error in ListAgents: {e}", exc_info=True)
            await context.abort(
                grpc.StatusCode.INTERNAL,
                "Internal server error",
            )
            return {}

    async def CreateAgent(  # noqa: N802
        self,
        request: dict[str, Any],
        context: grpc.aio.ServicerContext,
    ) -> dict[str, Any]:
        """Create a new agent.

        Args:
            request: gRPC request containing agent data
            context: gRPC service context

        Returns:
            Created agent data as dictionary

        Raises:
            grpc.StatusCode.INVALID_ARGUMENT: If request data is invalid
            grpc.StatusCode.ALREADY_EXISTS: If agent already exists
        """
        try:
            # Validate required fields
            required_fields = ["tenant_id", "name", "certificate_pem"]
            for field in required_fields:
                if field not in request:
                    await context.abort(
                        grpc.StatusCode.INVALID_ARGUMENT,
                        f"Missing required field: {field}",
                    )
                    return {}

            # Parse tenant_id
            try:
                tenant_id = UUID(request["tenant_id"])
            except ValueError as e:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT,
                    f"Invalid tenant_id format: {e}",
                )
                return {}

            # Build command
            command = {
                "tenant_id": tenant_id,
                "name": request["name"],
                "certificate_pem": request["certificate_pem"],
                "metadata": request.get("metadata", {}),
            }

            # Execute command
            agent = await self._command_handler.create_agent(command)

            logger.info(f"Created agent {agent.agent_id} via gRPC")

            # Convert to response format
            return self._agent_to_dict(agent)

        except ValueError as e:
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                str(e),
            )
            return {}
        except Exception as e:
            logger.error(f"Error in CreateAgent: {e}", exc_info=True)
            await context.abort(
                grpc.StatusCode.INTERNAL,
                "Internal server error",
            )
            return {}

    async def UpdateAgent(  # noqa: N802
        self,
        request: dict[str, Any],
        context: grpc.aio.ServicerContext,
    ) -> dict[str, Any]:
        """Update an existing agent.

        Args:
            request: gRPC request containing agent_id and update data
            context: gRPC service context

        Returns:
            Updated agent data as dictionary

        Raises:
            grpc.StatusCode.NOT_FOUND: If agent is not found
            grpc.StatusCode.INVALID_ARGUMENT: If request is invalid
        """
        try:
            # Extract agent_id
            agent_id_str = request.get("agent_id")
            if not agent_id_str:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT,
                    "agent_id is required",
                )
                return {}

            # Parse UUID
            try:
                agent_id = UUID(agent_id_str)
            except ValueError as e:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT,
                    f"Invalid agent_id format: {e}",
                )
                return {}

            # Build command with updates
            command: dict[str, Any] = {"agent_id": agent_id}

            # Add optional updates
            if "name" in request:
                command["name"] = request["name"]
            if "status" in request:
                command["status"] = request["status"]
            if "metadata" in request:
                command["metadata"] = request["metadata"]

            # Execute command
            agent = await self._command_handler.update_agent(command)

            if not agent:
                await context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"Agent with ID {agent_id} not found",
                )
                return {}

            logger.info(f"Updated agent {agent_id} via gRPC")

            # Convert to response format
            return self._agent_to_dict(agent)

        except ValueError as e:
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                str(e),
            )
            return {}
        except Exception as e:
            logger.error(f"Error in UpdateAgent: {e}", exc_info=True)
            await context.abort(
                grpc.StatusCode.INTERNAL,
                "Internal server error",
            )
            return {}

    async def start(self, port: int = 50051) -> None:
        """Start the gRPC server.

        Args:
            port: Port to listen on

        Raises:
            RuntimeError: If server is already running
        """
        if self._server is not None:
            raise RuntimeError("gRPC server is already running")

        self._port = port
        self._server = grpc.aio.server()

        # Add servicer to server (would normally use generated code)
        # self._server.add_servicer(self, server)

        # Add insecure port
        address = f"[::]:{port}"
        self._server.add_insecure_port(address)

        # Start server
        await self._server.start()

        logger.info(f"gRPC server started on {address}")

    async def stop(self, grace_period: float = 5.0) -> None:
        """Stop the gRPC server gracefully.

        Args:
            grace_period: Time in seconds to wait for active RPCs to complete
        """
        if self._server is None:
            logger.warning("gRPC server is not running")
            return

        await self._server.stop(grace_period)
        self._server = None

        logger.info("gRPC server stopped")

    def _agent_to_dict(self, agent: Any) -> dict[str, Any]:
        """Convert agent entity to dictionary for protobuf response.

        Args:
            agent: Agent entity

        Returns:
            Agent data as dictionary
        """
        return {
            "agent_id": str(agent.agent_id),
            "tenant_id": str(agent.tenant_id),
            "name": agent.name,
            "status": agent.status,
            "policy_ids": [str(pid) for pid in agent.policy_ids],
            "created_at": agent.created_at.isoformat(),
            "updated_at": agent.updated_at.isoformat(),
            "last_seen_at": agent.last_seen_at.isoformat() if agent.last_seen_at else None,
            "metadata": agent.metadata,
            "version": agent.version,
            "certificate": {
                "subject_common_name": agent.certificate.subject_common_name,
                "fingerprint_sha256": agent.certificate.fingerprint_sha256,
                "not_valid_before": agent.certificate.not_valid_before.isoformat(),
                "not_valid_after": agent.certificate.not_valid_after.isoformat(),
                "is_valid_now": agent.certificate.is_valid_now,
            },
        }

    @property
    def is_running(self) -> bool:
        """Check if server is running.

        Returns:
            True if server is running, False otherwise
        """
        return self._server is not None

    @property
    def port(self) -> int:
        """Get the server port.

        Returns:
            Server port number
        """
        return self._port
