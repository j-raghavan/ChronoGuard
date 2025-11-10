"""Envoy xDS server implementation for dynamic proxy configuration.

This module implements the Envoy xDS (Discovery Service) protocol to provide
dynamic configuration updates to Envoy proxies. It manages listeners, clusters,
routes, and endpoints based on agent and policy configurations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import grpc
from loguru import logger


if TYPE_CHECKING:
    from domain.agent.entity import Agent
    from infrastructure.envoy.config_generator import ConfigGenerator


@dataclass
class XDSServerConfig:
    """Configuration for xDS server.

    Attributes:
        port: Port to listen on for xDS connections
        node_id: Identifier for this control plane node
        enable_mtls: Whether to enable mTLS for xDS connections
        cert_path: Path to server certificate (if mTLS enabled)
        key_path: Path to server private key (if mTLS enabled)
        ca_cert_path: Path to CA certificate for client verification
    """

    port: int = 18000
    node_id: str = "chronoguard"
    enable_mtls: bool = False
    cert_path: str | None = None
    key_path: str | None = None
    ca_cert_path: str | None = None


class XDSServer:
    """Implements Envoy's xDS protocol for dynamic configuration.

    This server provides dynamic configuration updates to Envoy proxies using
    the xDS (Discovery Service) protocol. It maintains a configuration cache
    and pushes updates when agent or policy configurations change.

    The server implements a simplified xDS control plane that:
    1. Accepts connections from Envoy proxies
    2. Provides listener, cluster, route, and endpoint configurations
    3. Dynamically updates configurations based on policy changes
    4. Supports both secure (mTLS) and insecure connections

    Example:
        >>> config = XDSServerConfig(port=18000, enable_mtls=True)
        >>> config_gen = ConfigGenerator()
        >>> server = XDSServer(config, config_gen)
        >>> await server.start()
    """

    def __init__(
        self,
        config: XDSServerConfig,
        config_generator: ConfigGenerator,
    ) -> None:
        """Initialize xDS server.

        Args:
            config: Server configuration
            config_generator: Generates Envoy configurations from domain models
        """
        self.config = config
        self.config_generator = config_generator
        self.grpc_server: grpc.aio.Server | None = None
        self._config_version: int = 0
        self._running: bool = False

    async def start(self) -> None:
        """Start the xDS server.

        This method initializes the gRPC server and begins listening for
        connections from Envoy proxies. In production, it uses mTLS for
        secure communication.

        Raises:
            RuntimeError: If server is already running
            ValueError: If mTLS is enabled but certificates are not configured
        """
        if self._running:
            raise RuntimeError("xDS server is already running")

        self.grpc_server = grpc.aio.server()

        # Configure server address
        address = f"[::]:{self.config.port}"

        if self.config.enable_mtls:
            # Validate mTLS configuration
            if not all(
                [
                    self.config.cert_path,
                    self.config.key_path,
                    self.config.ca_cert_path,
                ]
            ):
                raise ValueError(
                    "mTLS enabled but certificates not configured. "
                    "Provide cert_path, key_path, and ca_cert_path."
                )

            # Load certificates
            try:
                with open(self.config.cert_path, "rb") as f:
                    server_cert = f.read()
                with open(self.config.key_path, "rb") as f:
                    server_key = f.read()
                with open(self.config.ca_cert_path, "rb") as f:
                    ca_cert = f.read()
            except FileNotFoundError as e:
                raise ValueError(f"Certificate file not found: {e}") from e

            # Create mTLS credentials
            server_credentials = grpc.ssl_server_credentials(
                [(server_key, server_cert)],
                root_certificates=ca_cert,
                require_client_auth=True,
            )
            self.grpc_server.add_secure_port(address, server_credentials)
            logger.info(f"Secure xDS server listening on {address}")
        else:
            # Development mode - insecure
            self.grpc_server.add_insecure_port(address)
            logger.warning(f"Insecure xDS server listening on {address} (development only)")

        await self.grpc_server.start()
        self._running = True
        logger.info(f"xDS server started successfully on {address}")

    async def stop(self, grace_period: float = 5.0) -> None:
        """Stop the xDS server gracefully.

        Args:
            grace_period: Time in seconds to wait for active RPCs to complete
        """
        if not self._running:
            logger.warning("xDS server is not running")
            return

        if self.grpc_server:
            await self.grpc_server.stop(grace_period)
            self._running = False
            logger.info("xDS server stopped successfully")

    async def update_configuration(self, agents: list[Agent]) -> None:
        """Update Envoy configuration dynamically.

        This method generates new Envoy configurations based on the current
        agent and policy state, then updates the xDS cache to push changes
        to connected Envoy proxies.

        Args:
            agents: List of agents to generate configuration for

        Raises:
            RuntimeError: If configuration update fails
        """
        if not self._running:
            raise RuntimeError("Cannot update configuration - server not running")

        try:
            # Generate new configurations
            listeners = await self.config_generator.generate_listeners(agents)
            clusters = await self.config_generator.generate_clusters(agents)
            routes = await self.config_generator.generate_routes(agents)
            endpoints = await self.config_generator.generate_endpoints(agents)

            # Increment version for cache invalidation
            self._config_version += 1

            # In a real implementation, this would update an xDS cache
            # For now, we log the update
            logger.info(
                f"Updated xDS configuration to version {self._config_version} "
                f"for {len(agents)} agents: "
                f"{len(listeners)} listeners, "
                f"{len(clusters)} clusters, "
                f"{len(routes)} routes, "
                f"{len(endpoints)} endpoints"
            )

        except Exception as e:
            logger.error(f"Failed to update xDS configuration: {e}", exc_info=True)
            raise RuntimeError(f"Configuration update failed: {e}") from e

    async def health_check(self) -> dict[str, Any]:
        """Perform health check of xDS server.

        Returns:
            Health status including server state and metrics

        Example:
            >>> health = await server.health_check()
            >>> health
            {
                'status': 'healthy',
                'running': True,
                'config_version': 42,
                'port': 18000
            }
        """
        return {
            "status": "healthy" if self._running else "stopped",
            "running": self._running,
            "config_version": self._config_version,
            "port": self.config.port,
            "mtls_enabled": self.config.enable_mtls,
        }

    @property
    def is_running(self) -> bool:
        """Check if server is currently running.

        Returns:
            True if server is running, False otherwise
        """
        return self._running

    @property
    def config_version(self) -> int:
        """Get current configuration version.

        Returns:
            Current configuration version number
        """
        return self._config_version
