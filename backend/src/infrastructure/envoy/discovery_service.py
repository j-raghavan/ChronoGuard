"""Envoy Discovery Service (xDS) cache management and snapshot orchestration.

This module implements xDS cache management, snapshot orchestration, and listener
lifecycle management for dynamic Envoy proxy configuration updates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from loguru import logger


if TYPE_CHECKING:
    from domain.agent.entity import Agent
    from infrastructure.envoy.config_generator import (
        ClusterConfig,
        EndpointConfig,
        ListenerConfig,
        RouteConfig,
    )


@dataclass
class XDSSnapshot:
    """Represents a versioned snapshot of Envoy configuration.

    Attributes:
        version: Snapshot version number
        listeners: Listener configurations
        clusters: Cluster configurations
        routes: Route configurations
        endpoints: Endpoint configurations
        timestamp: Snapshot creation timestamp
    """

    version: int
    listeners: list[ListenerConfig]
    clusters: list[ClusterConfig]
    routes: list[RouteConfig]
    endpoints: list[EndpointConfig]
    timestamp: float
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CacheEntry:
    """Cache entry for a specific node's configuration snapshot.

    Attributes:
        node_id: Identifier for the Envoy node
        snapshot: Current configuration snapshot
        last_updated: Last update timestamp
    """

    node_id: str
    snapshot: XDSSnapshot
    last_updated: float


class DiscoveryService:
    """Manages xDS cache and configuration snapshots for Envoy proxies.

    This service implements the core xDS cache management functionality:
    - Creating and managing configuration snapshots
    - Version tracking and cache invalidation
    - Per-node configuration isolation
    - Snapshot consistency validation

    The service maintains a cache of configuration snapshots per Envoy node,
    enabling efficient configuration updates and rollbacks.

    Example:
        >>> from infrastructure.envoy.config_generator import ConfigGenerator
        >>> config_gen = ConfigGenerator()
        >>> discovery = DiscoveryService(config_gen)
        >>> snapshot = await discovery.create_snapshot(agents)
        >>> await discovery.update_snapshot("node-1", snapshot)
    """

    def __init__(
        self,
        config_generator: Any,  # ConfigGenerator type hint causes circular import
    ) -> None:
        """Initialize the discovery service.

        Args:
            config_generator: Generator for Envoy configurations from domain models
        """
        self._config_generator = config_generator
        self._cache: dict[str, CacheEntry] = {}
        self._global_version: int = 0

    async def create_snapshot(
        self,
        agents: list[Agent],
        version: int | None = None,
    ) -> XDSSnapshot:
        """Create a new configuration snapshot from agents.

        Generates a complete xDS configuration snapshot including listeners,
        clusters, routes, and endpoints based on the provided agents.

        Args:
            agents: List of agents to generate configuration for
            version: Optional explicit version number (auto-increments if None)

        Returns:
            Complete xDS configuration snapshot

        Raises:
            ValueError: If agents list is empty
        """
        if not agents:
            raise ValueError("Cannot create snapshot with empty agents list")

        # Auto-increment version if not specified
        if version is None:
            self._global_version += 1
            version = self._global_version

        # Generate all configuration components
        listeners = await self._config_generator.generate_listeners(agents)
        clusters = await self._config_generator.generate_clusters(agents)
        routes = await self._config_generator.generate_routes(agents)
        endpoints = await self._config_generator.generate_endpoints(agents)

        # Create snapshot with metadata
        import time

        snapshot = XDSSnapshot(
            version=version,
            listeners=listeners,
            clusters=clusters,
            routes=routes,
            endpoints=endpoints,
            timestamp=time.time(),
            metadata={
                "agent_count": len(agents),
                "tenant_ids": list({str(agent.tenant_id) for agent in agents}),
            },
        )

        logger.info(
            f"Created xDS snapshot version {version} for {len(agents)} agents: "
            f"{len(listeners)} listeners, {len(clusters)} clusters, "
            f"{len(routes)} routes, {len(endpoints)} endpoints"
        )

        return snapshot

    async def update_snapshot(
        self,
        node_id: str,
        snapshot: XDSSnapshot,
    ) -> None:
        """Update the configuration snapshot for a specific node.

        Updates the cache with a new snapshot for the given Envoy node.
        This triggers configuration updates to connected Envoy instances.

        Args:
            node_id: Identifier for the Envoy node
            snapshot: New configuration snapshot

        Raises:
            ValueError: If node_id is empty or snapshot is invalid
        """
        if not node_id:
            raise ValueError("node_id cannot be empty")

        if not snapshot:
            raise ValueError("snapshot cannot be None")

        import time

        # Create or update cache entry
        entry = CacheEntry(
            node_id=node_id,
            snapshot=snapshot,
            last_updated=time.time(),
        )

        self._cache[node_id] = entry

        logger.info(f"Updated snapshot for node '{node_id}' to version {snapshot.version}")

    def get_snapshot(self, node_id: str) -> XDSSnapshot | None:
        """Retrieve the current snapshot for a specific node.

        Args:
            node_id: Identifier for the Envoy node

        Returns:
            Current snapshot if exists, None otherwise
        """
        entry = self._cache.get(node_id)
        if entry:
            logger.debug(
                f"Retrieved snapshot version {entry.snapshot.version} for node '{node_id}'"
            )
            return entry.snapshot

        logger.debug(f"No snapshot found for node '{node_id}'")
        return None

    def invalidate_cache(self, node_id: str | None = None) -> None:
        """Invalidate cache entries, forcing configuration refresh.

        If node_id is specified, only that node's cache is invalidated.
        If node_id is None, the entire cache is cleared.

        Args:
            node_id: Optional node identifier to invalidate specific entry
        """
        if node_id:
            if node_id in self._cache:
                del self._cache[node_id]
                logger.info(f"Invalidated cache for node '{node_id}'")
            else:
                logger.warning(f"No cache entry found for node '{node_id}'")
        else:
            # Clear entire cache
            cache_size = len(self._cache)
            self._cache.clear()
            logger.info(f"Invalidated entire cache ({cache_size} entries)")

    def get_cache_stats(self) -> dict[str, Any]:
        """Get statistics about the current cache state.

        Returns:
            Dictionary containing cache statistics including:
            - total_nodes: Number of nodes in cache
            - global_version: Current global version number
            - nodes: List of node IDs and their snapshot versions
        """
        nodes_info = [
            {
                "node_id": node_id,
                "version": entry.snapshot.version,
                "last_updated": entry.last_updated,
                "listeners": len(entry.snapshot.listeners),
                "clusters": len(entry.snapshot.clusters),
            }
            for node_id, entry in self._cache.items()
        ]

        return {
            "total_nodes": len(self._cache),
            "global_version": self._global_version,
            "nodes": nodes_info,
        }

    def get_version_for_node(self, node_id: str) -> int | None:
        """Get the current snapshot version for a specific node.

        Args:
            node_id: Identifier for the Envoy node

        Returns:
            Current snapshot version if node exists, None otherwise
        """
        entry = self._cache.get(node_id)
        return entry.snapshot.version if entry else None

    def has_newer_snapshot(self, node_id: str, current_version: int) -> bool:
        """Check if a newer snapshot exists for a node.

        Args:
            node_id: Identifier for the Envoy node
            current_version: Version to compare against

        Returns:
            True if a newer snapshot exists, False otherwise
        """
        node_version = self.get_version_for_node(node_id)
        if node_version is None:
            return False

        return node_version > current_version

    async def update_agents_configuration(
        self,
        node_id: str,
        agents: list[Agent],
    ) -> XDSSnapshot:
        """Update configuration for a node with new agent list.

        This is a convenience method that creates a new snapshot and
        updates the cache in a single operation.

        Args:
            node_id: Identifier for the Envoy node
            agents: Updated list of agents

        Returns:
            Newly created snapshot

        Raises:
            ValueError: If node_id is empty or agents list is empty
        """
        if not node_id:
            raise ValueError("node_id cannot be empty")

        # Create new snapshot
        snapshot = await self.create_snapshot(agents)

        # Update cache
        await self.update_snapshot(node_id, snapshot)

        logger.info(f"Updated configuration for node '{node_id}' with {len(agents)} agents")

        return snapshot

    def list_nodes(self) -> list[str]:
        """List all node IDs currently in the cache.

        Returns:
            List of node identifiers
        """
        return list(self._cache.keys())

    def get_global_version(self) -> int:
        """Get the current global version number.

        Returns:
            Current global version counter
        """
        return self._global_version
