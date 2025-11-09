"""Comprehensive tests for Envoy Discovery Service."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from domain.agent.entity import Agent, AgentStatus
from domain.common.value_objects import X509Certificate
from infrastructure.envoy.config_generator import (
    ClusterConfig,
    ConfigGenerator,
    EndpointConfig,
    ListenerConfig,
    RouteConfig,
)
from infrastructure.envoy.discovery_service import CacheEntry, DiscoveryService, XDSSnapshot


def create_test_certificate(
    common_name: str = "test.example.com",
    organization: str = "Test Organization",
    days_valid: int = 365,
) -> str:
    """Create a valid self-signed test certificate."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture
def mock_config_generator() -> ConfigGenerator:
    """Create a mock config generator."""
    generator = MagicMock(spec=ConfigGenerator)

    # Mock async methods
    generator.generate_listeners = AsyncMock(
        return_value=[
            ListenerConfig(
                name="test_listener",
                address="0.0.0.0",  # noqa: S104
                port=8443,
                filter_chains=[{"filters": []}],
            )
        ]
    )

    generator.generate_clusters = AsyncMock(
        return_value=[
            ClusterConfig(
                name="test_cluster",
                type="LOGICAL_DNS",
                connect_timeout_seconds=5,
                endpoints=["localhost:8080"],
            )
        ]
    )

    generator.generate_routes = AsyncMock(
        return_value=[
            RouteConfig(
                name="test_route",
                virtual_hosts=[{"name": "test", "domains": ["*"]}],
            )
        ]
    )

    generator.generate_endpoints = AsyncMock(
        return_value=[
            EndpointConfig(
                cluster_name="test_cluster",
                endpoints=["localhost:8080"],
            )
        ]
    )

    return generator


@pytest.fixture
def discovery_service(mock_config_generator: ConfigGenerator) -> DiscoveryService:
    """Create a discovery service instance."""
    return DiscoveryService(mock_config_generator)


@pytest.fixture
def sample_agent() -> Agent:
    """Create a sample agent for testing."""
    cert_pem = create_test_certificate(
        common_name="test-agent",
        organization="TestOrg",
    )
    cert = X509Certificate(pem_data=cert_pem)

    return Agent(
        tenant_id=uuid4(),
        name="test-agent",
        certificate=cert,
        status=AgentStatus.ACTIVE,
    )


@pytest.fixture
def sample_agents(sample_agent: Agent) -> list[Agent]:
    """Create a list of sample agents."""
    agents = [sample_agent]

    # Add more agents
    for i in range(2):
        cert_pem = create_test_certificate(
            common_name=f"agent-{i}",
            organization="TestOrg",
        )
        cert = X509Certificate(pem_data=cert_pem)
        agents.append(
            Agent(
                tenant_id=uuid4(),
                name=f"agent-{i}",
                certificate=cert,
                status=AgentStatus.ACTIVE,
            )
        )

    return agents


class TestXDSSnapshot:
    """Test XDSSnapshot dataclass."""

    def test_snapshot_creation(self) -> None:
        """Test creating a snapshot."""
        snapshot = XDSSnapshot(
            version=1,
            listeners=[],
            clusters=[],
            routes=[],
            endpoints=[],
            timestamp=time.time(),
        )

        assert snapshot.version == 1
        assert snapshot.listeners == []
        assert snapshot.clusters == []
        assert snapshot.routes == []
        assert snapshot.endpoints == []
        assert snapshot.metadata == {}

    def test_snapshot_with_metadata(self) -> None:
        """Test snapshot with metadata."""
        metadata = {"agent_count": 5, "tenant_ids": ["tenant-1"]}
        snapshot = XDSSnapshot(
            version=2,
            listeners=[],
            clusters=[],
            routes=[],
            endpoints=[],
            timestamp=time.time(),
            metadata=metadata,
        )

        assert snapshot.metadata == metadata


class TestCacheEntry:
    """Test CacheEntry dataclass."""

    def test_cache_entry_creation(self) -> None:
        """Test creating a cache entry."""
        snapshot = XDSSnapshot(
            version=1,
            listeners=[],
            clusters=[],
            routes=[],
            endpoints=[],
            timestamp=time.time(),
        )

        entry = CacheEntry(
            node_id="test-node",
            snapshot=snapshot,
            last_updated=time.time(),
        )

        assert entry.node_id == "test-node"
        assert entry.snapshot == snapshot
        assert entry.last_updated > 0


class TestDiscoveryServiceInit:
    """Test DiscoveryService initialization."""

    def test_initialization(self, mock_config_generator: ConfigGenerator) -> None:
        """Test service initialization."""
        service = DiscoveryService(mock_config_generator)

        assert service._config_generator == mock_config_generator
        assert service._cache == {}
        assert service._global_version == 0


class TestCreateSnapshot:
    """Test snapshot creation."""

    async def test_create_snapshot_success(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test successful snapshot creation."""
        snapshot = await discovery_service.create_snapshot(sample_agents)

        assert snapshot.version == 1
        assert len(snapshot.listeners) == 1
        assert len(snapshot.clusters) == 1
        assert len(snapshot.routes) == 1
        assert len(snapshot.endpoints) == 1
        assert snapshot.metadata["agent_count"] == len(sample_agents)

    async def test_create_snapshot_auto_increment_version(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test version auto-increment."""
        snapshot1 = await discovery_service.create_snapshot(sample_agents)
        snapshot2 = await discovery_service.create_snapshot(sample_agents)

        assert snapshot1.version == 1
        assert snapshot2.version == 2
        assert discovery_service._global_version == 2

    async def test_create_snapshot_explicit_version(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test creating snapshot with explicit version."""
        snapshot = await discovery_service.create_snapshot(sample_agents, version=100)

        assert snapshot.version == 100
        # Global version should not be incremented
        assert discovery_service._global_version == 0

    async def test_create_snapshot_empty_agents_raises_error(
        self,
        discovery_service: DiscoveryService,
    ) -> None:
        """Test that empty agents list raises error."""
        with pytest.raises(ValueError, match="Cannot create snapshot with empty agents list"):
            await discovery_service.create_snapshot([])

    async def test_create_snapshot_metadata_includes_tenant_ids(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test snapshot metadata includes unique tenant IDs."""
        snapshot = await discovery_service.create_snapshot(sample_agents)

        tenant_ids = snapshot.metadata["tenant_ids"]
        assert len(tenant_ids) == len({str(a.tenant_id) for a in sample_agents})


class TestUpdateSnapshot:
    """Test snapshot updates."""

    async def test_update_snapshot_success(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test successful snapshot update."""
        snapshot = await discovery_service.create_snapshot(sample_agents)
        await discovery_service.update_snapshot("node-1", snapshot)

        cached_snapshot = discovery_service.get_snapshot("node-1")
        assert cached_snapshot == snapshot

    async def test_update_snapshot_empty_node_id_raises_error(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test that empty node_id raises error."""
        snapshot = await discovery_service.create_snapshot(sample_agents)

        with pytest.raises(ValueError, match="node_id cannot be empty"):
            await discovery_service.update_snapshot("", snapshot)

    async def test_update_snapshot_none_snapshot_raises_error(
        self,
        discovery_service: DiscoveryService,
    ) -> None:
        """Test that None snapshot raises error."""
        with pytest.raises(ValueError, match="snapshot cannot be None"):
            await discovery_service.update_snapshot("node-1", None)

    async def test_update_snapshot_overwrites_existing(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test updating existing snapshot."""
        snapshot1 = await discovery_service.create_snapshot(sample_agents)
        snapshot2 = await discovery_service.create_snapshot(sample_agents)

        await discovery_service.update_snapshot("node-1", snapshot1)
        await discovery_service.update_snapshot("node-1", snapshot2)

        cached = discovery_service.get_snapshot("node-1")
        assert cached == snapshot2
        assert cached.version == snapshot2.version


class TestGetSnapshot:
    """Test snapshot retrieval."""

    async def test_get_snapshot_exists(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test retrieving existing snapshot."""
        snapshot = await discovery_service.create_snapshot(sample_agents)
        await discovery_service.update_snapshot("node-1", snapshot)

        retrieved = discovery_service.get_snapshot("node-1")
        assert retrieved == snapshot

    def test_get_snapshot_not_exists(
        self,
        discovery_service: DiscoveryService,
    ) -> None:
        """Test retrieving non-existent snapshot returns None."""
        result = discovery_service.get_snapshot("non-existent")
        assert result is None


class TestInvalidateCache:
    """Test cache invalidation."""

    async def test_invalidate_specific_node(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test invalidating specific node's cache."""
        snapshot = await discovery_service.create_snapshot(sample_agents)
        await discovery_service.update_snapshot("node-1", snapshot)
        await discovery_service.update_snapshot("node-2", snapshot)

        discovery_service.invalidate_cache("node-1")

        assert discovery_service.get_snapshot("node-1") is None
        assert discovery_service.get_snapshot("node-2") is not None

    async def test_invalidate_entire_cache(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test invalidating entire cache."""
        snapshot = await discovery_service.create_snapshot(sample_agents)
        await discovery_service.update_snapshot("node-1", snapshot)
        await discovery_service.update_snapshot("node-2", snapshot)

        discovery_service.invalidate_cache()

        assert discovery_service.get_snapshot("node-1") is None
        assert discovery_service.get_snapshot("node-2") is None

    def test_invalidate_non_existent_node(
        self,
        discovery_service: DiscoveryService,
    ) -> None:
        """Test invalidating non-existent node doesn't raise error."""
        # Should not raise
        discovery_service.invalidate_cache("non-existent")


class TestGetCacheStats:
    """Test cache statistics."""

    async def test_get_cache_stats_empty(
        self,
        discovery_service: DiscoveryService,
    ) -> None:
        """Test stats for empty cache."""
        stats = discovery_service.get_cache_stats()

        assert stats["total_nodes"] == 0
        assert stats["global_version"] == 0
        assert stats["nodes"] == []

    async def test_get_cache_stats_populated(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test stats for populated cache."""
        snapshot = await discovery_service.create_snapshot(sample_agents)
        await discovery_service.update_snapshot("node-1", snapshot)
        await discovery_service.update_snapshot("node-2", snapshot)

        stats = discovery_service.get_cache_stats()

        assert stats["total_nodes"] == 2
        assert stats["global_version"] == 1
        assert len(stats["nodes"]) == 2

        # Check node info structure
        node_info = stats["nodes"][0]
        assert "node_id" in node_info
        assert "version" in node_info
        assert "last_updated" in node_info
        assert "listeners" in node_info
        assert "clusters" in node_info


class TestGetVersionForNode:
    """Test version retrieval for nodes."""

    async def test_get_version_for_existing_node(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test getting version for existing node."""
        snapshot = await discovery_service.create_snapshot(sample_agents)
        await discovery_service.update_snapshot("node-1", snapshot)

        version = discovery_service.get_version_for_node("node-1")
        assert version == snapshot.version

    def test_get_version_for_non_existent_node(
        self,
        discovery_service: DiscoveryService,
    ) -> None:
        """Test getting version for non-existent node returns None."""
        version = discovery_service.get_version_for_node("non-existent")
        assert version is None


class TestHasNewerSnapshot:
    """Test newer snapshot detection."""

    async def test_has_newer_snapshot_true(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test detecting newer snapshot."""
        snapshot = await discovery_service.create_snapshot(sample_agents, version=10)
        await discovery_service.update_snapshot("node-1", snapshot)

        has_newer = discovery_service.has_newer_snapshot("node-1", 5)
        assert has_newer is True

    async def test_has_newer_snapshot_false(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test no newer snapshot."""
        snapshot = await discovery_service.create_snapshot(sample_agents, version=5)
        await discovery_service.update_snapshot("node-1", snapshot)

        has_newer = discovery_service.has_newer_snapshot("node-1", 10)
        assert has_newer is False

    def test_has_newer_snapshot_non_existent_node(
        self,
        discovery_service: DiscoveryService,
    ) -> None:
        """Test newer snapshot check for non-existent node."""
        has_newer = discovery_service.has_newer_snapshot("non-existent", 5)
        assert has_newer is False


class TestUpdateAgentsConfiguration:
    """Test updating agents configuration."""

    async def test_update_agents_configuration_success(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test successful configuration update."""
        snapshot = await discovery_service.update_agents_configuration(
            "node-1",
            sample_agents,
        )

        assert snapshot.version == 1
        cached = discovery_service.get_snapshot("node-1")
        assert cached == snapshot

    async def test_update_agents_configuration_empty_node_id(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test empty node_id raises error."""
        with pytest.raises(ValueError, match="node_id cannot be empty"):
            await discovery_service.update_agents_configuration("", sample_agents)

    async def test_update_agents_configuration_empty_agents(
        self,
        discovery_service: DiscoveryService,
    ) -> None:
        """Test empty agents list raises error."""
        with pytest.raises(ValueError, match="Cannot create snapshot with empty agents list"):
            await discovery_service.update_agents_configuration("node-1", [])


class TestListNodes:
    """Test listing nodes."""

    async def test_list_nodes_empty(
        self,
        discovery_service: DiscoveryService,
    ) -> None:
        """Test listing nodes with empty cache."""
        nodes = discovery_service.list_nodes()
        assert nodes == []

    async def test_list_nodes_populated(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test listing nodes with populated cache."""
        snapshot = await discovery_service.create_snapshot(sample_agents)
        await discovery_service.update_snapshot("node-1", snapshot)
        await discovery_service.update_snapshot("node-2", snapshot)

        nodes = discovery_service.list_nodes()
        assert set(nodes) == {"node-1", "node-2"}


class TestGetGlobalVersion:
    """Test global version retrieval."""

    def test_get_global_version_initial(
        self,
        discovery_service: DiscoveryService,
    ) -> None:
        """Test initial global version."""
        version = discovery_service.get_global_version()
        assert version == 0

    async def test_get_global_version_after_snapshot(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test global version after creating snapshot."""
        await discovery_service.create_snapshot(sample_agents)
        version = discovery_service.get_global_version()
        assert version == 1

    async def test_get_global_version_multiple_snapshots(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test global version increments correctly."""
        await discovery_service.create_snapshot(sample_agents)
        await discovery_service.create_snapshot(sample_agents)
        await discovery_service.create_snapshot(sample_agents)

        version = discovery_service.get_global_version()
        assert version == 3


class TestEdgeCases:
    """Test edge cases and error conditions."""

    async def test_multiple_updates_same_node(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test multiple updates to same node."""
        for i in range(5):
            snapshot = await discovery_service.create_snapshot(
                sample_agents,
                version=i + 1,
            )
            await discovery_service.update_snapshot("node-1", snapshot)

        final_snapshot = discovery_service.get_snapshot("node-1")
        assert final_snapshot is not None
        assert final_snapshot.version == 5

    async def test_concurrent_node_updates(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test updating different nodes concurrently."""
        snapshots = []
        for i in range(3):
            snapshot = await discovery_service.create_snapshot(
                sample_agents,
                version=i + 1,
            )
            snapshots.append(snapshot)
            await discovery_service.update_snapshot(f"node-{i}", snapshot)

        # Verify all nodes have correct snapshots
        for i in range(3):
            cached = discovery_service.get_snapshot(f"node-{i}")
            assert cached == snapshots[i]

    async def test_snapshot_timestamp_ordering(
        self,
        discovery_service: DiscoveryService,
        sample_agents: list[Agent],
    ) -> None:
        """Test snapshots have increasing timestamps."""
        snapshot1 = await discovery_service.create_snapshot(sample_agents)
        time.sleep(0.01)  # Small delay
        snapshot2 = await discovery_service.create_snapshot(sample_agents)

        assert snapshot2.timestamp > snapshot1.timestamp
