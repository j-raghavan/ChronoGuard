"""Unit tests for Envoy xDS Server."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, Mock, patch
from uuid import uuid4

import pytest

from domain.agent.entity import Agent, AgentStatus
from domain.common.value_objects import X509Certificate
from infrastructure.envoy.config_generator import (
    ClusterConfig,
    ConfigGenerator,
    EndpointConfig,
    ListenerConfig,
    RouteConfig,
)
from infrastructure.envoy.xds_server import XDSServer, XDSServerConfig

if TYPE_CHECKING:
    from datetime import datetime


@pytest.fixture
def xds_config() -> XDSServerConfig:
    """Create test xDS server configuration."""
    return XDSServerConfig(
        port=18000,
        node_id="test_node",
        enable_mtls=False,
    )


@pytest.fixture
def xds_config_with_mtls(tmp_path: Path) -> XDSServerConfig:
    """Create test xDS server configuration with mTLS."""
    # Create dummy cert files
    cert_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"
    ca_path = tmp_path / "ca.crt"

    cert_path.write_text("fake cert")
    key_path.write_text("fake key")
    ca_path.write_text("fake ca")

    return XDSServerConfig(
        port=18000,
        node_id="test_node",
        enable_mtls=True,
        cert_path=str(cert_path),
        key_path=str(key_path),
        ca_cert_path=str(ca_path),
    )


@pytest.fixture
def config_generator() -> ConfigGenerator:
    """Create test config generator."""
    return ConfigGenerator()


@pytest.fixture
def sample_agent(test_certificate: X509Certificate) -> Agent:
    """Create sample agent for testing."""
    return Agent(
        agent_id=uuid4(),
        tenant_id=uuid4(),
        name="test-agent",
        certificate=test_certificate,
        status=AgentStatus.ACTIVE,
    )


class TestXDSServerConfig:
    """Test XDSServerConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = XDSServerConfig()

        assert config.port == 18000
        assert config.node_id == "chronoguard"
        assert config.enable_mtls is False
        assert config.cert_path is None
        assert config.key_path is None
        assert config.ca_cert_path is None

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = XDSServerConfig(
            port=19000,
            node_id="custom_node",
            enable_mtls=True,
            cert_path="/path/to/cert",
            key_path="/path/to/key",
            ca_cert_path="/path/to/ca",
        )

        assert config.port == 19000
        assert config.node_id == "custom_node"
        assert config.enable_mtls is True
        assert config.cert_path == "/path/to/cert"
        assert config.key_path == "/path/to/key"
        assert config.ca_cert_path == "/path/to/ca"


class TestXDSServer:
    """Test XDSServer class."""

    def test_initialization(
        self, xds_config: XDSServerConfig, config_generator: ConfigGenerator
    ) -> None:
        """Test server initialization."""
        server = XDSServer(xds_config, config_generator)

        assert server.config == xds_config
        assert server.config_generator == config_generator
        assert server.grpc_server is None
        assert server._config_version == 0
        assert server._running is False
        assert server.is_running is False

    @pytest.mark.asyncio
    async def test_start_insecure(
        self, xds_config: XDSServerConfig, config_generator: ConfigGenerator
    ) -> None:
        """Test starting server in insecure mode."""
        server = XDSServer(xds_config, config_generator)

        with patch("grpc.aio.server") as mock_grpc_server:
            mock_server = AsyncMock()
            mock_grpc_server.return_value = mock_server

            await server.start()

            assert server._running is True
            assert server.is_running is True
            mock_server.add_insecure_port.assert_called_once()
            mock_server.start.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_start_with_mtls(
        self,
        xds_config_with_mtls: XDSServerConfig,
        config_generator: ConfigGenerator,
    ) -> None:
        """Test starting server with mTLS."""
        server = XDSServer(xds_config_with_mtls, config_generator)

        with (
            patch("grpc.aio.server") as mock_grpc_server,
            patch("grpc.ssl_server_credentials") as mock_ssl_creds,
        ):
            mock_server = AsyncMock()
            mock_grpc_server.return_value = mock_server
            mock_creds = Mock()
            mock_ssl_creds.return_value = mock_creds

            await server.start()

            assert server._running is True
            mock_ssl_creds.assert_called_once()
            mock_server.add_secure_port.assert_called_once()
            mock_server.start.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_start_already_running(
        self, xds_config: XDSServerConfig, config_generator: ConfigGenerator
    ) -> None:
        """Test starting server when already running raises error."""
        server = XDSServer(xds_config, config_generator)
        server._running = True

        with pytest.raises(RuntimeError, match="already running"):
            await server.start()

    @pytest.mark.asyncio
    async def test_start_mtls_missing_certs(
        self, xds_config: XDSServerConfig, config_generator: ConfigGenerator
    ) -> None:
        """Test starting with mTLS but missing certificates raises error."""
        xds_config.enable_mtls = True
        server = XDSServer(xds_config, config_generator)

        with pytest.raises(ValueError, match="certificates not configured"):
            await server.start()

    @pytest.mark.asyncio
    async def test_stop(
        self, xds_config: XDSServerConfig, config_generator: ConfigGenerator
    ) -> None:
        """Test stopping server."""
        server = XDSServer(xds_config, config_generator)

        mock_server = AsyncMock()
        server.grpc_server = mock_server
        server._running = True

        await server.stop(grace_period=3.0)

        assert server._running is False
        assert not server.is_running
        mock_server.stop.assert_awaited_once_with(3.0)

    @pytest.mark.asyncio
    async def test_stop_not_running(
        self, xds_config: XDSServerConfig, config_generator: ConfigGenerator
    ) -> None:
        """Test stopping server when not running."""
        server = XDSServer(xds_config, config_generator)

        # Should not raise, just log warning
        await server.stop()

        assert server._running is False

    @pytest.mark.asyncio
    async def test_update_configuration(
        self,
        xds_config: XDSServerConfig,
        config_generator: ConfigGenerator,
        sample_agent: Agent,
    ) -> None:
        """Test updating configuration."""
        server = XDSServer(xds_config, config_generator)
        server._running = True

        agents = [sample_agent]

        with (
            patch.object(
                config_generator, "generate_listeners", new_callable=AsyncMock
            ) as mock_listeners,
            patch.object(
                config_generator, "generate_clusters", new_callable=AsyncMock
            ) as mock_clusters,
            patch.object(
                config_generator, "generate_routes", new_callable=AsyncMock
            ) as mock_routes,
            patch.object(
                config_generator, "generate_endpoints", new_callable=AsyncMock
            ) as mock_endpoints,
        ):
            mock_listeners.return_value = []
            mock_clusters.return_value = []
            mock_routes.return_value = []
            mock_endpoints.return_value = []

            initial_version = server.config_version

            await server.update_configuration(agents)

            assert server.config_version == initial_version + 1
            mock_listeners.assert_awaited_once_with(agents)
            mock_clusters.assert_awaited_once_with(agents)
            mock_routes.assert_awaited_once_with(agents)
            mock_endpoints.assert_awaited_once_with(agents)

    @pytest.mark.asyncio
    async def test_update_configuration_not_running(
        self,
        xds_config: XDSServerConfig,
        config_generator: ConfigGenerator,
        sample_agent: Agent,
    ) -> None:
        """Test updating configuration when server not running raises error."""
        server = XDSServer(xds_config, config_generator)
        agents = [sample_agent]

        with pytest.raises(RuntimeError, match="server not running"):
            await server.update_configuration(agents)

    @pytest.mark.asyncio
    async def test_update_configuration_failure(
        self,
        xds_config: XDSServerConfig,
        config_generator: ConfigGenerator,
        sample_agent: Agent,
    ) -> None:
        """Test configuration update failure handling."""
        server = XDSServer(xds_config, config_generator)
        server._running = True

        agents = [sample_agent]

        with (
            patch.object(
                config_generator,
                "generate_listeners",
                new_callable=AsyncMock,
                side_effect=Exception("Generation failed"),
            ),
            pytest.raises(RuntimeError, match="Configuration update failed"),
        ):
            await server.update_configuration(agents)

    @pytest.mark.asyncio
    async def test_health_check_running(
        self, xds_config: XDSServerConfig, config_generator: ConfigGenerator
    ) -> None:
        """Test health check when server is running."""
        server = XDSServer(xds_config, config_generator)
        server._running = True
        server._config_version = 5

        health = await server.health_check()

        assert health["status"] == "healthy"
        assert health["running"] is True
        assert health["config_version"] == 5
        assert health["port"] == 18000
        assert health["mtls_enabled"] is False

    @pytest.mark.asyncio
    async def test_health_check_stopped(
        self, xds_config: XDSServerConfig, config_generator: ConfigGenerator
    ) -> None:
        """Test health check when server is stopped."""
        server = XDSServer(xds_config, config_generator)

        health = await server.health_check()

        assert health["status"] == "stopped"
        assert health["running"] is False
        assert health["config_version"] == 0

    def test_config_version_property(
        self, xds_config: XDSServerConfig, config_generator: ConfigGenerator
    ) -> None:
        """Test config_version property."""
        server = XDSServer(xds_config, config_generator)

        assert server.config_version == 0

        server._config_version = 42

        assert server.config_version == 42

    def test_is_running_property(
        self, xds_config: XDSServerConfig, config_generator: ConfigGenerator
    ) -> None:
        """Test is_running property."""
        server = XDSServer(xds_config, config_generator)

        assert server.is_running is False

        server._running = True

        assert server.is_running is True
