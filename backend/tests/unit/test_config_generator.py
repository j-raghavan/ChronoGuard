"""Unit tests for Envoy Config Generator."""

from __future__ import annotations

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


@pytest.fixture
def multiple_agents(test_certificate: X509Certificate) -> list[Agent]:
    """Create multiple sample agents."""
    tenant_id = uuid4()
    return [
        Agent(
            agent_id=uuid4(),
            tenant_id=tenant_id,
            name=f"agent-{i}",
            certificate=test_certificate,
            status=AgentStatus.ACTIVE,
        )
        for i in range(3)
    ]


class TestListenerConfig:
    """Test ListenerConfig dataclass."""

    def test_initialization(self) -> None:
        """Test listener config initialization."""
        config = ListenerConfig(
            name="test_listener",
            address="0.0.0.0",  # noqa: S104
            port=8443,
            filter_chains=[{"filter": "test"}],
        )

        assert config.name == "test_listener"
        assert config.address == "0.0.0.0"  # noqa: S104
        assert config.port == 8443
        assert len(config.filter_chains) == 1


class TestClusterConfig:
    """Test ClusterConfig dataclass."""

    def test_initialization(self) -> None:
        """Test cluster config initialization."""
        config = ClusterConfig(
            name="test_cluster",
            type="LOGICAL_DNS",
            connect_timeout_seconds=5,
            endpoints=["localhost:8080"],
        )

        assert config.name == "test_cluster"
        assert config.type == "LOGICAL_DNS"
        assert config.connect_timeout_seconds == 5
        assert config.endpoints == ["localhost:8080"]
        assert config.lb_policy == "ROUND_ROBIN"

    def test_custom_lb_policy(self) -> None:
        """Test cluster config with custom LB policy."""
        config = ClusterConfig(
            name="test_cluster",
            type="LOGICAL_DNS",
            connect_timeout_seconds=5,
            endpoints=["localhost:8080"],
            lb_policy="LEAST_REQUEST",
        )

        assert config.lb_policy == "LEAST_REQUEST"


class TestRouteConfig:
    """Test RouteConfig dataclass."""

    def test_initialization(self) -> None:
        """Test route config initialization."""
        virtual_hosts = [{"name": "host1", "domains": ["example.com"]}]
        config = RouteConfig(name="test_routes", virtual_hosts=virtual_hosts)

        assert config.name == "test_routes"
        assert len(config.virtual_hosts) == 1
        assert config.virtual_hosts[0]["name"] == "host1"


class TestEndpointConfig:
    """Test EndpointConfig dataclass."""

    def test_initialization(self) -> None:
        """Test endpoint config initialization."""
        config = EndpointConfig(
            cluster_name="test_cluster", endpoints=["localhost:8080", "localhost:8081"]
        )

        assert config.cluster_name == "test_cluster"
        assert len(config.endpoints) == 2


class TestConfigGenerator:
    """Test ConfigGenerator class."""

    def test_initialization(self) -> None:
        """Test generator initialization."""
        generator = ConfigGenerator()

        assert generator._opa_cluster_name == "opa_authz_cluster"
        assert generator._dynamic_proxy_cluster == "dynamic_forward_proxy_cluster"

    @pytest.mark.asyncio
    async def test_generate_listeners_empty(self, config_generator: ConfigGenerator) -> None:
        """Test generating listeners with empty agent list."""
        listeners = await config_generator.generate_listeners([])

        assert len(listeners) == 1  # Main proxy listener
        assert listeners[0].name == "chronoguard_proxy"
        assert listeners[0].address == "0.0.0.0"  # noqa: S104
        assert listeners[0].port == 8443

    @pytest.mark.asyncio
    async def test_generate_listeners_with_agents(
        self, config_generator: ConfigGenerator, sample_agent: Agent
    ) -> None:
        """Test generating listeners with agents."""
        listeners = await config_generator.generate_listeners([sample_agent])

        assert len(listeners) == 1
        listener = listeners[0]

        assert listener.name == "chronoguard_proxy"
        assert len(listener.filter_chains) == 1

        # Check filter chain has required filters
        filter_chain = listener.filter_chains[0]
        assert "filters" in filter_chain
        assert "transport_socket" in filter_chain

    @pytest.mark.asyncio
    async def test_generate_listeners_mtls_config(
        self, config_generator: ConfigGenerator, sample_agent: Agent
    ) -> None:
        """Test listener mTLS transport socket configuration."""
        listeners = await config_generator.generate_listeners([sample_agent])

        filter_chain = listeners[0].filter_chains[0]
        transport_socket = filter_chain["transport_socket"]

        assert transport_socket["name"] == "envoy.transport_sockets.tls"
        assert transport_socket["config"]["require_client_certificate"] is True

    @pytest.mark.asyncio
    async def test_generate_clusters_empty(self, config_generator: ConfigGenerator) -> None:
        """Test generating clusters with empty agent list."""
        clusters = await config_generator.generate_clusters([])

        assert len(clusters) == 2  # DFP cluster and OPA cluster

        cluster_names = {c.name for c in clusters}
        assert "dynamic_forward_proxy_cluster" in cluster_names
        assert "opa_authz_cluster" in cluster_names

    @pytest.mark.asyncio
    async def test_generate_clusters_with_agents(
        self, config_generator: ConfigGenerator, sample_agent: Agent
    ) -> None:
        """Test generating clusters with agents."""
        clusters = await config_generator.generate_clusters([sample_agent])

        assert len(clusters) == 2

        # Find OPA cluster
        opa_cluster = next((c for c in clusters if c.name == "opa_authz_cluster"), None)
        assert opa_cluster is not None
        assert opa_cluster.type == "LOGICAL_DNS"
        assert opa_cluster.connect_timeout_seconds == 1
        assert "opa:9191" in opa_cluster.endpoints

        # Find DFP cluster
        dfp_cluster = next((c for c in clusters if c.name == "dynamic_forward_proxy_cluster"), None)
        assert dfp_cluster is not None
        assert dfp_cluster.type == "LOGICAL_DNS"
        assert dfp_cluster.lb_policy == "CLUSTER_PROVIDED"

    @pytest.mark.asyncio
    async def test_generate_routes_empty(self, config_generator: ConfigGenerator) -> None:
        """Test generating routes with empty agent list."""
        routes = await config_generator.generate_routes([])

        assert len(routes) == 1
        assert routes[0].name == "chronoguard_routes"
        assert len(routes[0].virtual_hosts) == 0

    @pytest.mark.asyncio
    async def test_generate_routes_single_tenant(
        self, config_generator: ConfigGenerator, multiple_agents: list[Agent]
    ) -> None:
        """Test generating routes with single tenant."""
        # All agents have same tenant
        routes = await config_generator.generate_routes(multiple_agents)

        assert len(routes) == 1
        route_config = routes[0]

        assert route_config.name == "chronoguard_routes"
        assert len(route_config.virtual_hosts) == 1

        vhost = route_config.virtual_hosts[0]
        assert vhost["name"].startswith("tenant_")
        assert vhost["domains"] == ["*"]
        assert len(vhost["routes"]) == 1

    @pytest.mark.asyncio
    async def test_generate_routes_multiple_tenants(
        self,
        config_generator: ConfigGenerator,
        sample_agent: Agent,
        test_certificate: X509Certificate,
    ) -> None:
        """Test generating routes with multiple tenants."""
        # Create agents with different tenants
        agent2 = Agent(
            agent_id=uuid4(),
            tenant_id=uuid4(),  # Different tenant
            name="agent-2",
            certificate=test_certificate,
            status=AgentStatus.ACTIVE,
        )

        routes = await config_generator.generate_routes([sample_agent, agent2])

        assert len(routes) == 1
        route_config = routes[0]

        assert len(route_config.virtual_hosts) == 2

    @pytest.mark.asyncio
    async def test_generate_routes_retry_policy(
        self, config_generator: ConfigGenerator, sample_agent: Agent
    ) -> None:
        """Test route retry policy configuration."""
        routes = await config_generator.generate_routes([sample_agent])

        vhost = routes[0].virtual_hosts[0]
        route = vhost["routes"][0]

        assert "retry_policy" in route["route"]
        retry_policy = route["route"]["retry_policy"]
        assert retry_policy["num_retries"] == 3
        assert "5xx" in retry_policy["retry_on"]

    @pytest.mark.asyncio
    async def test_generate_routes_metadata(
        self, config_generator: ConfigGenerator, multiple_agents: list[Agent]
    ) -> None:
        """Test route metadata includes tenant info."""
        routes = await config_generator.generate_routes(multiple_agents)

        vhost = routes[0].virtual_hosts[0]
        route = vhost["routes"][0]

        assert "metadata" in route
        chronoguard_meta = route["metadata"]["filter_metadata"]["chronoguard"]
        assert "tenant_id" in chronoguard_meta
        assert chronoguard_meta["agent_count"] == 3

    @pytest.mark.asyncio
    async def test_generate_endpoints_empty(self, config_generator: ConfigGenerator) -> None:
        """Test generating endpoints with empty agent list."""
        endpoints = await config_generator.generate_endpoints([])

        assert len(endpoints) == 1  # OPA endpoint

        opa_endpoint = next((e for e in endpoints if e.cluster_name == "opa_authz_cluster"), None)
        assert opa_endpoint is not None
        assert "opa:9191" in opa_endpoint.endpoints

    @pytest.mark.asyncio
    async def test_generate_endpoints_with_agents(
        self, config_generator: ConfigGenerator, sample_agent: Agent
    ) -> None:
        """Test generating endpoints with agents."""
        endpoints = await config_generator.generate_endpoints([sample_agent])

        assert len(endpoints) >= 1

        opa_endpoint = next((e for e in endpoints if e.cluster_name == "opa_authz_cluster"), None)
        assert opa_endpoint is not None

    def test_create_mtls_config(
        self, config_generator: ConfigGenerator, multiple_agents: list[Agent]
    ) -> None:
        """Test mTLS configuration creation."""
        mtls_config = config_generator._create_mtls_config(multiple_agents)

        assert mtls_config["name"] == "envoy.transport_sockets.tls"
        assert "typed_config" in mtls_config

        typed_config = mtls_config["typed_config"]
        assert typed_config["require_client_certificate"] is True
        assert "common_tls_context" in typed_config

    def test_create_mtls_config_san_matching(
        self, config_generator: ConfigGenerator, multiple_agents: list[Agent]
    ) -> None:
        """Test mTLS config includes SAN matching for active agents."""
        # Set one agent to suspended
        multiple_agents[1].suspend()

        mtls_config = config_generator._create_mtls_config(multiple_agents)

        validation_context = mtls_config["typed_config"]["common_tls_context"]["validation_context"]
        san_matchers = validation_context["match_subject_alt_names"]

        # Should only include active agents that can make requests
        active_count = sum(1 for a in multiple_agents if a.can_make_requests())
        assert len(san_matchers) == active_count

    def test_create_authz_filter(self, config_generator: ConfigGenerator) -> None:
        """Test authorization filter configuration."""
        authz_filter = config_generator._create_authz_filter()

        assert authz_filter["name"] == "envoy.filters.http.ext_authz"
        assert "typed_config" in authz_filter

        typed_config = authz_filter["typed_config"]
        assert typed_config["failure_mode_deny"] is True
        assert typed_config["include_peer_certificate"] is True
        assert "grpc_service" in typed_config

        grpc_service = typed_config["grpc_service"]
        assert grpc_service["envoy_grpc"]["cluster_name"] == "opa_authz_cluster"

    def test_create_authz_filter_request_body(self, config_generator: ConfigGenerator) -> None:
        """Test authorization filter includes request body config."""
        authz_filter = config_generator._create_authz_filter()

        typed_config = authz_filter["typed_config"]
        assert "with_request_body" in typed_config

        body_config = typed_config["with_request_body"]
        assert body_config["max_request_bytes"] == 8192
        assert body_config["allow_partial_message"] is True
