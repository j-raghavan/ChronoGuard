"""Envoy configuration generator from domain models.

This module generates Envoy proxy configurations (listeners, clusters, routes,
endpoints) from ChronoGuard domain models (agents, policies). It translates
high-level security policies into low-level Envoy filter configurations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from uuid import UUID

from loguru import logger

if TYPE_CHECKING:
    from domain.agent.entity import Agent


@dataclass
class ListenerConfig:
    """Envoy listener configuration.

    Attributes:
        name: Listener name
        address: Listen address
        port: Listen port
        filter_chains: List of filter chain configurations
    """

    name: str
    address: str
    port: int
    filter_chains: list[dict[str, Any]]


@dataclass
class ClusterConfig:
    """Envoy cluster configuration.

    Attributes:
        name: Cluster name
        type: Cluster type (STATIC, STRICT_DNS, LOGICAL_DNS, etc.)
        connect_timeout_seconds: Connection timeout in seconds
        endpoints: List of endpoint addresses
        lb_policy: Load balancing policy
    """

    name: str
    type: str
    connect_timeout_seconds: int
    endpoints: list[str]
    lb_policy: str = "ROUND_ROBIN"


@dataclass
class RouteConfig:
    """Envoy route configuration.

    Attributes:
        name: Route configuration name
        virtual_hosts: List of virtual host configurations
    """

    name: str
    virtual_hosts: list[dict[str, Any]]


@dataclass
class EndpointConfig:
    """Envoy endpoint configuration.

    Attributes:
        cluster_name: Name of the cluster this endpoint belongs to
        endpoints: List of endpoint addresses with ports
    """

    cluster_name: str
    endpoints: list[str]


class ConfigGenerator:
    """Generates Envoy configuration from domain models.

    This class translates ChronoGuard's domain model (agents, policies) into
    Envoy proxy configuration structures. It creates:
    - Listeners with mTLS and authorization filters
    - Clusters for dynamic forward proxy and OPA
    - Routes based on agent policies
    - Endpoints for upstream services

    Example:
        >>> generator = ConfigGenerator()
        >>> agents = [agent1, agent2]
        >>> listeners = await generator.generate_listeners(agents)
        >>> clusters = await generator.generate_clusters(agents)
    """

    def __init__(self) -> None:
        """Initialize configuration generator."""
        self._opa_cluster_name = "opa_authz_cluster"
        self._dynamic_proxy_cluster = "dynamic_forward_proxy_cluster"

    async def generate_listeners(self, agents: list[Agent]) -> list[ListenerConfig]:
        """Generate listener configurations for agents.

        Creates a main proxy listener with:
        - mTLS for agent authentication
        - External authorization (OPA) filter
        - Dynamic forward proxy filter
        - HTTP connection manager

        Args:
            agents: List of agents to configure

        Returns:
            List of listener configurations
        """
        listeners: list[ListenerConfig] = []

        # Main proxy listener
        main_listener = ListenerConfig(
            name="chronoguard_proxy",
            address="0.0.0.0",  # noqa: S104 - Envoy proxy binds to all interfaces
            port=8443,
            filter_chains=[
                {
                    "filters": [
                        {
                            "name": "envoy.filters.network.http_connection_manager",
                            "config": {
                                "stat_prefix": "chronoguard",
                                "codec_type": "AUTO",
                                "route_config": {
                                    "name": "local_route",
                                    "virtual_hosts": [
                                        {
                                            "name": "backend",
                                            "domains": ["*"],
                                            "routes": [
                                                {
                                                    "match": {"prefix": "/"},
                                                    "route": {
                                                        "cluster": self._dynamic_proxy_cluster,
                                                        "timeout": "30s",
                                                    },
                                                }
                                            ],
                                        }
                                    ],
                                },
                                "http_filters": [
                                    {
                                        "name": "envoy.filters.http.ext_authz",
                                        "config": {
                                            "grpc_service": {
                                                "envoy_grpc": {
                                                    "cluster_name": self._opa_cluster_name
                                                },
                                                "timeout": "1s",
                                            },
                                            "failure_mode_deny": True,
                                            "include_peer_certificate": True,
                                        },
                                    },
                                    {
                                        "name": "envoy.filters.http.dynamic_forward_proxy",
                                        "config": {
                                            "dns_cache_config": {
                                                "name": "dynamic_forward_proxy_cache",
                                                "dns_lookup_family": "V4_ONLY",
                                                "max_hosts": 5000,
                                                "dns_refresh_rate": "30s",
                                                "host_ttl": "300s",
                                            }
                                        },
                                    },
                                    {"name": "envoy.filters.http.router"},
                                ],
                            },
                        }
                    ],
                    "transport_socket": {
                        "name": "envoy.transport_sockets.tls",
                        "config": {
                            "require_client_certificate": True,
                            "common_tls_context": {
                                "tls_certificates": [
                                    {
                                        "certificate_chain": {"filename": "/etc/envoy/server.crt"},
                                        "private_key": {"filename": "/etc/envoy/server.key"},
                                    }
                                ],
                                "validation_context": {
                                    "trusted_ca": {"filename": "/etc/envoy/ca.crt"}
                                },
                            },
                        },
                    },
                }
            ],
        )

        listeners.append(main_listener)
        logger.debug(f"Generated {len(listeners)} listener configurations")
        return listeners

    async def generate_clusters(self, agents: list[Agent]) -> list[ClusterConfig]:
        """Generate cluster configurations.

        Creates clusters for:
        - Dynamic forward proxy (for outbound requests)
        - OPA authorization service
        - Any agent-specific upstream services

        Args:
            agents: List of agents to configure

        Returns:
            List of cluster configurations
        """
        clusters: list[ClusterConfig] = []

        # Dynamic forward proxy cluster
        dynamic_cluster = ClusterConfig(
            name=self._dynamic_proxy_cluster,
            type="LOGICAL_DNS",
            connect_timeout_seconds=5,
            endpoints=[],  # DFP clusters don't use static endpoints
            lb_policy="CLUSTER_PROVIDED",
        )
        clusters.append(dynamic_cluster)

        # OPA authorization cluster (gRPC)
        opa_cluster = ClusterConfig(
            name=self._opa_cluster_name,
            type="LOGICAL_DNS",
            connect_timeout_seconds=1,
            endpoints=["opa:9191"],  # OPA gRPC Envoy plugin port
            lb_policy="ROUND_ROBIN",
        )
        clusters.append(opa_cluster)

        logger.debug(f"Generated {len(clusters)} cluster configurations")
        return clusters

    async def generate_routes(self, agents: list[Agent]) -> list[RouteConfig]:
        """Generate route configurations based on agent policies.

        Creates route configurations that:
        - Map domains to appropriate clusters
        - Apply per-agent routing rules
        - Configure timeouts and retries

        Args:
            agents: List of agents to configure

        Returns:
            List of route configurations
        """
        routes: list[RouteConfig] = []

        # Create virtual hosts per tenant for better isolation
        virtual_hosts: list[dict[str, Any]] = []

        # Group agents by tenant
        tenants: dict[UUID, list[Agent]] = {}
        for agent in agents:
            if agent.tenant_id not in tenants:
                tenants[agent.tenant_id] = []
            tenants[agent.tenant_id].append(agent)

        # Create virtual host per tenant
        for tenant_id, tenant_agents in tenants.items():
            virtual_host = {
                "name": f"tenant_{tenant_id}",
                "domains": ["*"],  # Will be refined based on policies
                "routes": [
                    {
                        "match": {"prefix": "/"},
                        "route": {
                            "cluster": self._dynamic_proxy_cluster,
                            "timeout": "30s",
                            "retry_policy": {
                                "retry_on": "5xx,reset,connect-failure,refused-stream",
                                "num_retries": 3,
                                "per_try_timeout": "10s",
                            },
                        },
                        "metadata": {
                            "filter_metadata": {
                                "chronoguard": {
                                    "tenant_id": str(tenant_id),
                                    "agent_count": len(tenant_agents),
                                }
                            }
                        },
                    }
                ],
            }
            virtual_hosts.append(virtual_host)

        route_config = RouteConfig(name="chronoguard_routes", virtual_hosts=virtual_hosts)
        routes.append(route_config)

        logger.debug(
            f"Generated {len(routes)} route configurations "
            f"with {len(virtual_hosts)} virtual hosts"
        )
        return routes

    async def generate_endpoints(self, agents: list[Agent]) -> list[EndpointConfig]:
        """Generate endpoint configurations.

        Creates endpoint assignments for clusters, mapping cluster names
        to their backend endpoints.

        Args:
            agents: List of agents to configure

        Returns:
            List of endpoint configurations
        """
        endpoints: list[EndpointConfig] = []

        # OPA endpoint
        opa_endpoint = EndpointConfig(cluster_name=self._opa_cluster_name, endpoints=["opa:9191"])
        endpoints.append(opa_endpoint)

        # Dynamic forward proxy doesn't need static endpoints
        # Additional agent-specific endpoints would be added here

        logger.debug(f"Generated {len(endpoints)} endpoint configurations")
        return endpoints

    def _create_mtls_config(self, agents: list[Agent]) -> dict[str, Any]:
        """Create mTLS transport socket configuration.

        Args:
            agents: Agents requiring mTLS authentication

        Returns:
            Transport socket configuration dictionary
        """
        return {
            "name": "envoy.transport_sockets.tls",
            "typed_config": {
                "@type": (
                    "type.googleapis.com/envoy.extensions.transport_sockets."
                    "tls.v3.DownstreamTlsContext"
                ),
                "require_client_certificate": True,
                "common_tls_context": {
                    "tls_certificates": [
                        {
                            "certificate_chain": {"filename": "/etc/envoy/server.crt"},
                            "private_key": {"filename": "/etc/envoy/server.key"},
                        }
                    ],
                    "validation_context": {
                        "trusted_ca": {"filename": "/etc/envoy/ca.crt"},
                        "match_subject_alt_names": [
                            {
                                "exact": (
                                    agent.certificate.subject_common_name
                                    or f"agent-{agent.agent_id}"
                                )
                            }
                            for agent in agents
                            if agent.can_make_requests()
                        ],
                    },
                },
            },
        }

    def _create_authz_filter(self) -> dict[str, Any]:
        """Create external authorization filter configuration.

        Returns:
            Authorization filter configuration dictionary
        """
        return {
            "name": "envoy.filters.http.ext_authz",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz",
                "grpc_service": {
                    "envoy_grpc": {"cluster_name": self._opa_cluster_name},
                    "timeout": "1s",
                },
                "failure_mode_deny": True,
                "include_peer_certificate": True,
                "with_request_body": {
                    "max_request_bytes": 8192,
                    "allow_partial_message": True,
                },
            },
        }
