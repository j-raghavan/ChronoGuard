"""Dependency injection container with feature flag awareness."""

from __future__ import annotations

from collections.abc import Callable
from functools import cache
from typing import Any, TypeVar

from core.features import FeatureCategory, FeatureManager

T = TypeVar("T")


class ServiceRegistry:
    """Registry for service instances and factories with feature flag support."""

    def __init__(self, feature_manager: FeatureManager) -> None:
        """Initialize service registry.

        Args:
            feature_manager: Feature manager for conditional service activation
        """
        self._feature_manager = feature_manager
        self._instances: dict[type[Any], Any] = {}
        self._factories: dict[type[Any], Callable[[], Any]] = {}
        self._feature_requirements: dict[type[Any], set[str]] = {}

    def register_singleton(
        self,
        interface: type[T],
        instance: T,
        required_features: set[str] | None = None,
    ) -> None:
        """Register a singleton instance.

        Args:
            interface: Interface type
            instance: Service instance
            required_features: Set of feature flags required for this service
        """
        if required_features and not self._feature_manager.should_enable_component(
            interface.__name__, required_features
        ):
            return

        self._instances[interface] = instance
        if required_features:
            self._feature_requirements[interface] = required_features

    def register_factory(
        self,
        interface: type[T],
        factory: Callable[[], T],
        required_features: set[str] | None = None,
    ) -> None:
        """Register a service factory.

        Args:
            interface: Interface type
            factory: Factory function that creates service instances
            required_features: Set of feature flags required for this service
        """
        if required_features and not self._feature_manager.should_enable_component(
            interface.__name__, required_features
        ):
            return

        self._factories[interface] = factory
        if required_features:
            self._feature_requirements[interface] = required_features

    def get(self, interface: type[T]) -> T:
        """Get service instance by interface type.

        Args:
            interface: Interface type to resolve

        Returns:
            Service instance

        Raises:
            ServiceNotFoundError: If service is not registered
            FeatureDisabledError: If required features are disabled
        """
        # Check if service has feature requirements
        if interface in self._feature_requirements:
            required_features = self._feature_requirements[interface]
            if not self._feature_manager.should_enable_component(
                interface.__name__, required_features
            ):
                raise FeatureDisabledError(
                    f"Service {interface.__name__} disabled: "
                    f"required features {required_features} not enabled"
                )

        # Return singleton instance if available
        if interface in self._instances:
            return self._instances[interface]

        # Create instance from factory
        if interface in self._factories:
            instance = self._factories[interface]()
            self._instances[interface] = instance
            return instance

        raise ServiceNotFoundError(f"Service {interface.__name__} not registered")

    def is_registered(self, interface: type[T]) -> bool:
        """Check if a service is registered and enabled.

        Args:
            interface: Interface type to check

        Returns:
            True if service is registered and enabled, False otherwise
        """
        if interface not in self._instances and interface not in self._factories:
            return False

        if interface in self._feature_requirements:
            required_features = self._feature_requirements[interface]
            return self._feature_manager.should_enable_component(
                interface.__name__, required_features
            )

        return True

    def get_registered_services(self) -> dict[str, bool]:
        """Get status of all registered services.

        Returns:
            Dictionary mapping service names to their enabled status
        """
        services = {}

        all_interfaces = set(self._instances.keys()) | set(self._factories.keys())
        for interface in all_interfaces:
            services[interface.__name__] = self.is_registered(interface)

        return services


class DependencyContainer:
    """Main dependency injection container with feature flag integration."""

    def __init__(self, feature_manager: FeatureManager | None = None) -> None:
        """Initialize dependency container.

        Args:
            feature_manager: Optional feature manager. Creates default if None.
        """
        self._feature_manager = feature_manager or FeatureManager()
        self._registry = ServiceRegistry(self._feature_manager)

    @property
    def feature_manager(self) -> FeatureManager:
        """Get the feature manager instance."""
        return self._feature_manager

    def register_singleton(
        self,
        interface: type[T],
        instance: T,
        required_features: set[str] | None = None,
    ) -> DependencyContainer:
        """Register a singleton service.

        Args:
            interface: Service interface type
            instance: Service instance
            required_features: Feature flags required for this service

        Returns:
            Self for method chaining
        """
        self._registry.register_singleton(interface, instance, required_features)
        return self

    def register_factory(
        self,
        interface: type[T],
        factory: Callable[[], T],
        required_features: set[str] | None = None,
    ) -> DependencyContainer:
        """Register a service factory.

        Args:
            interface: Service interface type
            factory: Factory function
            required_features: Feature flags required for this service

        Returns:
            Self for method chaining
        """
        self._registry.register_factory(interface, factory, required_features)
        return self

    def get(self, interface: type[T]) -> T:
        """Resolve service by interface type.

        Args:
            interface: Service interface type

        Returns:
            Service instance
        """
        return self._registry.get(interface)

    def is_registered(self, interface: type[T]) -> bool:
        """Check if service is registered and enabled.

        Args:
            interface: Service interface type

        Returns:
            True if service is available, False otherwise
        """
        return self._registry.is_registered(interface)

    def health_check(self) -> dict[str, Any]:
        """Perform health check on container and services.

        Returns:
            Health check status with service information
        """
        return {
            "container_status": "healthy",
            "feature_manager": "enabled",
            "registered_services": self._registry.get_registered_services(),
            "enabled_features": {
                category.value: list(
                    self._feature_manager.get_enabled_features_by_category(category).keys()
                )
                for category in FeatureCategory
            },
        }


class ServiceNotFoundError(Exception):
    """Raised when a requested service is not registered."""

    pass


class FeatureDisabledError(Exception):
    """Raised when a service's required features are disabled."""

    pass


# Global container instance
_container: DependencyContainer | None = None


def get_container() -> DependencyContainer:
    """Get the global dependency container instance.

    Returns:
        Global DependencyContainer instance
    """
    global _container
    if _container is None:
        _container = DependencyContainer()
    return _container


@cache
def get_service(interface: type[T]) -> T:
    """Get service from global container with caching.

    Args:
        interface: Service interface type

    Returns:
        Service instance
    """
    return get_container().get(interface)


def configure_container(
    feature_manager: FeatureManager | None = None,
) -> DependencyContainer:
    """Configure the global dependency container.

    Args:
        feature_manager: Optional feature manager instance

    Returns:
        Configured DependencyContainer instance
    """
    global _container
    _container = DependencyContainer(feature_manager)
    # Clear LRU cache when container is reconfigured
    get_service.cache_clear()
    return _container
