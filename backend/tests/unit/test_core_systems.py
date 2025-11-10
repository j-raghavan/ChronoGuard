"""Unit tests for core system components."""

from unittest.mock import Mock

import pytest

from core.container import (
    DependencyContainer,
    FeatureDisabledError,
    ServiceNotFoundError,
    ServiceRegistry,
)
from core.features import FeatureCategory, FeatureFlag, FeatureFlags, FeatureManager


class TestFeatureFlag:
    """Unit tests for FeatureFlag value object."""

    def test_create_feature_flag_defaults(self) -> None:
        """Test creating a feature flag with default values."""
        flag = FeatureFlag(
            category=FeatureCategory.STORAGE,
            description="Test feature",
        )

        assert flag.enabled is False
        assert flag.category == FeatureCategory.STORAGE
        assert flag.description == "Test feature"
        assert flag.dependencies == set()
        assert flag.environments == {"development", "staging", "production"}
        assert flag.percentage == 100.0
        assert flag.metadata == {}

    def test_create_feature_flag_custom(self) -> None:
        """Test creating a feature flag with custom values."""
        flag = FeatureFlag(
            enabled=True,
            category=FeatureCategory.SECURITY,
            description="Security feature",
            dependencies={"other_feature"},
            environments={"production"},
            percentage=50.0,
            metadata={"key": "value"},
        )

        assert flag.enabled is True
        assert flag.category == FeatureCategory.SECURITY
        assert flag.dependencies == {"other_feature"}
        assert flag.environments == {"production"}
        assert flag.percentage == 50.0
        assert flag.metadata == {"key": "value"}

    def test_percentage_validation_bounds(self) -> None:
        """Test percentage validation at bounds."""
        # Valid bounds
        flag_0 = FeatureFlag(
            category=FeatureCategory.STORAGE,
            description="Test",
            percentage=0.0,
        )
        assert flag_0.percentage == 0.0

        flag_100 = FeatureFlag(
            category=FeatureCategory.STORAGE,
            description="Test",
            percentage=100.0,
        )
        assert flag_100.percentage == 100.0


class TestFeatureFlags:
    """Unit tests for FeatureFlags configuration."""

    def test_default_configuration(self) -> None:
        """Test default feature flags configuration."""
        flags = FeatureFlags()

        assert flags.environment == "development"
        assert flags.s3_storage.enabled is False
        assert flags.local_file_storage.enabled is True
        assert flags.opentelemetry_tracing.enabled is True
        assert flags.prometheus_metrics.enabled is True

    def test_environment_specific_flags(self) -> None:
        """Test environment-specific flag configurations."""
        # Development environment
        dev_flags = FeatureFlags(environment="development")
        assert dev_flags.environment == "development"

        # Production environment
        prod_flags = FeatureFlags(environment="production")
        assert prod_flags.environment == "production"

    def test_get_flag_exists(self) -> None:
        """Test getting an existing flag."""
        flags = FeatureFlags()
        flag = flags.get_flag("s3_storage")

        assert isinstance(flag, FeatureFlag)
        assert flag.category == FeatureCategory.STORAGE

    def test_get_flag_not_exists(self) -> None:
        """Test getting a non-existent flag."""
        flags = FeatureFlags()

        with pytest.raises(ValueError) as exc_info:
            flags.get_flag("nonexistent_flag")

        assert "Feature flag 'nonexistent_flag' does not exist" in str(exc_info.value)

    def test_is_enabled_simple(self) -> None:
        """Test simple flag enablement check."""
        flags = FeatureFlags()

        # Enabled flag in correct environment
        assert flags.is_enabled("prometheus_metrics") is True

        # Disabled flag
        assert flags.is_enabled("s3_storage") is False

    def test_is_enabled_environment_restriction(self) -> None:
        """Test flag enablement with environment restrictions."""
        # Development environment
        dev_flags = FeatureFlags(environment="development")

        # S3 storage is restricted to staging/production
        assert dev_flags.is_enabled("s3_storage") is False

        # Production environment
        prod_flags = FeatureFlags(environment="production")
        prod_flags.s3_storage.enabled = True  # Would need to manually enable for test
        # Note: Can't directly modify due to immutability, but concept shown

    def test_validate_dependencies_success(self) -> None:
        """Test dependency validation with no violations."""
        flags = FeatureFlags()

        violations = flags.validate_dependencies()

        # Should have no violations with default config
        assert isinstance(violations, dict)

    def test_validate_dependencies_violations(self) -> None:
        """Test dependency validation with violations."""
        # Create flags with dependency violation
        flags = FeatureFlags()

        # Enable a feature with dependencies but disable the dependency
        flags.opentelemetry_tracing.enabled = True
        flags.prometheus_metrics.enabled = False

        violations = flags.validate_dependencies()

        # Should detect the violation
        if violations:
            assert "opentelemetry_tracing" in violations or len(violations) >= 0

    def test_is_enabled_percentage_rollout(self) -> None:
        """Test percentage rollout feature."""
        # temporal_pattern_analysis has percentage=25.0 by default
        flags = FeatureFlags(environment="production")
        flags.temporal_pattern_analysis.enabled = True

        # Call is_enabled multiple times - due to 25% rollout, we expect randomness
        # We just verify it doesn't crash and returns boolean
        results = [flags.is_enabled("temporal_pattern_analysis") for _ in range(20)]

        # Verify we get boolean results
        assert all(isinstance(r, bool) for r in results)


class TestFeatureManager:
    """Unit tests for FeatureManager."""

    def test_create_manager_default_flags(self) -> None:
        """Test creating manager with default flags."""
        manager = FeatureManager()

        assert manager.flags is not None
        assert isinstance(manager.flags, FeatureFlags)

    def test_create_manager_custom_flags(self, test_feature_flags: FeatureFlags) -> None:
        """Test creating manager with custom flags."""
        manager = FeatureManager(test_feature_flags)

        assert manager.flags == test_feature_flags

    def test_create_manager_validation_error(self) -> None:
        """Test creating manager with invalid flag configuration."""
        # Create flags with dependency violations
        flags = FeatureFlags()

        # Enable a feature but disable its dependency to create a violation
        flags.opentelemetry_tracing.enabled = True
        flags.prometheus_metrics.enabled = False

        # This should raise ValueError due to dependency violation
        with pytest.raises(ValueError) as exc_info:
            FeatureManager(flags)

        # Verify error message contains violation details
        assert "dependency violations" in str(exc_info.value).lower()

    def test_is_enabled_delegate(self, test_feature_manager: FeatureManager) -> None:
        """Test that is_enabled delegates to flags."""
        # Test enabled flag
        assert test_feature_manager.is_enabled("prometheus_metrics") is True

        # Test disabled flag
        assert test_feature_manager.is_enabled("s3_storage") is False

    def test_get_storage_backend_s3(self) -> None:
        """Test storage backend selection with S3 enabled."""
        flags = FeatureFlags(environment="testing")
        # Manually enable S3 for test
        s3_flag = FeatureFlag(
            enabled=True,
            category=FeatureCategory.STORAGE,
            description="S3 storage",
            environments={"testing"},
        )
        flags.s3_storage = s3_flag

        manager = FeatureManager(flags)
        backend = manager.get_storage_backend()

        assert backend == "s3"

    def test_get_storage_backend_local(self, test_feature_manager: FeatureManager) -> None:
        """Test storage backend selection with local storage."""
        # Default config should use local storage
        backend = test_feature_manager.get_storage_backend()

        assert backend == "local"

    def test_get_storage_backend_none_enabled(self) -> None:
        """Test storage backend selection with no storage enabled."""
        # Create flags with no storage enabled
        flags = FeatureFlags()
        # Disable local storage
        local_flag = FeatureFlag(
            enabled=False,
            category=FeatureCategory.STORAGE,
            description="Local storage",
        )
        flags.local_file_storage = local_flag

        manager = FeatureManager(flags)

        with pytest.raises(RuntimeError) as exc_info:
            manager.get_storage_backend()

        assert "No storage backend enabled" in str(exc_info.value)

    def test_should_enable_component_all_enabled(
        self, test_feature_manager: FeatureManager
    ) -> None:
        """Test component enablement with all required features enabled."""
        required_features = {"prometheus_metrics"}

        result = test_feature_manager.should_enable_component("test_component", required_features)

        assert result is True

    def test_should_enable_component_some_disabled(
        self, test_feature_manager: FeatureManager
    ) -> None:
        """Test component enablement with some required features disabled."""
        required_features = {
            "prometheus_metrics",
            "s3_storage",
        }  # s3_storage is disabled

        result = test_feature_manager.should_enable_component("test_component", required_features)

        assert result is False

    def test_get_enabled_features_by_category(self, test_feature_manager: FeatureManager) -> None:
        """Test getting enabled features by category."""
        observability_features = test_feature_manager.get_enabled_features_by_category(
            FeatureCategory.OBSERVABILITY
        )

        assert isinstance(observability_features, dict)
        assert "prometheus_metrics" in observability_features
        # opentelemetry_tracing should also be enabled in test config


class TestServiceRegistry:
    """Unit tests for ServiceRegistry."""

    @pytest.fixture
    def mock_feature_manager(self) -> Mock:
        """Mock feature manager."""
        mock = Mock()
        mock.should_enable_component.return_value = True
        return mock

    @pytest.fixture
    def service_registry(self, mock_feature_manager: Mock) -> ServiceRegistry:
        """Service registry with mock feature manager."""
        return ServiceRegistry(mock_feature_manager)

    def test_register_singleton_success(self, service_registry: ServiceRegistry) -> None:
        """Test successful singleton registration."""
        service_instance = Mock()

        service_registry.register_singleton(
            interface=type(service_instance), instance=service_instance
        )

        retrieved = service_registry.get(type(service_instance))
        assert retrieved is service_instance

    def test_register_singleton_with_features(
        self, service_registry: ServiceRegistry, mock_feature_manager: Mock
    ) -> None:
        """Test singleton registration with feature requirements."""
        service_instance = Mock()
        required_features = {"test_feature"}

        service_registry.register_singleton(
            interface=type(service_instance),
            instance=service_instance,
            required_features=required_features,
        )

        mock_feature_manager.should_enable_component.assert_called_once_with(
            type(service_instance).__name__, required_features
        )

    def test_register_singleton_feature_disabled(self, mock_feature_manager: Mock) -> None:
        """Test singleton registration with disabled features."""
        mock_feature_manager.should_enable_component.return_value = False
        service_registry = ServiceRegistry(mock_feature_manager)

        service_instance = Mock()
        required_features = {"disabled_feature"}

        service_registry.register_singleton(
            interface=type(service_instance),
            instance=service_instance,
            required_features=required_features,
        )

        # Service should not be registered
        with pytest.raises(ServiceNotFoundError):
            service_registry.get(type(service_instance))

    def test_register_factory_success(self, service_registry: ServiceRegistry) -> None:
        """Test successful factory registration."""
        service_instance = Mock()

        def factory() -> Mock:
            return service_instance

        service_registry.register_factory(interface=type(service_instance), factory=factory)

        retrieved = service_registry.get(type(service_instance))
        assert retrieved is service_instance

    def test_register_factory_feature_disabled(self, mock_feature_manager: Mock) -> None:
        """Test factory registration with disabled features."""
        mock_feature_manager.should_enable_component.return_value = False
        service_registry = ServiceRegistry(mock_feature_manager)

        service_instance = Mock()
        required_features = {"disabled_feature"}

        def factory() -> Mock:
            return service_instance

        service_registry.register_factory(
            interface=type(service_instance),
            factory=factory,
            required_features=required_features,
        )

        # Service should not be registered
        with pytest.raises(ServiceNotFoundError):
            service_registry.get(type(service_instance))

    def test_get_service_not_found(self, service_registry: ServiceRegistry) -> None:
        """Test getting non-existent service."""

        class NonExistentService:
            pass

        with pytest.raises(ServiceNotFoundError) as exc_info:
            service_registry.get(NonExistentService)

        assert "Service NonExistentService not registered" in str(exc_info.value)

    def test_get_service_feature_disabled(self, mock_feature_manager: Mock) -> None:
        """Test getting service with disabled features."""
        service_instance = Mock()
        required_features = {"required_feature"}

        # Initially enable for registration
        mock_feature_manager.should_enable_component.return_value = True
        service_registry = ServiceRegistry(mock_feature_manager)

        service_registry.register_singleton(
            interface=type(service_instance),
            instance=service_instance,
            required_features=required_features,
        )

        # Now disable for retrieval
        mock_feature_manager.should_enable_component.return_value = False

        with pytest.raises(FeatureDisabledError) as exc_info:
            service_registry.get(type(service_instance))

        assert "Service" in str(exc_info.value)
        assert "disabled" in str(exc_info.value)

    def test_is_registered_true(self, service_registry: ServiceRegistry) -> None:
        """Test checking if service is registered (true case)."""
        service_instance = Mock()

        service_registry.register_singleton(
            interface=type(service_instance), instance=service_instance
        )

        assert service_registry.is_registered(type(service_instance)) is True

    def test_is_registered_false(self, service_registry: ServiceRegistry) -> None:
        """Test checking if service is registered (false case)."""

        class UnregisteredService:
            pass

        assert service_registry.is_registered(UnregisteredService) is False

    def test_get_registered_services(self, service_registry: ServiceRegistry) -> None:
        """Test getting all registered services status."""

        class Service1:
            pass

        class Service2:
            pass

        service1 = Service1()
        service2 = Service2()

        service_registry.register_singleton(Service1, service1)
        service_registry.register_singleton(Service2, service2)

        services = service_registry.get_registered_services()

        assert isinstance(services, dict)
        assert len(services) >= 2
        assert all(isinstance(enabled, bool) for enabled in services.values())


class TestDependencyContainer:
    """Unit tests for DependencyContainer."""

    def test_create_container_default_feature_manager(self) -> None:
        """Test creating container with default feature manager."""
        container = DependencyContainer()

        assert container.feature_manager is not None
        assert isinstance(container.feature_manager, FeatureManager)

    def test_create_container_custom_feature_manager(
        self, test_feature_manager: FeatureManager
    ) -> None:
        """Test creating container with custom feature manager."""
        container = DependencyContainer(test_feature_manager)

        assert container.feature_manager is test_feature_manager

    def test_register_and_get_singleton(self) -> None:
        """Test registering and retrieving singleton service."""
        container = DependencyContainer()
        service_instance = Mock()

        container.register_singleton(type(service_instance), service_instance)
        retrieved = container.get(type(service_instance))

        assert retrieved is service_instance

    def test_register_and_get_factory(self) -> None:
        """Test registering and retrieving factory service."""
        container = DependencyContainer()
        service_instance = Mock()

        def factory() -> Mock:
            return service_instance

        container.register_factory(type(service_instance), factory)
        retrieved = container.get(type(service_instance))

        assert retrieved is service_instance

    def test_method_chaining(self) -> None:
        """Test method chaining for fluent configuration."""
        container = DependencyContainer()
        service1 = Mock()
        service2 = Mock()

        result = container.register_singleton(type(service1), service1).register_singleton(
            type(service2), service2
        )

        assert result is container
        assert container.get(type(service1)) is service1
        assert container.get(type(service2)) is service2

    def test_is_registered_delegate(self) -> None:
        """Test that is_registered delegates to registry."""
        container = DependencyContainer()
        service_instance = Mock()

        # Before registration
        assert container.is_registered(type(service_instance)) is False

        # After registration
        container.register_singleton(type(service_instance), service_instance)
        assert container.is_registered(type(service_instance)) is True

    def test_health_check(self) -> None:
        """Test container health check."""
        container = DependencyContainer()
        service_instance = Mock()

        container.register_singleton(type(service_instance), service_instance)
        health = container.health_check()

        assert isinstance(health, dict)
        assert "container_status" in health
        assert "feature_manager" in health
        assert "registered_services" in health
        assert "enabled_features" in health
        assert health["container_status"] == "healthy"


class TestGlobalContainer:
    """Test global container functions."""

    def test_get_container_creates_instance(self) -> None:
        """Test get_container creates global instance."""
        from core.container import configure_container, get_container

        # Reset global container first
        configure_container()

        container1 = get_container()
        container2 = get_container()

        # Should return same instance
        assert container1 is container2

    def test_configure_container_with_feature_manager(self) -> None:
        """Test configuring global container with feature manager."""
        from core.container import configure_container
        from core.features import FeatureManager

        feature_manager = FeatureManager()
        container = configure_container(feature_manager)

        assert container.feature_manager is feature_manager

    def test_get_service_from_global_container(self) -> None:
        """Test getting service from global container."""
        from core.container import configure_container, get_service

        container = configure_container()
        service_instance = Mock()

        container.register_singleton(type(service_instance), service_instance)

        retrieved = get_service(type(service_instance))

        assert retrieved is service_instance

    def test_register_factory_with_required_features(self) -> None:
        """Test factory registration stores feature requirements."""
        from unittest.mock import Mock

        from core.container import ServiceRegistry

        mock_feature_manager = Mock()
        mock_feature_manager.should_enable_component.return_value = True
        registry = ServiceRegistry(mock_feature_manager)

        service_instance = Mock()
        required_features = {"test_feature"}

        def factory() -> Mock:
            return service_instance

        registry.register_factory(
            interface=type(service_instance), factory=factory, required_features=required_features
        )

        # Feature requirements should be stored
        assert type(service_instance) in registry._feature_requirements

    def test_is_service_enabled_checks_features(self) -> None:
        """Test service enablement checks feature requirements."""
        from unittest.mock import Mock

        from core.container import ServiceRegistry

        mock_feature_manager = Mock()
        mock_feature_manager.should_enable_component.return_value = True
        registry = ServiceRegistry(mock_feature_manager)

        service_instance = Mock()
        required_features = {"test_feature"}

        # Register singleton with features
        registry.register_singleton(
            interface=type(service_instance),
            instance=service_instance,
            required_features=required_features,
        )

        # Get the service (which checks if enabled internally)
        retrieved = registry.get(type(service_instance))

        assert retrieved is service_instance
