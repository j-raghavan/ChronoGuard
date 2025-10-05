"""Feature flag system for ChronoGuard with conditional service activation."""

from __future__ import annotations

import secrets
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class FeatureCategory(str, Enum):
    """Categories of features for organization."""

    STORAGE = "storage"
    OBSERVABILITY = "observability"
    SECURITY = "security"
    PROXY = "proxy"
    AUDIT = "audit"
    ANALYTICS = "analytics"
    INTEGRATIONS = "integrations"


class FeatureFlag(BaseModel):
    """Individual feature flag configuration."""

    enabled: bool = False
    category: FeatureCategory
    description: str
    dependencies: set[str] = Field(default_factory=set)
    environments: set[str] = Field(default_factory=lambda: {"development", "staging", "production"})
    percentage: float = Field(default=100.0, ge=0.0, le=100.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class FeatureFlags(BaseSettings):
    """ChronoGuard feature flag configuration."""

    model_config = {"env_prefix": "CHRONOGUARD_FEATURE_", "case_sensitive": False}

    # Environment
    environment: str = Field(default="development")

    # Storage Features
    s3_storage: FeatureFlag = Field(
        default_factory=lambda: FeatureFlag(
            enabled=False,
            category=FeatureCategory.STORAGE,
            description="Enable S3 storage for audit logs and reports",
            environments={"staging", "production"},
            metadata={"bucket_prefix": "chronoguard-"},
        )
    )

    local_file_storage: FeatureFlag = Field(
        default_factory=lambda: FeatureFlag(
            enabled=True,
            category=FeatureCategory.STORAGE,
            description="Enable local file storage for audit logs",
            environments={"development", "testing"},
        )
    )

    # Observability Features
    opentelemetry_tracing: FeatureFlag = Field(
        default_factory=lambda: FeatureFlag(
            enabled=True,
            category=FeatureCategory.OBSERVABILITY,
            description="Enable OpenTelemetry distributed tracing",
            dependencies={"prometheus_metrics"},
        )
    )

    prometheus_metrics: FeatureFlag = Field(
        default_factory=lambda: FeatureFlag(
            enabled=True,
            category=FeatureCategory.OBSERVABILITY,
            description="Basic metrics collection",
            environments={"development", "testing", "staging", "production"},
        )
    )

    jaeger_exporter: FeatureFlag = Field(
        default_factory=lambda: FeatureFlag(
            enabled=False,
            category=FeatureCategory.OBSERVABILITY,
            description="Enable Jaeger trace exporting",
            environments={"staging", "production"},
            metadata={"endpoint": "http://jaeger:14268/api/traces"},
        )
    )

    # Security Features
    mtls_authentication: FeatureFlag = Field(
        default_factory=lambda: FeatureFlag(
            enabled=True,
            category=FeatureCategory.SECURITY,
            description="Enable mutual TLS authentication for agents",
            environments={"staging", "production"},
        )
    )

    # Proxy Features
    envoy_proxy: FeatureFlag = Field(
        default_factory=lambda: FeatureFlag(
            enabled=True,
            category=FeatureCategory.PROXY,
            description="Enable Envoy proxy for request filtering",
        )
    )

    opa_authorization: FeatureFlag = Field(
        default_factory=lambda: FeatureFlag(
            enabled=True,
            category=FeatureCategory.PROXY,
            description="Enable OPA for authorization decisions",
            dependencies={"envoy_proxy"},
        )
    )

    # Analytics Features (Progressive Rollout)
    temporal_pattern_analysis: FeatureFlag = Field(
        default_factory=lambda: FeatureFlag(
            enabled=False,
            category=FeatureCategory.ANALYTICS,
            description="Enable temporal pattern analysis for behavior detection",
            environments={"production"},
            percentage=25.0,  # Gradual rollout
        )
    )

    def get_flag(self, flag_name: str) -> FeatureFlag:
        """Get a specific feature flag by name.

        Args:
            flag_name: Name of the feature flag

        Returns:
            FeatureFlag instance

        Raises:
            ValueError: If flag name doesn't exist
        """
        if not hasattr(self, flag_name):
            raise ValueError(f"Feature flag '{flag_name}' does not exist")
        return getattr(self, flag_name)

    def is_enabled(self, flag_name: str) -> bool:
        """Check if a feature flag is enabled for current environment.

        Args:
            flag_name: Name of the feature flag to check

        Returns:
            True if flag is enabled, False otherwise
        """
        flag = self.get_flag(flag_name)

        # Check environment compatibility
        if self.environment not in flag.environments:
            return False

        # Check basic enabled status
        if not flag.enabled:
            return False

        # Check percentage rollout
        if flag.percentage < 100.0:
            # Use cryptographically secure random for production security
            return (secrets.randbelow(10000) / 100.0) < flag.percentage

        return True

    def validate_dependencies(self) -> dict[str, set[str]]:
        """Validate that all feature flag dependencies are satisfied.

        Returns:
            Dictionary mapping flag names to their missing dependencies
        """
        violations = {}

        for field_name in self.model_fields:
            if field_name == "environment":
                continue

            flag = self.get_flag(field_name)
            if not self.is_enabled(field_name):
                continue

            missing_deps = set()
            for dep in flag.dependencies:
                if not self.is_enabled(dep):
                    missing_deps.add(dep)

            if missing_deps:
                violations[field_name] = missing_deps

        return violations


class FeatureManager:
    """Centralized feature flag manager with dependency validation."""

    def __init__(self, flags: FeatureFlags | None = None) -> None:
        """Initialize feature manager.

        Args:
            flags: Optional FeatureFlags instance. Creates default if None.

        Raises:
            ValueError: If feature flag dependencies are violated
        """
        self.flags = flags or FeatureFlags()
        self._validate_configuration()

    def _validate_configuration(self) -> None:
        """Validate feature flag configuration on startup.

        Raises:
            ValueError: If dependency violations are detected
        """
        violations = self.flags.validate_dependencies()
        if violations:
            error_msg = "Feature flag dependency violations detected:\n"
            for flag, missing_deps in violations.items():
                error_msg += f"  {flag} requires: {', '.join(missing_deps)}\n"
            raise ValueError(error_msg)

    def is_enabled(self, feature_name: str) -> bool:
        """Check if a feature is enabled.

        Args:
            feature_name: Name of the feature to check

        Returns:
            True if feature is enabled, False otherwise
        """
        return self.flags.is_enabled(feature_name)

    def get_storage_backend(self) -> str:
        """Determine which storage backend to use based on feature flags.

        Returns:
            Storage backend type ("s3" or "local")

        Raises:
            RuntimeError: If no storage backend is enabled
        """
        if self.is_enabled("s3_storage"):
            return "s3"
        if self.is_enabled("local_file_storage"):
            return "local"
        raise RuntimeError("No storage backend enabled")

    def should_enable_component(self, component_name: str, required_features: set[str]) -> bool:
        """Check if a component should be enabled based on feature requirements.

        Args:
            component_name: Name of the component (for logging)
            required_features: Set of feature flags that must be enabled

        Returns:
            True if all required features are enabled, False otherwise
        """
        return all(self.is_enabled(feature) for feature in required_features)

    def get_enabled_features_by_category(self, category: FeatureCategory) -> dict[str, FeatureFlag]:
        """Get all enabled features for a specific category.

        Args:
            category: Feature category to filter by

        Returns:
            Dictionary mapping feature names to their flags
        """
        enabled_features = {}

        for field_name in self.flags.model_fields:
            if field_name == "environment":
                continue

            flag = self.flags.get_flag(field_name)
            if flag.category == category and self.is_enabled(field_name):
                enabled_features[field_name] = flag

        return enabled_features
