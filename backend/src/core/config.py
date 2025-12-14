"""Centralized configuration management for ChronoGuard.

This module provides Pydantic-based configuration with environment variable support,
validation, and feature flag integration for all system components.
"""

from __future__ import annotations

import secrets
from functools import cached_property
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    """PostgreSQL database configuration with TimescaleDB support."""

    model_config = SettingsConfigDict(
        env_prefix="CHRONOGUARD_DB_",
        case_sensitive=False,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str = Field(default="localhost", description="Database host")
    port: int = Field(default=5432, ge=1, le=65535, description="Database port")
    user: str = Field(default="chronoguard", description="Database user")
    password: str = Field(default="chronoguard", description="Database password")
    database: str = Field(default="chronoguard", description="Database name")
    pool_size: int = Field(default=10, ge=1, le=100, description="Connection pool size")
    max_overflow: int = Field(default=20, ge=0, le=100, description="Max overflow connections")
    pool_timeout: int = Field(default=30, ge=1, le=300, description="Pool timeout in seconds")
    pool_recycle: int = Field(
        default=3600, ge=300, le=7200, description="Connection recycle time in seconds"
    )
    echo: bool = Field(default=False, description="Echo SQL statements")

    @cached_property
    def async_url(self) -> str:
        """Generate async SQLAlchemy connection URL.

        Returns:
            PostgreSQL async connection string
        """
        return f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"

    @cached_property
    def sync_url(self) -> str:
        """Generate sync SQLAlchemy connection URL (for Alembic migrations).

        Returns:
            PostgreSQL sync connection string
        """
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"


class RedisSettings(BaseSettings):
    """Redis configuration for caching and rate limiting."""

    model_config = SettingsConfigDict(env_prefix="CHRONOGUARD_REDIS_", case_sensitive=False)

    host: str = Field(default="localhost", description="Redis host")
    port: int = Field(default=6379, ge=1, le=65535, description="Redis port")
    db: int = Field(default=0, ge=0, le=15, description="Redis database number")
    password: str | None = Field(default=None, description="Redis password")
    max_connections: int = Field(
        default=50, ge=1, le=1000, description="Maximum connection pool size"
    )
    socket_timeout: int = Field(default=5, ge=1, le=60, description="Socket timeout in seconds")
    socket_keepalive: bool = Field(default=True, description="Enable TCP keepalive")
    decode_responses: bool = Field(default=True, description="Decode responses to strings")

    @cached_property
    def url(self) -> str:
        """Generate Redis connection URL.

        Returns:
            Redis connection string
        """
        if self.password:
            return f"redis://:{self.password}@{self.host}:{self.port}/{self.db}"
        return f"redis://{self.host}:{self.port}/{self.db}"


class CelerySettings(BaseSettings):
    """Celery task queue configuration."""

    model_config = SettingsConfigDict(env_prefix="CHRONOGUARD_CELERY_", case_sensitive=False)

    broker_url: str = Field(default="redis://localhost:6379/1", description="Celery broker URL")
    result_backend: str = Field(
        default="redis://localhost:6379/2", description="Result backend URL"
    )
    task_serializer: str = Field(default="json", description="Task serialization format")
    result_serializer: str = Field(default="json", description="Result serialization format")
    accept_content: list[str] = Field(
        default_factory=lambda: ["json"], description="Accepted content types"
    )
    timezone: str = Field(default="UTC", description="Celery timezone")
    enable_utc: bool = Field(default=True, description="Enable UTC timestamps")
    task_track_started: bool = Field(default=True, description="Track task start time")
    task_time_limit: int = Field(
        default=300, ge=10, le=3600, description="Hard task time limit in seconds"
    )
    task_soft_time_limit: int = Field(
        default=270, ge=10, le=3600, description="Soft task time limit in seconds"
    )
    worker_prefetch_multiplier: int = Field(
        default=4, ge=1, le=10, description="Worker prefetch multiplier"
    )
    worker_max_tasks_per_child: int = Field(
        default=1000, ge=100, le=10000, description="Max tasks per worker before restart"
    )


class SecuritySettings(BaseSettings):
    """Security and authentication configuration."""

    model_config = SettingsConfigDict(
        env_prefix="CHRONOGUARD_SECURITY_",
        case_sensitive=False,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    secret_key: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        description="Secret key for JWT signing",
    )
    algorithm: str = Field(default="HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(
        default=30, ge=5, le=1440, description="Access token expiration in minutes"
    )
    refresh_token_expire_days: int = Field(
        default=7, ge=1, le=30, description="Refresh token expiration in days"
    )
    password_min_length: int = Field(
        default=12, ge=8, le=128, description="Minimum password length"
    )
    password_require_uppercase: bool = Field(
        default=True, description="Require uppercase in passwords"
    )
    password_require_lowercase: bool = Field(
        default=True, description="Require lowercase in passwords"
    )
    password_require_digits: bool = Field(default=True, description="Require digits in passwords")
    password_require_special: bool = Field(
        default=True, description="Require special characters in passwords"
    )
    bcrypt_rounds: int = Field(default=12, ge=10, le=16, description="Bcrypt hash rounds")

    # mTLS settings
    mtls_enabled: bool = Field(default=False, description="Enable mTLS authentication")
    ca_cert_path: Path | None = Field(default=None, description="CA certificate path")
    server_cert_path: Path | None = Field(default=None, description="Server certificate path")
    server_key_path: Path | None = Field(default=None, description="Server private key path")
    verify_client_cert: bool = Field(default=True, description="Verify client certificates")
    demo_mode_enabled: bool = Field(
        default=False,
        description="Enable demo authentication mode using shared password (development only)",
    )
    demo_admin_password: str | None = Field(
        default=None,
        description="Demo administrator password for development login",
    )
    demo_tenant_id: UUID = Field(
        default=UUID("550e8400-e29b-41d4-a716-446655440001"),
        description="Default tenant ID for demo authentication",
    )
    demo_user_id: UUID = Field(
        default=UUID("550e8400-e29b-41d4-a716-446655440002"),
        description="Default user ID for demo authentication",
    )

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """Validate secret key strength.

        Args:
            v: Secret key value

        Returns:
            Validated secret key

        Raises:
            ValueError: If secret key is too weak
        """
        if len(v) < 32:
            raise ValueError("Secret key must be at least 32 characters")
        return v

    session_cookie_name: str = Field(
        default="chronoguard_session",
        description="Name of the secure session cookie used for JWT tokens",
    )
    session_cookie_secure: bool = Field(
        default=True,
        description="Whether to mark the session cookie as Secure (HTTPS only)",
    )
    session_cookie_same_site: Literal["lax", "strict", "none"] = Field(
        default="lax",
        description="SameSite attribute for the session cookie",
    )
    session_cookie_domain: str | None = Field(
        default=None,
        description="Optional cookie domain override",
    )
    session_cookie_path: str = Field(
        default="/",
        description="Cookie path scope",
    )

    @field_validator("demo_admin_password")
    @classmethod
    def validate_demo_password(cls, v: str | None) -> str | None:
        """Ensure demo password is strong when provided."""

        if v is None:
            return None

        password = v.strip()
        if not password:
            raise ValueError("Demo admin password cannot be empty")
        if len(password) < 16:
            raise ValueError("Demo admin password must be at least 16 characters")
        return password

    @model_validator(mode="after")
    def validate_demo_mode_configuration(self) -> SecuritySettings:
        """Ensure demo mode has explicit credentials."""

        if self.demo_mode_enabled and not self.demo_admin_password:
            raise ValueError(
                "Demo mode requires CHRONOGUARD_SECURITY_DEMO_ADMIN_PASSWORD to be set"
            )
        return self

    @model_validator(mode="after")
    def validate_cookie_security(self) -> SecuritySettings:
        """Ensure cookie settings are safe."""

        if self.session_cookie_same_site == "none" and not self.session_cookie_secure:
            raise ValueError("Secure cookies are required when SameSite=None")
        return self


class APISettings(BaseSettings):
    """FastAPI application configuration."""

    model_config = SettingsConfigDict(env_prefix="CHRONOGUARD_API_", case_sensitive=False)

    title: str = Field(default="ChronoGuard API", description="API title")
    description: str = Field(
        default="Agent Identity & Compliance Platform for AI agents",
        description="API description",
    )
    version: str = Field(default="1.0.0", description="API version")
    host: str = Field(
        default="127.0.0.1",
        description="API host (use 0.0.0.0 for all interfaces in production with firewall)",
    )
    port: int = Field(default=8000, ge=1, le=65535, description="API port")
    workers: int = Field(default=4, ge=1, le=16, description="Uvicorn workers")
    reload: bool = Field(default=False, description="Enable auto-reload in development")
    debug: bool = Field(default=False, description="Enable debug mode")
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000"],
        description="Allowed CORS origins",
    )
    cors_credentials: bool = Field(default=True, description="Allow CORS credentials")
    cors_methods: list[str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "PATCH"],
        description="Allowed CORS methods",
    )
    cors_headers: list[str] = Field(
        default_factory=lambda: ["*"], description="Allowed CORS headers"
    )
    rate_limit_requests: int = Field(
        default=100, ge=1, le=10000, description="Rate limit requests per window"
    )
    rate_limit_window: int = Field(
        default=60, ge=1, le=3600, description="Rate limit window in seconds"
    )


class ObservabilitySettings(BaseSettings):
    """Observability configuration for logging, metrics, and tracing."""

    model_config = SettingsConfigDict(env_prefix="CHRONOGUARD_OBSERVABILITY_", case_sensitive=False)

    # Logging
    log_level: str = Field(default="INFO", description="Logging level")
    log_format: str = Field(default="json", description="Log format (json or text)")
    log_file_path: Path | None = Field(default=None, description="Log file path")
    log_rotation: str = Field(default="100 MB", description="Log rotation size")
    log_retention: str = Field(default="30 days", description="Log retention period")

    # Metrics
    metrics_enabled: bool = Field(default=True, description="Enable Prometheus metrics")
    metrics_port: int = Field(default=9090, ge=1, le=65535, description="Metrics port")

    # Tracing
    tracing_enabled: bool = Field(default=True, description="Enable OpenTelemetry tracing")
    tracing_endpoint: str | None = Field(default=None, description="OTLP exporter endpoint")
    tracing_sample_rate: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Trace sampling rate"
    )
    service_name: str = Field(default="chronoguard", description="Service name for tracing")

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level.

        Args:
            v: Log level value

        Returns:
            Validated log level

        Raises:
            ValueError: If log level is invalid
        """
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of {valid_levels}")
        return v.upper()


class ProxySettings(BaseSettings):
    """Envoy proxy and OPA configuration."""

    model_config = SettingsConfigDict(env_prefix="CHRONOGUARD_PROXY_", case_sensitive=False)

    # Envoy settings
    envoy_xds_port: int = Field(
        default=18000, ge=1, le=65535, description="Envoy xDS control plane port"
    )
    envoy_admin_port: int = Field(default=9901, ge=1, le=65535, description="Envoy admin port")
    envoy_proxy_port: int = Field(default=8443, ge=1, le=65535, description="Envoy proxy port")
    envoy_cluster_name: str = Field(default="chronoguard_cluster", description="Envoy cluster name")

    # OPA settings
    opa_url: str = Field(default="http://localhost:8181", description="OPA server URL")
    opa_policy_path: str = Field(
        default="/v1/data/chronoguard/allow", description="OPA policy decision path"
    )
    opa_bundle_path: Path = Field(
        default=Path("/var/lib/chronoguard/opa/bundles"), description="OPA bundle storage path"
    )
    opa_decision_logging: bool = Field(default=True, description="Enable OPA decision logging")
    opa_timeout: int = Field(default=5, ge=1, le=30, description="OPA request timeout in seconds")


class StorageSettings(BaseSettings):
    """Storage configuration for audit logs and exports."""

    model_config = SettingsConfigDict(env_prefix="CHRONOGUARD_STORAGE_", case_sensitive=False)

    backend: str = Field(default="local", description="Storage backend (local or s3)")
    local_path: Path = Field(
        default=Path("/var/lib/chronoguard/storage"), description="Local storage path"
    )

    # S3 settings
    s3_bucket: str | None = Field(default=None, description="S3 bucket name")
    s3_region: str = Field(default="us-east-1", description="S3 region")
    s3_access_key_id: str | None = Field(default=None, description="S3 access key ID")
    s3_secret_access_key: str | None = Field(default=None, description="S3 secret access key")
    s3_endpoint_url: str | None = Field(default=None, description="S3 endpoint URL (for MinIO)")

    @field_validator("backend")
    @classmethod
    def validate_backend(cls, v: str) -> str:
        """Validate storage backend.

        Args:
            v: Backend value

        Returns:
            Validated backend

        Raises:
            ValueError: If backend is invalid
        """
        valid_backends = {"local", "s3"}
        if v.lower() not in valid_backends:
            raise ValueError(f"Storage backend must be one of {valid_backends}")
        return v.lower()


class Settings(BaseSettings):
    """Main ChronoGuard configuration combining all subsystems."""

    model_config = SettingsConfigDict(
        env_prefix="CHRONOGUARD_",
        case_sensitive=False,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Environment
    environment: str = Field(
        default="development",
        description="Application environment (development, staging, production)",
    )
    debug: bool = Field(default=False, description="Global debug mode")

    # Component settings
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    celery: CelerySettings = Field(default_factory=CelerySettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    api: APISettings = Field(default_factory=APISettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)
    proxy: ProxySettings = Field(default_factory=ProxySettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        """Validate environment value.

        Args:
            v: Environment value

        Returns:
            Validated environment

        Raises:
            ValueError: If environment is invalid
        """
        valid_envs = {"development", "testing", "staging", "production"}
        if v.lower() not in valid_envs:
            raise ValueError(f"Environment must be one of {valid_envs}")
        return v.lower()

    def is_production(self) -> bool:
        """Check if running in production environment.

        Returns:
            True if production, False otherwise
        """
        return self.environment == "production"

    def is_development(self) -> bool:
        """Check if running in development environment.

        Returns:
            True if development, False otherwise
        """
        return self.environment == "development"

    def is_testing(self) -> bool:
        """Check if running in testing environment.

        Returns:
            True if testing, False otherwise
        """
        return self.environment == "testing"

    def get_component_config(self, component: str) -> BaseSettings:
        """Get configuration for a specific component.

        Args:
            component: Component name (database, redis, celery, etc.)

        Returns:
            Component settings instance

        Raises:
            ValueError: If component doesn't exist
        """
        if not hasattr(self, component):
            raise ValueError(f"Component '{component}' configuration not found")
        return getattr(self, component)

    def validate_required_settings(self) -> dict[str, list[str]]:
        """Validate that required settings are configured for current environment.

        Returns:
            Dictionary of validation issues by component

        Raises:
            ValueError: If critical settings are missing in production
        """
        issues: dict[str, list[str]] = {}

        # Production validations
        if self.is_production():
            if self.debug:
                issues.setdefault("general", []).append(
                    "Debug mode should be disabled in production"
                )

            if self.security.secret_key == secrets.token_urlsafe(32):
                issues.setdefault("security", []).append(
                    "Secret key must be explicitly set in production"
                )

            if not self.security.mtls_enabled:
                issues.setdefault("security", []).append("mTLS should be enabled in production")

            if self.api.debug:
                issues.setdefault("api", []).append(
                    "API debug mode should be disabled in production"
                )

            if self.observability.log_level == "DEBUG":
                issues.setdefault("observability", []).append(
                    "Debug logging should be disabled in production"
                )

        return issues


# Global settings instance
_settings: Settings | None = None


def get_settings() -> Settings:
    """Get the global settings instance.

    Returns:
        Global Settings instance
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def configure_settings(settings: Settings) -> None:
    """Configure the global settings instance.

    Args:
        settings: Settings instance to use globally
    """
    global _settings
    _settings = settings


def reload_settings() -> Settings:
    """Reload settings from environment variables.

    Returns:
        Reloaded Settings instance
    """
    global _settings
    _settings = Settings()
    return _settings
