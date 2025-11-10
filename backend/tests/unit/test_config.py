"""Unit tests for core configuration module."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import pytest
from pydantic import ValidationError

from core.config import (
    APISettings,
    CelerySettings,
    DatabaseSettings,
    ObservabilitySettings,
    ProxySettings,
    RedisSettings,
    SecuritySettings,
    Settings,
    StorageSettings,
    configure_settings,
    get_settings,
    reload_settings,
)


class TestDatabaseSettings:
    """Tests for DatabaseSettings configuration."""

    def test_default_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that default database settings are correctly initialized."""
        # Clear any environment variables that could affect defaults
        for key in [
            "CHRONOGUARD_DB_HOST",
            "CHRONOGUARD_DB_PORT",
            "CHRONOGUARD_DB_USER",
            "CHRONOGUARD_DB_PASSWORD",
            "CHRONOGUARD_DB_DATABASE",
        ]:
            monkeypatch.delenv(key, raising=False)

        # Prevent loading from .env file
        monkeypatch.setenv("CHRONOGUARD_DB_HOST", "localhost")
        monkeypatch.setenv("CHRONOGUARD_DB_PORT", "5432")
        monkeypatch.setenv("CHRONOGUARD_DB_USER", "chronoguard")
        monkeypatch.setenv("CHRONOGUARD_DB_PASSWORD", "chronoguard")
        monkeypatch.setenv("CHRONOGUARD_DB_DATABASE", "chronoguard")

        db = DatabaseSettings()

        assert db.host == "localhost"
        assert db.port == 5432
        assert db.user == "chronoguard"
        assert db.database == "chronoguard"
        assert db.pool_size == 10
        assert db.max_overflow == 20
        assert db.pool_timeout == 30
        assert db.pool_recycle == 3600
        assert db.echo is False

    def test_async_url_generation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test async PostgreSQL connection URL generation."""
        # Override environment to ensure consistent defaults
        monkeypatch.setenv("CHRONOGUARD_DB_HOST", "localhost")
        monkeypatch.setenv("CHRONOGUARD_DB_PORT", "5432")

        db = DatabaseSettings(user="testuser", password="testpass", database="testdb")

        expected_url = "postgresql+asyncpg://testuser:testpass@localhost:5432/testdb"
        assert db.async_url == expected_url

    def test_sync_url_generation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test sync PostgreSQL connection URL generation."""
        # Override environment to ensure consistent defaults
        monkeypatch.setenv("CHRONOGUARD_DB_HOST", "localhost")
        monkeypatch.setenv("CHRONOGUARD_DB_PORT", "5432")

        db = DatabaseSettings(user="testuser", password="testpass", database="testdb")

        expected_url = "postgresql://testuser:testpass@localhost:5432/testdb"
        assert db.sync_url == expected_url

    def test_custom_host_and_port(self) -> None:
        """Test URL generation with custom host and port."""
        db = DatabaseSettings(
            host="db.example.com", port=5433, user="user", password="pass", database="mydb"
        )

        assert "db.example.com:5433" in db.async_url
        assert "db.example.com:5433" in db.sync_url

    def test_pool_size_validation(self) -> None:
        """Test that pool size is validated within allowed range."""
        # Valid pool sizes
        DatabaseSettings(pool_size=1)
        DatabaseSettings(pool_size=100)

        # Invalid pool sizes
        with pytest.raises(ValidationError):
            DatabaseSettings(pool_size=0)

        with pytest.raises(ValidationError):
            DatabaseSettings(pool_size=101)

    def test_port_validation(self) -> None:
        """Test that port is validated within allowed range."""
        # Valid ports
        DatabaseSettings(port=1)
        DatabaseSettings(port=65535)

        # Invalid ports
        with pytest.raises(ValidationError):
            DatabaseSettings(port=0)

        with pytest.raises(ValidationError):
            DatabaseSettings(port=65536)


class TestRedisSettings:
    """Tests for RedisSettings configuration."""

    def test_default_values(self) -> None:
        """Test that default Redis settings are correctly initialized."""
        redis = RedisSettings()

        assert redis.host == "localhost"
        assert redis.port == 6379
        assert redis.db == 0
        assert redis.password is None
        assert redis.max_connections == 50
        assert redis.socket_timeout == 5
        assert redis.socket_keepalive is True
        assert redis.decode_responses is True

    def test_url_generation_without_password(self) -> None:
        """Test Redis URL generation without password."""
        redis = RedisSettings(host="redis.example.com", port=6380, db=1)

        expected_url = "redis://redis.example.com:6380/1"
        assert redis.url == expected_url

    def test_url_generation_with_password(self) -> None:
        """Test Redis URL generation with password."""
        redis = RedisSettings(password="securepass", db=2)

        expected_url = "redis://:securepass@localhost:6379/2"
        assert redis.url == expected_url

    def test_db_number_validation(self) -> None:
        """Test that database number is validated within allowed range."""
        # Valid DB numbers
        RedisSettings(db=0)
        RedisSettings(db=15)

        # Invalid DB numbers
        with pytest.raises(ValidationError):
            RedisSettings(db=-1)

        with pytest.raises(ValidationError):
            RedisSettings(db=16)


class TestCelerySettings:
    """Tests for CelerySettings configuration."""

    def test_default_values(self) -> None:
        """Test that default Celery settings are correctly initialized."""
        celery = CelerySettings()

        assert celery.broker_url == "redis://localhost:6379/1"
        assert celery.result_backend == "redis://localhost:6379/2"
        assert celery.task_serializer == "json"
        assert celery.result_serializer == "json"
        assert celery.accept_content == ["json"]
        assert celery.timezone == "UTC"
        assert celery.enable_utc is True
        assert celery.task_track_started is True
        assert celery.task_time_limit == 300
        assert celery.task_soft_time_limit == 270

    def test_custom_broker_and_backend(self) -> None:
        """Test Celery with custom broker and backend URLs."""
        celery = CelerySettings(
            broker_url="redis://broker:6379/0", result_backend="redis://backend:6379/1"
        )

        assert celery.broker_url == "redis://broker:6379/0"
        assert celery.result_backend == "redis://backend:6379/1"

    def test_time_limit_validation(self) -> None:
        """Test that time limits are validated within allowed range."""
        # Valid time limits
        CelerySettings(task_time_limit=10, task_soft_time_limit=10)
        CelerySettings(task_time_limit=3600, task_soft_time_limit=3600)

        # Invalid time limits
        with pytest.raises(ValidationError):
            CelerySettings(task_time_limit=5)

        with pytest.raises(ValidationError):
            CelerySettings(task_time_limit=3601)


class TestSecuritySettings:
    """Tests for SecuritySettings configuration."""

    def test_default_values(self) -> None:
        """Test that default security settings are correctly initialized."""
        security = SecuritySettings()

        assert len(security.secret_key) >= 32
        assert security.algorithm == "HS256"
        assert security.access_token_expire_minutes == 30
        assert security.refresh_token_expire_days == 7
        assert security.password_min_length == 12
        assert security.password_require_uppercase is True
        assert security.password_require_lowercase is True
        assert security.password_require_digits is True
        assert security.password_require_special is True
        assert security.bcrypt_rounds == 12
        assert security.mtls_enabled is False
        assert security.verify_client_cert is True

    def test_secret_key_validation_minimum_length(self) -> None:
        """Test that secret key must meet minimum length requirement."""
        # Valid secret key
        SecuritySettings(secret_key="a" * 32)

        # Invalid secret key (too short)
        with pytest.raises(ValidationError, match="at least 32 characters"):
            SecuritySettings(secret_key="short")

    def test_mtls_configuration(self) -> None:
        """Test mTLS configuration with certificate paths."""
        security = SecuritySettings(
            mtls_enabled=True,
            ca_cert_path=Path("/path/to/ca.crt"),
            server_cert_path=Path("/path/to/server.crt"),
            server_key_path=Path("/path/to/server.key"),
        )

        assert security.mtls_enabled is True
        assert security.ca_cert_path == Path("/path/to/ca.crt")
        assert security.server_cert_path == Path("/path/to/server.crt")
        assert security.server_key_path == Path("/path/to/server.key")

    def test_token_expiration_validation(self) -> None:
        """Test that token expiration values are validated."""
        # Valid expiration times
        SecuritySettings(access_token_expire_minutes=5, refresh_token_expire_days=1)
        SecuritySettings(access_token_expire_minutes=1440, refresh_token_expire_days=30)

        # Invalid expiration times
        with pytest.raises(ValidationError):
            SecuritySettings(access_token_expire_minutes=4)

        with pytest.raises(ValidationError):
            SecuritySettings(access_token_expire_minutes=1441)

        with pytest.raises(ValidationError):
            SecuritySettings(refresh_token_expire_days=0)

        with pytest.raises(ValidationError):
            SecuritySettings(refresh_token_expire_days=31)


class TestAPISettings:
    """Tests for APISettings configuration."""

    def test_default_values(self) -> None:
        """Test that default API settings are correctly initialized."""
        api = APISettings()

        assert api.title == "ChronoGuard API"
        assert api.version == "1.0.0"
        assert api.host == "127.0.0.1"  # Secure default - localhost only
        assert api.port == 8000
        assert api.workers == 4
        assert api.reload is False
        assert api.debug is False
        assert "http://localhost:3000" in api.cors_origins
        assert api.cors_credentials is True
        assert "GET" in api.cors_methods
        assert "POST" in api.cors_methods
        assert api.rate_limit_requests == 100
        assert api.rate_limit_window == 60

    def test_custom_cors_configuration(self) -> None:
        """Test custom CORS configuration."""
        api = APISettings(
            cors_origins=["https://example.com", "https://app.example.com"],
            cors_methods=["GET", "POST"],
            cors_headers=["Content-Type", "Authorization"],
        )

        assert "https://example.com" in api.cors_origins
        assert "https://app.example.com" in api.cors_origins
        assert api.cors_methods == ["GET", "POST"]
        assert "Content-Type" in api.cors_headers

    def test_port_validation(self) -> None:
        """Test that API port is validated within allowed range."""
        # Valid ports
        APISettings(port=1)
        APISettings(port=65535)

        # Invalid ports
        with pytest.raises(ValidationError):
            APISettings(port=0)

        with pytest.raises(ValidationError):
            APISettings(port=65536)


class TestObservabilitySettings:
    """Tests for ObservabilitySettings configuration."""

    def test_default_values(self) -> None:
        """Test that default observability settings are correctly initialized."""
        obs = ObservabilitySettings()

        assert obs.log_level == "INFO"
        assert obs.log_format == "json"
        assert obs.log_file_path is None
        assert obs.log_rotation == "100 MB"
        assert obs.log_retention == "30 days"
        assert obs.metrics_enabled is True
        assert obs.metrics_port == 9090
        assert obs.tracing_enabled is True
        assert obs.tracing_endpoint is None
        assert obs.tracing_sample_rate == 1.0
        assert obs.service_name == "chronoguard"

    def test_log_level_validation(self) -> None:
        """Test that log level is validated against allowed values."""
        # Valid log levels
        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            obs = ObservabilitySettings(log_level=level)
            assert obs.log_level == level.upper()

        # Valid lowercase (auto-converted to uppercase)
        obs = ObservabilitySettings(log_level="info")
        assert obs.log_level == "INFO"

        # Invalid log level
        with pytest.raises(ValidationError, match="must be one of"):
            ObservabilitySettings(log_level="INVALID")

    def test_tracing_configuration(self) -> None:
        """Test tracing configuration with endpoint."""
        obs = ObservabilitySettings(
            tracing_enabled=True,
            tracing_endpoint="http://jaeger:14268/api/traces",
            tracing_sample_rate=0.5,
        )

        assert obs.tracing_enabled is True
        assert obs.tracing_endpoint == "http://jaeger:14268/api/traces"
        assert obs.tracing_sample_rate == 0.5

    def test_sample_rate_validation(self) -> None:
        """Test that sample rate is validated within 0.0-1.0 range."""
        # Valid sample rates
        ObservabilitySettings(tracing_sample_rate=0.0)
        ObservabilitySettings(tracing_sample_rate=0.5)
        ObservabilitySettings(tracing_sample_rate=1.0)

        # Invalid sample rates
        with pytest.raises(ValidationError):
            ObservabilitySettings(tracing_sample_rate=-0.1)

        with pytest.raises(ValidationError):
            ObservabilitySettings(tracing_sample_rate=1.1)


class TestProxySettings:
    """Tests for ProxySettings configuration."""

    def test_default_values(self) -> None:
        """Test that default proxy settings are correctly initialized."""
        proxy = ProxySettings()

        assert proxy.envoy_xds_port == 18000
        assert proxy.envoy_admin_port == 9901
        assert proxy.envoy_proxy_port == 8443
        assert proxy.envoy_cluster_name == "chronoguard_cluster"
        assert proxy.opa_url == "http://localhost:8181"
        assert proxy.opa_policy_path == "/v1/data/chronoguard/allow"
        assert proxy.opa_bundle_path == Path("/var/lib/chronoguard/opa/bundles")
        assert proxy.opa_decision_logging is True
        assert proxy.opa_timeout == 5

    def test_custom_opa_configuration(self) -> None:
        """Test custom OPA configuration."""
        proxy = ProxySettings(
            opa_url="http://opa.example.com:8181",
            opa_policy_path="/v1/data/custom/allow",
            opa_bundle_path=Path("/custom/bundles"),
            opa_timeout=10,
        )

        assert proxy.opa_url == "http://opa.example.com:8181"
        assert proxy.opa_policy_path == "/v1/data/custom/allow"
        assert proxy.opa_bundle_path == Path("/custom/bundles")
        assert proxy.opa_timeout == 10

    def test_port_validation(self) -> None:
        """Test that ports are validated within allowed range."""
        # Valid ports
        ProxySettings(envoy_xds_port=1, envoy_admin_port=1, envoy_proxy_port=1)
        ProxySettings(envoy_xds_port=65535, envoy_admin_port=65535, envoy_proxy_port=65535)

        # Invalid ports
        with pytest.raises(ValidationError):
            ProxySettings(envoy_xds_port=0)

        with pytest.raises(ValidationError):
            ProxySettings(envoy_xds_port=65536)


class TestStorageSettings:
    """Tests for StorageSettings configuration."""

    def test_default_values(self) -> None:
        """Test that default storage settings are correctly initialized."""
        storage = StorageSettings()

        assert storage.backend == "local"
        assert storage.local_path == Path("/var/lib/chronoguard/storage")
        assert storage.s3_bucket is None
        assert storage.s3_region == "us-east-1"
        assert storage.s3_access_key_id is None
        assert storage.s3_secret_access_key is None

    def test_s3_configuration(self) -> None:
        """Test S3 storage configuration."""
        storage = StorageSettings(
            backend="s3",
            s3_bucket="chronoguard-audit-logs",
            s3_region="us-west-2",
            s3_access_key_id="AKIAIOSFODNN7EXAMPLE",
            s3_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )

        assert storage.backend == "s3"
        assert storage.s3_bucket == "chronoguard-audit-logs"
        assert storage.s3_region == "us-west-2"
        assert storage.s3_access_key_id == "AKIAIOSFODNN7EXAMPLE"

    def test_backend_validation(self) -> None:
        """Test that storage backend is validated against allowed values."""
        # Valid backends
        StorageSettings(backend="local")
        StorageSettings(backend="s3")
        StorageSettings(backend="LOCAL")  # Should be lowercased
        StorageSettings(backend="S3")  # Should be lowercased

        # Invalid backend
        with pytest.raises(ValidationError, match="must be one of"):
            StorageSettings(backend="azure")


class TestSettings:
    """Tests for main Settings configuration."""

    def test_default_values(self) -> None:
        """Test that default main settings are correctly initialized."""
        settings = Settings()

        assert settings.environment == "development"
        assert settings.debug is False
        assert isinstance(settings.database, DatabaseSettings)
        assert isinstance(settings.redis, RedisSettings)
        assert isinstance(settings.celery, CelerySettings)
        assert isinstance(settings.security, SecuritySettings)
        assert isinstance(settings.api, APISettings)
        assert isinstance(settings.observability, ObservabilitySettings)
        assert isinstance(settings.proxy, ProxySettings)
        assert isinstance(settings.storage, StorageSettings)

    def test_environment_validation(self) -> None:
        """Test that environment is validated against allowed values."""
        # Valid environments
        for env in ["development", "testing", "staging", "production"]:
            settings = Settings(environment=env)
            assert settings.environment == env.lower()

        # Valid uppercase (auto-converted to lowercase)
        settings = Settings(environment="PRODUCTION")
        assert settings.environment == "production"

        # Invalid environment
        with pytest.raises(ValidationError, match="must be one of"):
            Settings(environment="invalid")

    def test_is_production(self) -> None:
        """Test production environment detection."""
        settings = Settings(environment="production")
        assert settings.is_production() is True

        settings = Settings(environment="development")
        assert settings.is_production() is False

    def test_is_development(self) -> None:
        """Test development environment detection."""
        settings = Settings(environment="development")
        assert settings.is_development() is True

        settings = Settings(environment="production")
        assert settings.is_development() is False

    def test_is_testing(self) -> None:
        """Test testing environment detection."""
        settings = Settings(environment="testing")
        assert settings.is_testing() is True

        settings = Settings(environment="production")
        assert settings.is_testing() is False

    def test_get_component_config(self) -> None:
        """Test getting component configuration by name."""
        settings = Settings()

        db_config = settings.get_component_config("database")
        assert isinstance(db_config, DatabaseSettings)

        redis_config = settings.get_component_config("redis")
        assert isinstance(redis_config, RedisSettings)

        # Invalid component
        with pytest.raises(ValueError, match="configuration not found"):
            settings.get_component_config("invalid_component")

    def test_validate_required_settings_production(self) -> None:
        """Test validation of required settings in production environment."""
        settings = Settings(
            environment="production",
            debug=True,  # Should trigger warning
        )

        issues = settings.validate_required_settings()

        # Should have issues for debug mode and secret key
        assert "general" in issues
        assert "security" in issues
        assert any("Debug mode" in msg for msg in issues["general"])
        assert any("mTLS" in msg for msg in issues["security"])

    def test_validate_required_settings_development(self) -> None:
        """Test that validation is lenient in development environment."""
        settings = Settings(environment="development", debug=True)

        issues = settings.validate_required_settings()

        # Development should have fewer strict requirements
        assert len(issues) == 0 or "general" not in issues

    def test_nested_component_configuration(self) -> None:
        """Test that nested component configurations are properly initialized."""
        settings = Settings()

        # Verify database nested config
        assert settings.database.pool_size == 10
        assert settings.database.async_url.startswith("postgresql+asyncpg://")

        # Verify Redis nested config
        assert settings.redis.max_connections == 50
        assert settings.redis.url.startswith("redis://")

        # Verify security nested config
        assert len(settings.security.secret_key) >= 32


class TestSettingsGlobalFunctions:
    """Tests for global settings management functions."""

    def test_get_settings_singleton(self) -> None:
        """Test that get_settings returns same instance."""
        settings1 = get_settings()
        settings2 = get_settings()

        assert settings1 is settings2

    def test_configure_settings(self) -> None:
        """Test configuring custom settings instance."""
        custom_settings = Settings(environment="testing")
        configure_settings(custom_settings)

        retrieved_settings = get_settings()
        assert retrieved_settings is custom_settings
        assert retrieved_settings.environment == "testing"

    def test_reload_settings(self) -> None:
        """Test reloading settings from environment."""
        original_settings = get_settings()

        # Reload settings (creates new instance)
        new_settings = reload_settings()

        # Should be a different instance
        assert new_settings is not original_settings

        # But get_settings() should now return the new instance
        current_settings = get_settings()
        assert current_settings is new_settings

    def test_environment_variable_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that environment variables override default values."""
        # Set environment variable
        monkeypatch.setenv("CHRONOGUARD_ENVIRONMENT", "production")
        monkeypatch.setenv("CHRONOGUARD_DB_HOST", "production-db.example.com")
        monkeypatch.setenv("CHRONOGUARD_DB_PORT", "5433")

        # Reload settings to pick up environment changes
        settings = reload_settings()

        assert settings.environment == "production"
        assert settings.database.host == "production-db.example.com"
        assert settings.database.port == 5433
