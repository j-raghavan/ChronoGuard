"""Tests for authentication routes."""

from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from presentation.api.routes.auth import router


class TestAuthLogin:
    """Tests for login endpoint."""

    @pytest.fixture
    def app(self) -> FastAPI:
        """Create FastAPI app with auth routes."""
        app = FastAPI()
        app.include_router(router)
        return app

    @pytest.fixture
    def client(self, app: FastAPI) -> TestClient:
        """Create test client."""
        return TestClient(app)

    def test_login_when_demo_mode_disabled(self, client: TestClient) -> None:
        """Test login fails when demo mode is disabled."""
        from core.config import SecuritySettings, Settings, get_settings

        # Mock settings with demo_mode_enabled=False
        with patch("presentation.api.routes.auth.get_settings") as mock_get_settings:
            mock_security = SecuritySettings(demo_mode_enabled=False)
            mock_settings = Settings()
            mock_settings.security = mock_security
            mock_get_settings.return_value = mock_settings

            response = client.post(
                "/api/v1/auth/login",
                json={"password": "any-password"},
            )

            # Should return 503 when demo mode is disabled
            assert response.status_code == 503
            assert "Demo authentication is disabled" in response.json()["detail"]
