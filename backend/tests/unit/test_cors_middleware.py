"""Unit tests for presentation.api.middleware.cors module.

This module provides comprehensive tests for CORS middleware including
preflight requests, origin validation, headers configuration, and credentials support.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from core.config import APISettings
from fastapi import FastAPI, Request
from presentation.api.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse
from starlette.testclient import TestClient


class TestCORSMiddlewareInitialization:
    """Tests for CORSMiddleware initialization."""

    def test_init_with_defaults(self) -> None:
        """Test middleware initialization with default settings."""
        app = FastAPI()
        middleware = CORSMiddleware(app)

        assert middleware.allow_origins is not None
        assert middleware.allow_methods is not None
        assert middleware.allow_headers is not None
        assert middleware.allow_credentials is not None
        assert middleware.max_age == 600

    def test_init_with_api_settings(self) -> None:
        """Test middleware initialization with APISettings."""
        app = FastAPI()
        settings = APISettings(
            cors_origins=["https://example.com"],
            cors_methods=["GET", "POST"],
            cors_headers=["Content-Type"],
            cors_credentials=True,
        )

        middleware = CORSMiddleware(app, api_settings=settings)

        assert middleware.allow_origins == ["https://example.com"]
        assert middleware.allow_methods == ["GET", "POST"]
        assert middleware.allow_headers == ["Content-Type"]
        assert middleware.allow_credentials is True

    def test_init_with_explicit_parameters(self) -> None:
        """Test middleware initialization with explicit parameters."""
        app = FastAPI()
        middleware = CORSMiddleware(
            app,
            allow_origins=["https://custom.com"],
            allow_methods=["GET"],
            allow_headers=["Authorization"],
            allow_credentials=False,
            max_age=3600,
        )

        assert middleware.allow_origins == ["https://custom.com"]
        assert middleware.allow_methods == ["GET"]
        assert middleware.allow_headers == ["Authorization"]
        assert middleware.allow_credentials is False
        assert middleware.max_age == 3600

    def test_init_explicit_overrides_settings(self) -> None:
        """Test that explicit parameters override api_settings."""
        app = FastAPI()
        settings = APISettings(cors_origins=["https://settings.com"])

        middleware = CORSMiddleware(
            app, api_settings=settings, allow_origins=["https://override.com"]
        )

        assert middleware.allow_origins == ["https://override.com"]

    def test_init_with_wildcard_origins(self) -> None:
        """Test middleware initialization with wildcard origins."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_origins=["*"])

        assert middleware.allow_all_origins is True

    def test_init_with_wildcard_headers(self) -> None:
        """Test middleware initialization with wildcard headers."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_headers=["*"])

        assert middleware.allow_all_headers is True

    def test_init_with_expose_headers(self) -> None:
        """Test middleware initialization with expose headers."""
        app = FastAPI()
        middleware = CORSMiddleware(app, expose_headers=["X-Custom-Header", "X-Request-ID"])

        assert middleware.expose_headers == ["X-Custom-Header", "X-Request-ID"]

    def test_middleware_is_base_http_middleware(self) -> None:
        """Test that CORSMiddleware extends BaseHTTPMiddleware."""
        app = FastAPI()
        middleware = CORSMiddleware(app)

        assert isinstance(middleware, BaseHTTPMiddleware)


class TestIsOriginAllowed:
    """Tests for _is_origin_allowed method."""

    def test_allow_all_origins(self) -> None:
        """Test origin validation with wildcard."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_origins=["*"])

        assert middleware._is_origin_allowed("https://example.com") is True
        assert middleware._is_origin_allowed("https://any-domain.com") is True

    def test_exact_origin_match(self) -> None:
        """Test exact origin matching."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_origins=["https://example.com"])

        assert middleware._is_origin_allowed("https://example.com") is True
        assert middleware._is_origin_allowed("https://other.com") is False

    def test_multiple_allowed_origins(self) -> None:
        """Test multiple allowed origins."""
        app = FastAPI()
        middleware = CORSMiddleware(
            app, allow_origins=["https://example.com", "https://app.example.com"]
        )

        assert middleware._is_origin_allowed("https://example.com") is True
        assert middleware._is_origin_allowed("https://app.example.com") is True
        assert middleware._is_origin_allowed("https://other.com") is False

    def test_wildcard_subdomain_pattern(self) -> None:
        """Test wildcard subdomain pattern matching."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_origins=["https://*.example.com"])

        assert middleware._is_origin_allowed("https://app.example.com") is True
        assert middleware._is_origin_allowed("https://api.example.com") is True
        assert middleware._is_origin_allowed("https://example.com") is False
        assert middleware._is_origin_allowed("https://other.com") is False

    def test_case_sensitive_origin_matching(self) -> None:
        """Test that origin matching is case-sensitive."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_origins=["https://Example.com"])

        assert middleware._is_origin_allowed("https://Example.com") is True
        assert middleware._is_origin_allowed("https://example.com") is False


class TestMatchWildcardOrigin:
    """Tests for _match_wildcard_origin method."""

    def test_match_wildcard_subdomain(self) -> None:
        """Test wildcard subdomain matching."""
        app = FastAPI()
        middleware = CORSMiddleware(app)

        assert (
            middleware._match_wildcard_origin("https://app.example.com", "https://*.example.com")
            is True
        )
        assert (
            middleware._match_wildcard_origin("https://api.example.com", "https://*.example.com")
            is True
        )

    def test_no_match_base_domain(self) -> None:
        """Test that base domain doesn't match wildcard subdomain."""
        app = FastAPI()
        middleware = CORSMiddleware(app)

        assert (
            middleware._match_wildcard_origin("https://example.com", "https://*.example.com")
            is False
        )

    def test_no_match_different_domain(self) -> None:
        """Test no match with different domain."""
        app = FastAPI()
        middleware = CORSMiddleware(app)

        assert (
            middleware._match_wildcard_origin("https://other.com", "https://*.example.com") is False
        )

    def test_no_wildcard_returns_exact_match(self) -> None:
        """Test that patterns without wildcard use exact matching."""
        app = FastAPI()
        middleware = CORSMiddleware(app)

        assert (
            middleware._match_wildcard_origin("https://example.com", "https://example.com") is True
        )
        assert (
            middleware._match_wildcard_origin("https://other.com", "https://example.com") is False
        )

    def test_wildcard_with_prefix_and_suffix(self) -> None:
        """Test wildcard pattern with both prefix and suffix."""
        app = FastAPI()
        middleware = CORSMiddleware(app)

        assert (
            middleware._match_wildcard_origin("https://app.example.com", "https://*.example.com")
            is True
        )
        assert (
            middleware._match_wildcard_origin("http://app.example.com", "https://*.example.com")
            is False
        )

    def test_multiple_wildcards_not_supported(self) -> None:
        """Test that multiple wildcards are not supported."""
        app = FastAPI()
        middleware = CORSMiddleware(app)

        # Pattern with multiple wildcards should return False
        assert middleware._match_wildcard_origin("test", "*.*") is False


class TestAddCORSHeaders:
    """Tests for _add_cors_headers method."""

    def test_add_cors_headers_with_allowed_origin(self) -> None:
        """Test adding CORS headers for allowed origin."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_origins=["https://example.com"])

        from starlette.responses import JSONResponse

        response = JSONResponse(content={})
        middleware._add_cors_headers(response, "https://example.com")

        assert response.headers["Access-Control-Allow-Origin"] == "https://example.com"

    def test_add_cors_headers_with_wildcard(self) -> None:
        """Test adding CORS headers with wildcard origin."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_origins=["*"])

        from starlette.responses import JSONResponse

        response = JSONResponse(content={})
        middleware._add_cors_headers(response, "https://example.com")

        assert response.headers["Access-Control-Allow-Origin"] == "*"

    def test_add_cors_headers_with_credentials(self) -> None:
        """Test adding credentials header."""
        app = FastAPI()
        middleware = CORSMiddleware(
            app, allow_origins=["https://example.com"], allow_credentials=True
        )

        from starlette.responses import JSONResponse

        response = JSONResponse(content={})
        middleware._add_cors_headers(response, "https://example.com")

        assert response.headers["Access-Control-Allow-Credentials"] == "true"

    def test_no_credentials_with_wildcard(self) -> None:
        """Test that credentials header is not set with wildcard origin."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_origins=["*"], allow_credentials=True)

        from starlette.responses import JSONResponse

        response = JSONResponse(content={})
        middleware._add_cors_headers(response, "https://example.com")

        assert "Access-Control-Allow-Credentials" not in response.headers

    def test_add_expose_headers(self) -> None:
        """Test adding expose headers."""
        app = FastAPI()
        middleware = CORSMiddleware(
            app,
            allow_origins=["https://example.com"],
            expose_headers=["X-Custom-Header", "X-Request-ID"],
        )

        from starlette.responses import JSONResponse

        response = JSONResponse(content={})
        middleware._add_cors_headers(response, "https://example.com")

        assert response.headers["Access-Control-Expose-Headers"] == "X-Custom-Header, X-Request-ID"

    def test_no_headers_for_disallowed_origin(self) -> None:
        """Test that no headers are added for disallowed origin."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_origins=["https://example.com"])

        from starlette.responses import JSONResponse

        response = JSONResponse(content={})
        middleware._add_cors_headers(response, "https://other.com")

        assert "Access-Control-Allow-Origin" not in response.headers

    def test_no_headers_without_origin(self) -> None:
        """Test that no headers are added when origin is None."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_origins=["*"])

        from starlette.responses import JSONResponse

        response = JSONResponse(content={})
        middleware._add_cors_headers(response, None)

        assert "Access-Control-Allow-Origin" not in response.headers


class TestAddPreflightHeaders:
    """Tests for _add_preflight_headers method."""

    def test_add_preflight_headers_basic(self) -> None:
        """Test adding basic preflight headers."""
        app = FastAPI()
        middleware = CORSMiddleware(
            app, allow_origins=["https://example.com"], allow_methods=["GET", "POST"]
        )

        response = PlainTextResponse("OK")
        request = Mock(spec=Request)
        request.headers = {}

        middleware._add_preflight_headers(response, "https://example.com", request)

        assert response.headers["Access-Control-Allow-Origin"] == "https://example.com"
        assert response.headers["Access-Control-Allow-Methods"] == "GET, POST"

    def test_add_preflight_allow_headers_explicit(self) -> None:
        """Test adding explicit allowed headers."""
        app = FastAPI()
        middleware = CORSMiddleware(
            app,
            allow_origins=["https://example.com"],
            allow_headers=["Content-Type", "Authorization"],
        )

        response = PlainTextResponse("OK")
        request = Mock(spec=Request)
        request.headers = {}

        middleware._add_preflight_headers(response, "https://example.com", request)

        assert response.headers["Access-Control-Allow-Headers"] == "Content-Type, Authorization"

    def test_add_preflight_allow_headers_wildcard(self) -> None:
        """Test adding wildcard allowed headers."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_origins=["https://example.com"], allow_headers=["*"])

        response = PlainTextResponse("OK")
        request = Mock(spec=Request)
        request.headers = {"access-control-request-headers": "Content-Type, X-Custom"}

        middleware._add_preflight_headers(response, "https://example.com", request)

        assert response.headers["Access-Control-Allow-Headers"] == "Content-Type, X-Custom"

    def test_add_preflight_allow_headers_wildcard_no_request(self) -> None:
        """Test wildcard headers without requested headers."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_origins=["https://example.com"], allow_headers=["*"])

        response = PlainTextResponse("OK")
        request = Mock(spec=Request)
        request.headers = {}

        middleware._add_preflight_headers(response, "https://example.com", request)

        assert response.headers["Access-Control-Allow-Headers"] == "*"

    def test_add_preflight_max_age(self) -> None:
        """Test adding max age header."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_origins=["https://example.com"], max_age=3600)

        response = PlainTextResponse("OK")
        request = Mock(spec=Request)
        request.headers = {}

        middleware._add_preflight_headers(response, "https://example.com", request)

        assert response.headers["Access-Control-Max-Age"] == "3600"

    def test_add_preflight_credentials(self) -> None:
        """Test adding credentials header in preflight."""
        app = FastAPI()
        middleware = CORSMiddleware(
            app, allow_origins=["https://example.com"], allow_credentials=True
        )

        response = PlainTextResponse("OK")
        request = Mock(spec=Request)
        request.headers = {}

        middleware._add_preflight_headers(response, "https://example.com", request)

        assert response.headers["Access-Control-Allow-Credentials"] == "true"

    def test_add_preflight_wildcard_origin(self) -> None:
        """Test preflight with wildcard origin."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_origins=["*"])

        response = PlainTextResponse("OK")
        request = Mock(spec=Request)
        request.headers = {}

        middleware._add_preflight_headers(response, "https://example.com", request)

        assert response.headers["Access-Control-Allow-Origin"] == "*"


class TestHandlePreflight:
    """Tests for _handle_preflight method."""

    def test_handle_preflight_success(self) -> None:
        """Test successful preflight request handling."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_origins=["https://example.com"])

        request = Mock(spec=Request)
        request.headers = {}

        response = middleware._handle_preflight(request, "https://example.com")

        assert response.status_code == 200
        assert "Access-Control-Allow-Origin" in response.headers

    def test_handle_preflight_disallowed_origin(self) -> None:
        """Test preflight with disallowed origin."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_origins=["https://example.com"])

        request = Mock(spec=Request)

        response = middleware._handle_preflight(request, "https://other.com")

        assert response.status_code == 403
        assert response.body == b"Origin not allowed"

    def test_handle_preflight_no_origin(self) -> None:
        """Test preflight without origin header."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_origins=["*"])

        request = Mock(spec=Request)

        response = middleware._handle_preflight(request, None)

        assert response.status_code == 403


class TestDispatch:
    """Tests for dispatch method integration."""

    def test_dispatch_preflight_request(self) -> None:
        """Test dispatch handles OPTIONS preflight request."""
        app = FastAPI()

        @app.get("/api/test")
        async def test_endpoint() -> dict[str, str]:
            return {"status": "ok"}

        app.add_middleware(CORSMiddleware, allow_origins=["https://example.com"])

        client = TestClient(app)
        response = client.options(
            "/api/test",
            headers={"Origin": "https://example.com", "Access-Control-Request-Method": "GET"},
        )

        assert response.status_code == 200
        assert response.headers["Access-Control-Allow-Origin"] == "https://example.com"

    def test_dispatch_normal_request_with_cors(self) -> None:
        """Test dispatch adds CORS headers to normal request."""
        app = FastAPI()

        @app.get("/api/test")
        async def test_endpoint() -> dict[str, str]:
            return {"status": "ok"}

        app.add_middleware(CORSMiddleware, allow_origins=["https://example.com"])

        client = TestClient(app)
        response = client.get("/api/test", headers={"Origin": "https://example.com"})

        assert response.status_code == 200
        assert response.headers["Access-Control-Allow-Origin"] == "https://example.com"
        assert response.json() == {"status": "ok"}

    def test_dispatch_without_origin_header(self) -> None:
        """Test dispatch without origin header."""
        app = FastAPI()

        @app.get("/api/test")
        async def test_endpoint() -> dict[str, str]:
            return {"status": "ok"}

        app.add_middleware(CORSMiddleware, allow_origins=["https://example.com"])

        client = TestClient(app)
        response = client.get("/api/test")

        assert response.status_code == 200
        assert "Access-Control-Allow-Origin" not in response.headers

    def test_dispatch_disallowed_origin(self) -> None:
        """Test dispatch with disallowed origin."""
        app = FastAPI()

        @app.get("/api/test")
        async def test_endpoint() -> dict[str, str]:
            return {"status": "ok"}

        app.add_middleware(CORSMiddleware, allow_origins=["https://example.com"])

        client = TestClient(app)
        response = client.get("/api/test", headers={"Origin": "https://malicious.com"})

        assert response.status_code == 200
        assert "Access-Control-Allow-Origin" not in response.headers


class TestIntegration:
    """Integration tests for CORSMiddleware."""

    def test_complete_cors_flow(self) -> None:
        """Test complete CORS flow with preflight and actual request."""
        app = FastAPI()

        @app.post("/api/data")
        async def post_data() -> dict[str, str]:
            return {"result": "success"}

        app.add_middleware(
            CORSMiddleware,
            allow_origins=["https://frontend.com"],
            allow_methods=["POST"],
            allow_headers=["Content-Type"],
        )

        client = TestClient(app)

        # Preflight request
        preflight = client.options(
            "/api/data",
            headers={
                "Origin": "https://frontend.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )

        assert preflight.status_code == 200
        assert preflight.headers["Access-Control-Allow-Methods"] == "POST"

        # Actual request
        actual = client.post("/api/data", headers={"Origin": "https://frontend.com"})

        assert actual.status_code == 200
        assert actual.headers["Access-Control-Allow-Origin"] == "https://frontend.com"
        assert actual.json() == {"result": "success"}

    def test_multiple_origins(self) -> None:
        """Test CORS with multiple allowed origins."""
        app = FastAPI()

        @app.get("/api/test")
        async def test() -> dict[str, str]:
            return {"status": "ok"}

        app.add_middleware(
            CORSMiddleware,
            allow_origins=["https://app1.com", "https://app2.com", "https://app3.com"],
        )

        client = TestClient(app)

        # Test each allowed origin
        for origin in ["https://app1.com", "https://app2.com", "https://app3.com"]:
            response = client.get("/api/test", headers={"Origin": origin})
            assert response.status_code == 200
            assert response.headers["Access-Control-Allow-Origin"] == origin

        # Test disallowed origin
        response = client.get("/api/test", headers={"Origin": "https://other.com"})
        assert "Access-Control-Allow-Origin" not in response.headers

    def test_wildcard_subdomain_integration(self) -> None:
        """Test wildcard subdomain pattern in integration."""
        app = FastAPI()

        @app.get("/api/test")
        async def test() -> dict[str, str]:
            return {"status": "ok"}

        app.add_middleware(CORSMiddleware, allow_origins=["https://*.example.com"])

        client = TestClient(app)

        # Test various subdomains
        for subdomain in ["app", "api", "admin", "test"]:
            response = client.get(
                "/api/test", headers={"Origin": f"https://{subdomain}.example.com"}
            )
            assert response.status_code == 200
            assert (
                response.headers["Access-Control-Allow-Origin"]
                == f"https://{subdomain}.example.com"
            )

    def test_credentials_flow(self) -> None:
        """Test CORS with credentials enabled."""
        app = FastAPI()

        @app.get("/api/auth")
        async def auth() -> dict[str, str]:
            return {"authenticated": "true"}

        app.add_middleware(
            CORSMiddleware, allow_origins=["https://example.com"], allow_credentials=True
        )

        client = TestClient(app)

        response = client.get("/api/auth", headers={"Origin": "https://example.com"})

        assert response.status_code == 200
        assert response.headers["Access-Control-Allow-Origin"] == "https://example.com"
        assert response.headers["Access-Control-Allow-Credentials"] == "true"

    def test_expose_headers_integration(self) -> None:
        """Test exposed headers in integration."""
        app = FastAPI()

        @app.get("/api/test")
        async def test() -> dict[str, str]:
            return {"status": "ok"}

        app.add_middleware(
            CORSMiddleware,
            allow_origins=["https://example.com"],
            expose_headers=["X-Total-Count", "X-Page-Number"],
        )

        client = TestClient(app)

        response = client.get("/api/test", headers={"Origin": "https://example.com"})

        assert response.status_code == 200
        assert response.headers["Access-Control-Expose-Headers"] == "X-Total-Count, X-Page-Number"


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_origin_header(self) -> None:
        """Test with empty origin header."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_origins=["*"])

        from starlette.responses import JSONResponse

        response = JSONResponse(content={})
        middleware._add_cors_headers(response, "")

        assert "Access-Control-Allow-Origin" not in response.headers

    def test_complex_wildcard_pattern(self) -> None:
        """Test complex wildcard patterns."""
        app = FastAPI()
        middleware = CORSMiddleware(app, allow_origins=["https://*.prod.example.com"])

        assert middleware._is_origin_allowed("https://app.prod.example.com") is True
        assert middleware._is_origin_allowed("https://api.prod.example.com") is True
        assert middleware._is_origin_allowed("https://prod.example.com") is False

    def test_preflight_with_all_headers(self) -> None:
        """Test preflight request with all possible headers."""
        app = FastAPI()
        middleware = CORSMiddleware(
            app,
            allow_origins=["https://example.com"],
            allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
            allow_headers=["Content-Type", "Authorization", "X-Custom"],
            allow_credentials=True,
            max_age=7200,
        )

        response = PlainTextResponse("OK")
        request = Mock(spec=Request)
        request.headers = {}

        middleware._add_preflight_headers(response, "https://example.com", request)

        assert "Access-Control-Allow-Origin" in response.headers
        assert "Access-Control-Allow-Methods" in response.headers
        assert "Access-Control-Allow-Headers" in response.headers
        assert "Access-Control-Allow-Credentials" in response.headers
        assert response.headers["Access-Control-Max-Age"] == "7200"

    def test_middleware_with_api_settings_integration(self) -> None:
        """Test middleware using APISettings from config."""
        from core.config import APISettings

        app = FastAPI()
        settings = APISettings(
            cors_origins=["https://configured.com"],
            cors_methods=["GET", "POST"],
            cors_headers=["Content-Type"],
            cors_credentials=False,
        )

        @app.get("/test")
        async def test() -> dict[str, str]:
            return {"status": "ok"}

        app.add_middleware(CORSMiddleware, api_settings=settings)

        client = TestClient(app)
        response = client.get("/test", headers={"Origin": "https://configured.com"})

        assert response.status_code == 200
        assert response.headers["Access-Control-Allow-Origin"] == "https://configured.com"
