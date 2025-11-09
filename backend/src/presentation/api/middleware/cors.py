"""CORS middleware for FastAPI.

This module provides a dedicated CORS middleware implementation that integrates
with APISettings configuration for origins, methods, headers, and credentials support.
"""

from __future__ import annotations

from collections.abc import Callable

from core.config import APISettings, get_settings
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse


class CORSMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for Cross-Origin Resource Sharing (CORS).

    Handles preflight requests and adds CORS headers to responses based on
    configuration from APISettings. Supports wildcard origins, credentials,
    and custom headers.

    Example:
        app.add_middleware(
            CORSMiddleware,
            api_settings=APISettings(
                cors_origins=["https://example.com"],
                cors_credentials=True
            )
        )
    """

    def __init__(
        self,
        app: Callable,
        api_settings: APISettings | None = None,
        allow_origins: list[str] | None = None,
        allow_methods: list[str] | None = None,
        allow_headers: list[str] | None = None,
        allow_credentials: bool | None = None,
        expose_headers: list[str] | None = None,
        max_age: int = 600,
    ) -> None:
        """Initialize CORS middleware.

        Args:
            app: FastAPI application instance
            api_settings: API configuration settings (uses global settings if None)
            allow_origins: Allowed origins (overrides api_settings)
            allow_methods: Allowed HTTP methods (overrides api_settings)
            allow_headers: Allowed headers (overrides api_settings)
            allow_credentials: Allow credentials flag (overrides api_settings)
            expose_headers: Headers exposed to browser
            max_age: Preflight cache duration in seconds
        """
        super().__init__(app)

        # Use provided settings or get global settings
        if api_settings is None:
            api_settings = get_settings().api

        # Use explicit parameters or fall back to settings
        self.allow_origins = allow_origins or api_settings.cors_origins
        self.allow_methods = allow_methods or api_settings.cors_methods
        self.allow_headers = allow_headers or api_settings.cors_headers
        self.allow_credentials = (
            allow_credentials if allow_credentials is not None else api_settings.cors_credentials
        )
        self.expose_headers = expose_headers or []
        self.max_age = max_age

        # Precompute flags for optimization
        self.allow_all_origins = "*" in self.allow_origins
        self.allow_all_headers = "*" in self.allow_headers

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through CORS pipeline.

        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in chain

        Returns:
            HTTP response with CORS headers added
        """
        # Get origin from request
        origin = request.headers.get("origin")

        # Handle preflight requests (OPTIONS method)
        if request.method == "OPTIONS":
            return self._handle_preflight(request, origin)

        # Process normal request
        response = await call_next(request)

        # Add CORS headers to response
        self._add_cors_headers(response, origin)

        return response

    def _handle_preflight(self, request: Request, origin: str | None) -> Response:
        """Handle CORS preflight request.

        Args:
            request: OPTIONS request with preflight headers
            origin: Origin header value

        Returns:
            Response with CORS preflight headers
        """
        # Validate origin
        if not origin or not self._is_origin_allowed(origin):
            return PlainTextResponse("Origin not allowed", status_code=403)

        # Create preflight response
        response = PlainTextResponse("OK", status_code=200)

        # Add CORS headers
        self._add_preflight_headers(response, origin, request)

        return response

    def _add_cors_headers(self, response: Response, origin: str | None) -> None:
        """Add CORS headers to response.

        Args:
            response: HTTP response to modify
            origin: Origin header value from request
        """
        # Only add CORS headers if origin is present and allowed
        if origin and self._is_origin_allowed(origin):
            # Set allowed origin
            if self.allow_all_origins:
                response.headers["Access-Control-Allow-Origin"] = "*"
            else:
                response.headers["Access-Control-Allow-Origin"] = origin

            # Set credentials if enabled (not allowed with wildcard origin)
            if self.allow_credentials and not self.allow_all_origins:
                response.headers["Access-Control-Allow-Credentials"] = "true"

            # Expose headers if configured
            if self.expose_headers:
                response.headers["Access-Control-Expose-Headers"] = ", ".join(self.expose_headers)

    def _add_preflight_headers(self, response: Response, origin: str, request: Request) -> None:
        """Add preflight-specific CORS headers.

        Args:
            response: Preflight response to modify
            origin: Origin header value
            request: Preflight request
        """
        # Set allowed origin
        if self.allow_all_origins:
            response.headers["Access-Control-Allow-Origin"] = "*"
        else:
            response.headers["Access-Control-Allow-Origin"] = origin

        # Set allowed methods
        response.headers["Access-Control-Allow-Methods"] = ", ".join(self.allow_methods)

        # Set allowed headers
        if self.allow_all_headers:
            # Echo back requested headers
            requested_headers = request.headers.get("access-control-request-headers")
            if requested_headers:
                response.headers["Access-Control-Allow-Headers"] = requested_headers
            else:
                response.headers["Access-Control-Allow-Headers"] = "*"
        else:
            response.headers["Access-Control-Allow-Headers"] = ", ".join(self.allow_headers)

        # Set credentials if enabled (not allowed with wildcard origin)
        if self.allow_credentials and not self.allow_all_origins:
            response.headers["Access-Control-Allow-Credentials"] = "true"

        # Set max age for preflight cache
        response.headers["Access-Control-Max-Age"] = str(self.max_age)

    def _is_origin_allowed(self, origin: str) -> bool:
        """Check if origin is allowed by CORS policy.

        Args:
            origin: Origin to validate

        Returns:
            True if origin is allowed, False otherwise
        """
        if self.allow_all_origins:
            return True

        # Check exact match
        if origin in self.allow_origins:
            return True

        # Check wildcard patterns (e.g., "https://*.example.com")
        for allowed_origin in self.allow_origins:
            if "*" in allowed_origin and self._match_wildcard_origin(origin, allowed_origin):
                return True

        return False

    def _match_wildcard_origin(self, origin: str, pattern: str) -> bool:
        """Match origin against wildcard pattern.

        Args:
            origin: Origin to match
            pattern: Wildcard pattern (e.g., "https://*.example.com")

        Returns:
            True if origin matches pattern, False otherwise

        Note:
            Only supports single wildcard at subdomain level.
            Examples:
            - "https://*.example.com" matches "https://app.example.com"
            - "https://*.example.com" does not match "https://example.com"
        """
        if "*" not in pattern:
            return origin == pattern

        # Split pattern into prefix and suffix
        parts = pattern.split("*", 1)
        if len(parts) != 2:
            return False

        prefix, suffix = parts

        # Check if origin starts with prefix and ends with suffix
        return origin.startswith(prefix) and origin.endswith(suffix)
