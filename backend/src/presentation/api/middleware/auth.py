"""Authentication middleware for FastAPI.

This module provides middleware components for JWT authentication, mTLS certificate
authentication, and API key authentication. It integrates with core/security.py and
injects user/agent context into request state.
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from core.config import SecuritySettings, get_settings
from core.security import (
    CertificateValidationError,
    TokenError,
    decode_token,
    extract_certificate_info,
    load_certificate_from_pem,
    validate_certificate,
)


class AuthenticationError(Exception):
    """Raised when authentication fails."""

    pass


class AuthMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for request authentication.

    Supports JWT token authentication, mTLS certificate authentication, and
    API key authentication. Injects authenticated user/agent context into
    request state for downstream handlers.

    Example:
        app.add_middleware(
            AuthMiddleware,
            exempt_paths=["/health", "/metrics"],
            enable_mtls=True
        )
    """

    def __init__(
        self,
        app: Callable,
        exempt_paths: list[str] | None = None,
        enable_mtls: bool = False,
        enable_api_key: bool = False,
        security_settings: SecuritySettings | None = None,
    ) -> None:
        """Initialize authentication middleware.

        Args:
            app: FastAPI application instance
            exempt_paths: List of paths that bypass authentication
            enable_mtls: Enable mTLS certificate authentication
            enable_api_key: Enable API key authentication
            security_settings: Security configuration settings
        """
        super().__init__(app)
        self.exempt_paths = exempt_paths or ["/health", "/metrics", "/docs", "/openapi.json"]
        self.enable_mtls = enable_mtls
        self.enable_api_key = enable_api_key
        self.security_settings = security_settings or get_settings().security

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through authentication pipeline.

        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in chain

        Returns:
            HTTP response from handler or authentication error

        Note:
            Authentication is performed in the following order:
            1. Check if path is exempt
            2. Try mTLS authentication (if enabled)
            3. Try JWT token authentication
            4. Try API key authentication (if enabled)
        """
        # Always allow OPTIONS requests (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)

        # Check if path is exempt from authentication
        if self._is_exempt_path(request.url.path):
            return await call_next(request)

        # Try mTLS authentication first if enabled
        if self.enable_mtls:
            try:
                await self._authenticate_mtls(request)
                return await call_next(request)
            except AuthenticationError:
                pass  # Fall through to other methods

        # Try JWT token authentication
        try:
            await self._authenticate_jwt(request)
            return await call_next(request)
        except AuthenticationError:
            pass  # Fall through to API key

        # Try API key authentication if enabled
        if self.enable_api_key:
            try:
                await self._authenticate_api_key(request)
                return await call_next(request)
            except AuthenticationError:
                pass  # Fall through to error

        # No authentication method succeeded
        return JSONResponse(
            status_code=401,
            content={
                "error": "Unauthorized",
                "message": "Authentication required",
                "detail": "No valid authentication credentials provided",
            },
        )

    def _is_exempt_path(self, path: str) -> bool:
        """Check if path is exempt from authentication.

        Args:
            path: Request path to check

        Returns:
            True if path is exempt, False otherwise
        """
        return any(path.startswith(exempt_path) for exempt_path in self.exempt_paths)

    async def _authenticate_jwt(self, request: Request) -> None:
        """Authenticate request using JWT token.

        Args:
            request: HTTP request carrying credentials

        Raises:
            AuthenticationError: If JWT authentication fails

        Note:
            Looks for Authorization bearer token first, then falls back to
            the secure session cookie configured in security settings.
        """
        token = self._extract_bearer_token(request)
        if not token:
            raise AuthenticationError("Missing authentication credentials")

        try:
            payload = decode_token(token, self.security_settings)
            request.state.user = payload
            request.state.auth_method = "jwt"
        except TokenError as e:
            raise AuthenticationError(f"Invalid JWT token: {e}") from e

    def _extract_bearer_token(self, request: Request) -> str | None:
        """Extract JWT token from Authorization header or secure cookie."""

        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            return auth_header[7:]

        cookie_name = getattr(self.security_settings, "session_cookie_name", None)
        if cookie_name:
            cookie_value = request.cookies.get(cookie_name)
            if cookie_value:
                return cookie_value

        return None

    async def _authenticate_mtls(self, request: Request) -> None:
        """Authenticate request using mTLS client certificate.

        Args:
            request: HTTP request with client certificate

        Raises:
            AuthenticationError: If mTLS authentication fails

        Note:
            Expects client certificate in request scope's "peercert" field
            Sets request.state.agent with certificate information
        """
        # Get client certificate from request scope
        client_cert_pem = request.scope.get("peercert")
        if not client_cert_pem:
            raise AuthenticationError("No client certificate provided")

        try:
            # Load and validate certificate
            cert = load_certificate_from_pem(client_cert_pem)

            # Validate certificate (check expiration and CA if configured)
            ca_cert = None
            if self.security_settings.ca_cert_path:
                with open(self.security_settings.ca_cert_path, "rb") as f:
                    ca_cert = load_certificate_from_pem(f.read())

            is_valid, errors = validate_certificate(
                cert, check_expiration=True, trusted_ca_cert=ca_cert
            )

            if not is_valid:
                raise AuthenticationError(f"Invalid certificate: {', '.join(errors)}")

            # Extract certificate information
            cert_info = extract_certificate_info(cert)

            # Set agent context in request state
            request.state.agent = cert_info
            request.state.auth_method = "mtls"

        except CertificateValidationError as e:
            raise AuthenticationError(f"Certificate validation failed: {e}") from e

    async def _authenticate_api_key(self, request: Request) -> None:
        """Authenticate request using API key.

        Args:
            request: HTTP request with X-API-Key header

        Raises:
            AuthenticationError: If API key authentication fails

        Note:
            Expects X-API-Key header with valid API key
            Sets request.state.api_key with key information

        Warning:
            This is a basic implementation. Production systems should:
            - Store API keys hashed in database
            - Implement rate limiting per API key
            - Support key rotation and expiration
        """
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            raise AuthenticationError("Missing X-API-Key header")

        # TODO: Implement proper API key validation against database
        # For now, this is a placeholder that always fails
        # Production implementation should:
        # 1. Query database for hashed API key
        # 2. Verify key is not expired
        # 3. Load associated permissions/scopes
        # 4. Set request.state with API key context
        raise AuthenticationError("API key authentication not fully implemented")
