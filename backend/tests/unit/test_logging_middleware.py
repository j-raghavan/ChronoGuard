"""Tests for request logging middleware."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from fastapi import FastAPI, Request
from starlette.testclient import TestClient

from main import create_app
from presentation.api.middleware.auth import AuthMiddleware
from presentation.api.middleware.logging import CORRELATION_ID_HEADER, RequestLoggingMiddleware


class TestRequestLoggingMiddleware:
    """Tests for request logging behavior."""

    def test_generates_correlation_id_and_logs_request_lifecycle(self) -> None:
        """Test middleware generates correlation IDs and logs start/end events."""
        app = FastAPI()

        @app.get("/ping")
        async def ping(request: Request) -> dict[str, str]:
            return {"correlation_id": request.state.correlation_id}

        with patch("presentation.api.middleware.logging.logger") as mock_logger:
            bound_logger = MagicMock()
            chained_logger = MagicMock()
            mock_logger.bind.return_value = bound_logger
            bound_logger.bind.return_value = chained_logger

            app.add_middleware(RequestLoggingMiddleware)
            client = TestClient(app)

            response = client.get("/ping")

        assert response.status_code == 200
        correlation_id = response.headers[CORRELATION_ID_HEADER]
        assert correlation_id
        assert response.json()["correlation_id"] == correlation_id

        mock_logger.bind.assert_called_once()
        bind_kwargs = mock_logger.bind.call_args.kwargs
        assert bind_kwargs["correlation_id"] == correlation_id
        assert bind_kwargs["method"] == "GET"
        assert bind_kwargs["path"] == "/ping"
        bound_logger.info.assert_called_once_with("HTTP request started")

        response_log_call = bound_logger.bind.call_args.kwargs
        assert response_log_call["status"] == 200
        assert response_log_call["latency_ms"] >= 0
        chained_logger.info.assert_called_once_with("HTTP request completed")

    def test_preserves_incoming_correlation_id_and_exposes_context(self) -> None:
        """Test middleware reuses incoming correlation ID and exposes it to handlers."""
        app = FastAPI()

        @app.get("/context")
        async def context(request: Request) -> dict[str, str | None]:
            from presentation.api.middleware.logging import get_correlation_id

            return {
                "state_correlation_id": request.state.correlation_id,
                "context_correlation_id": get_correlation_id(),
            }

        app.add_middleware(RequestLoggingMiddleware)
        client = TestClient(app)

        response = client.get("/context", headers={CORRELATION_ID_HEADER: "abc-123"})

        assert response.status_code == 200
        assert response.headers[CORRELATION_ID_HEADER] == "abc-123"
        assert response.json() == {
            "state_correlation_id": "abc-123",
            "context_correlation_id": "abc-123",
        }

    def test_logs_errors_with_request_context(self) -> None:
        """Test middleware logs unhandled exceptions with correlation context."""
        app = FastAPI()

        @app.get("/boom")
        async def boom() -> None:
            raise RuntimeError("boom")

        with patch("presentation.api.middleware.logging.logger") as mock_logger:
            bound_logger = MagicMock()
            error_logger = MagicMock()
            opt_logger = MagicMock()
            mock_logger.bind.return_value = bound_logger
            bound_logger.bind.return_value = error_logger
            error_logger.opt.return_value = opt_logger

            app.add_middleware(RequestLoggingMiddleware)
            client = TestClient(app, raise_server_exceptions=False)

            response = client.get("/boom")

        assert response.status_code == 500
        correlation_id = response.headers[CORRELATION_ID_HEADER]
        assert correlation_id
        bound_logger.info.assert_called_once_with("HTTP request started")

        bind_kwargs = mock_logger.bind.call_args.kwargs
        assert bind_kwargs["correlation_id"] == correlation_id
        assert bind_kwargs["method"] == "GET"
        assert bind_kwargs["path"] == "/boom"

        error_bind_kwargs = bound_logger.bind.call_args.kwargs
        assert error_bind_kwargs["latency_ms"] >= 0
        assert error_bind_kwargs["status"] == 500
        error_logger.opt.assert_called_once_with(exception=True)
        opt_logger.error.assert_called_once_with("HTTP request failed")


class TestMainApplicationLoggingMiddleware:
    """Tests for logging middleware registration."""

    def test_create_app_registers_logging_middleware(self) -> None:
        """Test main app includes request logging middleware."""
        app = create_app()

        middleware_classes = [middleware.cls for middleware in app.user_middleware]

        assert RequestLoggingMiddleware in middleware_classes
        assert middleware_classes.index(RequestLoggingMiddleware) < middleware_classes.index(
            AuthMiddleware
        )

    def test_create_app_unauthorized_response_includes_correlation_id(self) -> None:
        """Test logging middleware wraps unauthorized responses from auth middleware."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/api/v1/auth/session")

        assert response.status_code == 401
        assert CORRELATION_ID_HEADER in response.headers
        assert response.headers[CORRELATION_ID_HEADER]
