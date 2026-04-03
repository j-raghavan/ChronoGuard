"""Request logging middleware for FastAPI."""

from __future__ import annotations

from contextvars import ContextVar, Token
from datetime import UTC, datetime
from time import perf_counter
from uuid import uuid4

from loguru import logger
from starlette.responses import PlainTextResponse
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

CORRELATION_ID_HEADER = "X-Correlation-ID"
_correlation_id_context: ContextVar[str | None] = ContextVar(
    "request_correlation_id",
    default=None,
)


def get_correlation_id() -> str | None:
    """Return the correlation ID for the current request context."""

    return _correlation_id_context.get()


class RequestLoggingMiddleware:
    """Log inbound API requests with correlation IDs and latency."""

    def __init__(self, app: ASGIApp) -> None:
        """Initialize middleware with the downstream ASGI app."""

        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Log request lifecycle details and attach correlation metadata."""

        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        correlation_id = self._get_correlation_id(scope)
        context_token = self._set_correlation_context(correlation_id)
        scope.setdefault("state", {})["correlation_id"] = correlation_id

        request_logger = logger.bind(
            correlation_id=correlation_id,
            method=scope["method"],
            path=scope["path"],
            timestamp=datetime.now(UTC).isoformat(),
        )
        start_time = perf_counter()
        response_status: int | None = None

        request_logger.info("HTTP request started")

        async def send_wrapper(message: Message) -> None:
            nonlocal response_status

            if message["type"] == "http.response.start":
                response_status = message["status"]
                headers = MutableHeaders(scope=message)
                headers[CORRELATION_ID_HEADER] = correlation_id

            if message["type"] == "http.response.body" and not message.get("more_body", False):
                latency_ms = self._latency_ms(start_time)
                request_logger.bind(status=response_status, latency_ms=latency_ms).info(
                    "HTTP request completed"
                )

            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            latency_ms = self._latency_ms(start_time)
            request_logger.bind(latency_ms=latency_ms).opt(exception=True).error(
                "HTTP request failed"
            )
            if response_status is not None:
                raise

            await self._send_internal_server_error(scope, receive, send, correlation_id)
            request_logger.bind(status=500, latency_ms=latency_ms).info("HTTP request completed")
        finally:
            self._reset_correlation_context(context_token)

    def _get_correlation_id(self, scope: Scope) -> str:
        """Return inbound correlation ID header or generate a new one."""

        headers = Headers(scope=scope)
        return headers.get(CORRELATION_ID_HEADER) or str(uuid4())

    def _set_correlation_context(self, correlation_id: str) -> Token[str | None]:
        """Store the correlation ID in context for downstream access."""

        return _correlation_id_context.set(correlation_id)

    def _reset_correlation_context(self, token: Token[str | None]) -> None:
        """Reset correlation context after request completion."""

        _correlation_id_context.reset(token)

    def _latency_ms(self, start_time: float) -> float:
        """Return elapsed time in milliseconds."""

        return round((perf_counter() - start_time) * 1000, 3)

    async def _send_internal_server_error(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        correlation_id: str,
    ) -> None:
        """Send a fallback 500 response that preserves correlation metadata."""

        response = PlainTextResponse(
            "Internal Server Error",
            status_code=500,
            headers={CORRELATION_ID_HEADER: correlation_id},
        )
        await response(scope, receive, send)
