"""Application-layer security controls for the public CTI portal."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from fastapi import Request
from fastapi.responses import JSONResponse


MAX_REQUEST_BODY_BYTES = 64 * 1024
MAX_TLS_UPLOAD_BODY_BYTES = 128 * 1024


@dataclass(frozen=True)
class RateLimitRule:
    requests: int
    window_seconds: int


RATE_LIMIT_RULES = {
    "admin": RateLimitRule(20, 60),
    "sync": RateLimitRule(3, 300),
    "leak_check": RateLimitRule(20, 60),
    "watchlist_write": RateLimitRule(20, 60),
}


class InMemoryRateLimiter:
    """Small per-process sliding-window limiter.

    The application currently runs as one Uvicorn process. Deployments with
    multiple workers should enforce the same limits at the reverse proxy too.
    """

    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def allow(self, key: str, rule: RateLimitRule) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - rule.window_seconds
        async with self._lock:
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= rule.requests:
                retry_after = max(1, int(rule.window_seconds - (now - events[0])) + 1)
                return False, retry_after
            events.append(now)
            return True, 0

    def clear(self) -> None:
        self._events.clear()


rate_limiter = InMemoryRateLimiter()


class RequestBodyLimitMiddleware:
    """Enforce the body ceiling while streaming, including chunked requests."""

    def __init__(self, app, max_body_size: int = MAX_REQUEST_BODY_BYTES) -> None:
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope.get("method", "GET").upper() not in {
            "POST", "PUT", "PATCH"
        }:
            await self.app(scope, receive, send)
            return

        effective_limit = (
            MAX_TLS_UPLOAD_BODY_BYTES
            if scope.get("path") == "/api/admin/settings/tls"
            else self.max_body_size
        )
        headers = dict(scope.get("headers", []))
        declared_length = headers.get(b"content-length")
        if declared_length:
            try:
                if int(declared_length) > effective_limit:
                    response = JSONResponse(
                        status_code=413,
                        content={"error": "Request body too large", "status_code": 413},
                    )
                    await response(scope, receive, send)
                    return
            except ValueError:
                response = JSONResponse(
                    status_code=400,
                    content={"error": "Invalid Content-Length header", "status_code": 400},
                )
                await response(scope, receive, send)
                return

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > effective_limit:
                    raise _RequestBodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _RequestBodyTooLarge:
            response = JSONResponse(
                status_code=413,
                content={"error": "Request body too large", "status_code": 413},
            )
            await response(scope, receive, send)


class _RequestBodyTooLarge(Exception):
    pass


def _client_key(request: Request) -> str:
    # Do not trust X-Forwarded-For from arbitrary clients. A reverse proxy can
    # apply its own source-aware limits before forwarding to Uvicorn.
    return request.client.host if request.client else "unknown"


def _rate_limit_scope(request: Request) -> str | None:
    path = request.url.path
    method = request.method.upper()
    if path.startswith("/api/admin/"):
        return "admin"
    if path == "/api/sync" and method == "POST":
        return "sync"
    if path.startswith("/api/leak-check/") and method == "POST":
        return "leak_check"
    if path == "/api/watchlist" and method == "POST":
        return "watchlist_write"
    if path == "/api/watchlist/alerts/acknowledge" and method == "POST":
        return "watchlist_write"
    if path.startswith("/api/watchlist/") and method == "DELETE":
        return "watchlist_write"
    return None


async def security_middleware(request: Request, call_next):
    """Reject oversized/abusive requests and attach browser protections."""
    scope = _rate_limit_scope(request)
    if scope:
        rule = RATE_LIMIT_RULES[scope]
        allowed, retry_after = await rate_limiter.allow(
            f"{scope}:{_client_key(request)}", rule
        )
        if not allowed:
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(retry_after)},
                content={"error": "Too many requests", "status_code": 429},
            )

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'none'; object-src 'none'; "
        "frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; "
        "connect-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'"
    )
    if request.url.path.startswith("/api/admin/"):
        response.headers["Cache-Control"] = "no-store"
    return response
