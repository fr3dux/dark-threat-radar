"""Application-layer security controls for the public CTI portal."""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict, deque
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
    "watchlist_read": RateLimitRule(120, 60),
    "update_check": RateLimitRule(20, 300),
    "artifact_read": RateLimitRule(120, 60),
    "api_read": RateLimitRule(600, 60),
}


class InMemoryRateLimiter:
    """Small per-process sliding-window limiter.

    The application currently runs as one Uvicorn process. Deployments with
    multiple workers should enforce the same limits at the reverse proxy too.
    """

    def __init__(self, max_keys: int = 10_000) -> None:
        self._events: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = asyncio.Lock()
        self._max_keys = max_keys

    async def allow(self, key: str, rule: RateLimitRule) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - rule.window_seconds
        async with self._lock:
            events = self._events.get(key)
            if events is None:
                if len(self._events) >= self._max_keys:
                    self._events.popitem(last=False)
                events = deque()
                self._events[key] = events
            else:
                self._events.move_to_end(key)
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
    if path in {"/api/watchlist", "/api/watchlist/summary"} and method == "GET":
        return "watchlist_read"
    if path == "/api/update/status" and method == "GET":
        return "update_check"
    if path.startswith("/api/artifact/") and method == "GET":
        return "artifact_read"
    if path == "/api/watchlist" and method == "POST":
        return "watchlist_write"
    if path == "/api/watchlist/alerts/acknowledge" and method == "POST":
        return "watchlist_write"
    if path.startswith("/api/watchlist/") and method == "DELETE":
        return "watchlist_write"
    if path.startswith("/api/") and method == "GET":
        return "api_read"
    return None


def _is_audited_operation(request: Request) -> bool:
    path = request.url.path
    method = request.method.upper()
    return (
        path.startswith("/api/admin/")
        or (path == "/api/sync" and method == "POST")
        or (path.startswith("/api/watchlist") and method in {"POST", "PUT", "DELETE"})
    )


async def _record_audit(request: Request, status_code: int) -> None:
    try:
        from app.database import get_db

        async with get_db() as conn:
            await conn.execute(
                """INSERT INTO security_audit (
                       occurred_at, client_address, method, path, status_code, user_agent
                   ) VALUES (datetime('now'), ?, ?, ?, ?, ?)""",
                (
                    _client_key(request)[:128],
                    request.method.upper()[:10],
                    request.url.path[:512],
                    status_code,
                    request.headers.get("user-agent", "")[:256],
                ),
            )
            await conn.execute(
                """DELETE FROM security_audit WHERE id NOT IN (
                       SELECT id FROM security_audit ORDER BY id DESC LIMIT 5000
                   )"""
            )
            await conn.commit()
    except Exception:
        # Auditing must never disclose request data or take the service down.
        return


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
    if _is_audited_operation(request):
        await _record_audit(request, response.status_code)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'none'; object-src 'none'; "
        "frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; "
        "connect-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'"
    )
    if request.url.path.startswith(("/api/admin/", "/api/watchlist", "/api/leak-check/", "/api/artifact/")):
        response.headers["Cache-Control"] = "no-store"
    return response
