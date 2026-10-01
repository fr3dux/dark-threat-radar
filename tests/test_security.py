"""Focused tests for application-layer security middleware."""

import asyncio

from app.security import RequestBodyLimitMiddleware


def test_streaming_body_limit_rejects_chunked_oversize_request():
    messages = [
        {"type": "http.request", "body": b"x" * 40, "more_body": True},
        {"type": "http.request", "body": b"x" * 40, "more_body": False},
    ]
    sent = []

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    async def downstream(_scope, receive_limited, _send):
        while True:
            message = await receive_limited()
            if not message.get("more_body"):
                break

    middleware = RequestBodyLimitMiddleware(downstream, max_body_size=64)
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/leak-check/email",
        "headers": [(b"transfer-encoding", b"chunked")],
    }
    asyncio.run(middleware(scope, receive, send))

    response_start = next(message for message in sent if message["type"] == "http.response.start")
    assert response_start["status"] == 413
