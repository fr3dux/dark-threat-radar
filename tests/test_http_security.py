import asyncio

import httpx
import pytest

from app.http_security import (
    OutboundResponseTooLarge,
    UnsafeOutboundURL,
    safe_get,
    safe_post,
    validate_outbound_url,
)


def test_outbound_url_requires_exact_https_provider():
    assert validate_outbound_url(
        "https://api.example.com/feed", {"api.example.com"}
    ) == "https://api.example.com/feed"
    for unsafe in (
        "http://api.example.com/feed",
        "https://api.example.com.evil.test/feed",
        "https://user@api.example.com/feed",
        "https://api.example.com:8443/feed",
        "https://127.0.0.1/feed",
    ):
        with pytest.raises(UnsafeOutboundURL):
            validate_outbound_url(unsafe, {"api.example.com"})


def test_safe_get_blocks_cross_host_redirect():
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            302, headers={"Location": "https://metadata.invalid/latest"}, request=request
        )
    )

    async def run():
        async with httpx.AsyncClient(transport=transport) as client:
            await safe_get(client, "https://api.example.com/feed", allowed_hosts={"api.example.com"})

    with pytest.raises(UnsafeOutboundURL):
        asyncio.run(run())


def test_safe_get_enforces_decoded_body_limit():
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b"x" * 65, request=request))

    async def run():
        async with httpx.AsyncClient(transport=transport) as client:
            await safe_get(
                client,
                "https://api.example.com/feed",
                allowed_hosts={"api.example.com"},
                max_bytes=64,
            )

    with pytest.raises(OutboundResponseTooLarge):
        asyncio.run(run())


def test_safe_get_allows_bounded_same_host_redirect():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "/final"}, request=request)
        return httpx.Response(200, json={"ok": True}, request=request)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await safe_get(
                client,
                "https://api.example.com/start",
                allowed_hosts={"api.example.com"},
            )

    response = asyncio.run(run())
    assert response.url == "https://api.example.com/final"
    assert response.json() == {"ok": True}


def test_safe_post_rejects_redirects():
    transport = httpx.MockTransport(
        lambda request: httpx.Response(307, headers={"Location": "/elsewhere"}, request=request)
    )

    async def run():
        async with httpx.AsyncClient(transport=transport) as client:
            await safe_post(
                client,
                "https://api.example.com/query",
                allowed_hosts={"api.example.com"},
                json={"query": "value"},
            )

    with pytest.raises(UnsafeOutboundURL):
        asyncio.run(run())
