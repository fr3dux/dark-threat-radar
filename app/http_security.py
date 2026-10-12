"""Restricted outbound HTTP helpers for fixed CTI providers.

Connector URLs are controlled by the application, but remote providers can
still reply with redirects or unexpectedly large bodies.  This module keeps
those requests on HTTPS, pins them to an explicit hostname, and bounds the
decoded response body before parsers see it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from urllib.parse import urljoin, urlsplit

import httpx


REDIRECT_STATUSES = {301, 302, 303, 307, 308}
DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024
DECODED_BODY_HEADERS = {"content-encoding", "content-length", "transfer-encoding"}


class UnsafeOutboundURL(ValueError):
    """Raised when a provider attempts to leave its approved HTTPS origin."""


class OutboundResponseTooLarge(ValueError):
    """Raised before an untrusted response can consume unbounded memory."""


def _decoded_response_headers(headers: httpx.Headers) -> list[tuple[str, str]]:
    """Drop wire-encoding metadata after httpx has decoded the response body."""
    return [
        (name, value)
        for name, value in headers.multi_items()
        if name.casefold() not in DECODED_BODY_HEADERS
    ]


def validate_outbound_url(url: str, allowed_hosts: Iterable[str]) -> str:
    parsed = urlsplit(str(url))
    allowed = {host.casefold().rstrip(".") for host in allowed_hosts}
    hostname = (parsed.hostname or "").casefold().rstrip(".")
    if (
        parsed.scheme.casefold() != "https"
        or not hostname
        or hostname not in allowed
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
    ):
        raise UnsafeOutboundURL("Outbound request was blocked by the provider allowlist")
    return str(url)


async def safe_get(
    client: httpx.AsyncClient,
    url: str,
    *,
    allowed_hosts: Iterable[str],
    max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    max_redirects: int = 3,
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, object] | None = None,
) -> httpx.Response:
    """GET one provider resource with same-host redirects and a body ceiling."""
    if max_bytes < 1 or max_redirects < 0:
        raise ValueError("Invalid outbound response limits")

    current_url = validate_outbound_url(url, allowed_hosts)
    original_host = (urlsplit(current_url).hostname or "").casefold().rstrip(".")
    current_params = params

    for redirect_count in range(max_redirects + 1):
        async with client.stream(
            "GET",
            current_url,
            headers=headers,
            params=current_params,
            follow_redirects=False,
        ) as upstream:
            if upstream.status_code in REDIRECT_STATUSES:
                location = upstream.headers.get("location")
                if not location or redirect_count >= max_redirects:
                    raise UnsafeOutboundURL("Provider redirect limit exceeded")
                redirected = urljoin(str(upstream.url), location)
                validate_outbound_url(redirected, allowed_hosts)
                redirected_host = (urlsplit(redirected).hostname or "").casefold().rstrip(".")
                if redirected_host != original_host:
                    raise UnsafeOutboundURL("Cross-host provider redirect was blocked")
                current_url = redirected
                current_params = None
                continue

            declared_length = upstream.headers.get("content-length")
            if declared_length:
                try:
                    declared_size = int(declared_length)
                except ValueError as exc:
                    raise UnsafeOutboundURL("Provider returned an invalid Content-Length") from exc
                if declared_size < 0:
                    raise UnsafeOutboundURL("Provider returned an invalid Content-Length")
                if declared_size > max_bytes:
                    raise OutboundResponseTooLarge("Provider response exceeded the safety limit")

            content = bytearray()
            async for chunk in upstream.aiter_bytes():
                content.extend(chunk)
                if len(content) > max_bytes:
                    raise OutboundResponseTooLarge("Provider response exceeded the safety limit")

            return httpx.Response(
                status_code=upstream.status_code,
                headers=_decoded_response_headers(upstream.headers),
                content=bytes(content),
                request=upstream.request,
                extensions=upstream.extensions,
            )

    raise UnsafeOutboundURL("Provider redirect limit exceeded")


async def safe_post(
    client: httpx.AsyncClient,
    url: str,
    *,
    allowed_hosts: Iterable[str],
    max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    headers: Mapping[str, str] | None = None,
    json: object | None = None,
    data: Mapping[str, object] | None = None,
) -> httpx.Response:
    """POST to one fixed HTTPS provider without following redirects."""
    if max_bytes < 1:
        raise ValueError("Invalid outbound response limit")
    target = validate_outbound_url(url, allowed_hosts)
    async with client.stream(
        "POST", target, headers=headers, json=json, data=data, follow_redirects=False
    ) as upstream:
        if upstream.status_code in REDIRECT_STATUSES:
            raise UnsafeOutboundURL("Provider POST redirect was blocked")
        declared_length = upstream.headers.get("content-length")
        if declared_length:
            try:
                declared_size = int(declared_length)
            except ValueError as exc:
                raise UnsafeOutboundURL("Provider returned an invalid Content-Length") from exc
            if declared_size < 0:
                raise UnsafeOutboundURL("Provider returned an invalid Content-Length")
            if declared_size > max_bytes:
                raise OutboundResponseTooLarge("Provider response exceeded the safety limit")
        content = bytearray()
        async for chunk in upstream.aiter_bytes():
            content.extend(chunk)
            if len(content) > max_bytes:
                raise OutboundResponseTooLarge("Provider response exceeded the safety limit")
        return httpx.Response(
            status_code=upstream.status_code,
            headers=_decoded_response_headers(upstream.headers),
            content=bytes(content),
            request=upstream.request,
            extensions=upstream.extensions,
        )
