"""High-confidence malicious IP feed from AbuseIPDB."""

import logging
import time
from datetime import datetime, timedelta, timezone

import httpx

from app.config import ABUSEIPDB_INTERVAL_SECONDS
from app.credential_store import get_provider_secret
from app.database import get_connector_health, update_connector_health
from app.ingestion.common import IOCRecord, upsert_ioc_records
from app.ingestion.normalization import TYPE_IPV4

logger = logging.getLogger("ingestion.abuseipdb")
API_URL = "https://api.abuseipdb.com/api/v2/blacklist"


def _rate_limit_summary(headers: httpx.Headers) -> str | None:
    values = []
    for header, label in (
        ("x-ratelimit-remaining", "remaining"),
        ("x-ratelimit-limit", "limit"),
        ("x-ratelimit-reset", "reset"),
        ("retry-after", "retry_after"),
    ):
        value = headers.get(header)
        if value:
            values.append(f"{label}={value}")
    return "; ".join(values) or None


def _reset_at(rate_limit_info: str | None) -> datetime | None:
    for item in (rate_limit_info or "").split(";"):
        key, separator, value = item.strip().partition("=")
        if separator and key == "reset":
            try:
                return datetime.fromtimestamp(float(value), tz=timezone.utc)
            except (OverflowError, TypeError, ValueError):
                return None
    return None


def request_is_due(health: dict | None, now: datetime | None = None) -> bool:
    """Protect the provider's daily quota across restarts and manual syncs."""
    if not health or health.get("http_code") is None:
        return True

    current = now or datetime.now(timezone.utc)
    if health.get("state") == "rate_limited":
        reset = _reset_at(health.get("rate_limit_info"))
        if reset is not None:
            return current >= reset

    last_attempt_value = health.get("last_attempt")
    if not last_attempt_value:
        return True
    try:
        last_attempt = datetime.strptime(
            last_attempt_value, "%Y-%m-%d %H:%M:%S UTC"
        ).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return True
    return current >= last_attempt + timedelta(seconds=ABUSEIPDB_INTERVAL_SECONDS)


async def ingest_abuseipdb() -> int:
    started = time.time()
    key = get_provider_secret("abuseipdb")
    if not key:
        await update_connector_health(
            "abuseipdb", "Network Intelligence", "auth_required",
            last_error="ABUSEIPDB_API_KEY is not configured",
        )
        return 0
    health = await get_connector_health("abuseipdb")
    if not request_is_due(health):
        logger.info("AbuseIPDB request deferred to preserve the daily blacklist quota")
        return 0
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            response = await client.get(
                API_URL,
                params={"confidenceMinimum": 90, "limit": 10000},
                headers={"Key": key, "Accept": "application/json", "User-Agent": "DarkThreatRadar/1.10"},
            )
        if response.status_code in {401, 403}:
            await update_connector_health(
                "abuseipdb", "Network Intelligence", "failed",
                duration_seconds=round(time.time() - started, 2),
                last_error="Credential rejected by AbuseIPDB", http_code=response.status_code,
            )
            return 0
        if response.status_code == 429:
            rate_limit_info = _rate_limit_summary(response.headers)
            reset = _reset_at(rate_limit_info)
            retry_message = (
                f"; retry after {reset.strftime('%Y-%m-%d %H:%M:%S UTC')}"
                if reset else ""
            )
            await update_connector_health(
                "abuseipdb", "Network Intelligence", "rate_limited",
                duration_seconds=round(time.time() - started, 2),
                last_error=f"AbuseIPDB daily quota reached{retry_message}",
                http_code=429,
                rate_limit_info=rate_limit_info,
            )
            return 0
        response.raise_for_status()
        expires = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
        entries = response.json().get("data") or []
        records = [
            IOCRecord(
                TYPE_IPV4, str(item.get("ipAddress", "")), "abusive_host",
                country=str(item.get("countryCode") or ""), expires_at=expires,
                source_url=API_URL, reference_url="https://www.abuseipdb.com/",
                tags=["reputation", "abuse"], raw={
                    "confidence": item.get("abuseConfidenceScore"),
                    "reports": item.get("totalReports"),
                    "last_reported": item.get("lastReportedAt"),
                },
            ) for item in entries
        ]
        stats = await upsert_ioc_records("abuseipdb", records)
        await update_connector_health(
            "abuseipdb", "Network Intelligence", "healthy",
            duration_seconds=round(time.time() - started, 2),
            items_received=stats["received"], items_created=stats["created"],
            items_updated=stats["updated"], items_dropped=stats["dropped"],
            http_code=response.status_code,
            rate_limit_info=_rate_limit_summary(response.headers),
        )
        return stats["created"] + stats["updated"]
    except Exception as exc:
        logger.exception("AbuseIPDB ingestion failed")
        await update_connector_health(
            "abuseipdb", "Network Intelligence", "failed",
            duration_seconds=round(time.time() - started, 2),
            last_error=f"{type(exc).__name__}: AbuseIPDB ingestion failed",
        )
        return 0
