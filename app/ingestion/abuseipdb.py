"""High-confidence malicious IP feed from AbuseIPDB."""

import logging
import time
from datetime import datetime, timedelta, timezone

import httpx

from app.credential_store import get_provider_secret
from app.database import update_connector_health
from app.ingestion.common import IOCRecord, upsert_ioc_records
from app.ingestion.normalization import TYPE_IPV4

logger = logging.getLogger("ingestion.abuseipdb")
API_URL = "https://api.abuseipdb.com/api/v2/blacklist"


async def ingest_abuseipdb() -> int:
    started = time.time()
    key = get_provider_secret("abuseipdb")
    if not key:
        await update_connector_health(
            "abuseipdb", "Network Intelligence", "auth_required",
            last_error="ABUSEIPDB_API_KEY is not configured",
        )
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
            await update_connector_health(
                "abuseipdb", "Network Intelligence", "rate_limited",
                duration_seconds=round(time.time() - started, 2),
                last_error="AbuseIPDB daily quota reached", http_code=429,
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
            rate_limit_info=response.headers.get("x-ratelimit-remaining"),
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
