"""Recent attacker IPs observed by blocklist.de sensors."""

import logging
import time
from datetime import datetime, timedelta, timezone

import httpx

from app.database import update_connector_health
from app.ingestion.common import IOCRecord, upsert_ioc_records
from app.ingestion.normalization import TYPE_IPV4

logger = logging.getLogger("ingestion.blocklist_de")
FEED_URL = "https://lists.blocklist.de/lists/all.txt"


async def ingest_blocklist_de() -> int:
    started = time.time()
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            response = await client.get(FEED_URL, headers={"User-Agent": "DarkThreatRadar/1.10"})
            response.raise_for_status()
        now = datetime.now(timezone.utc)
        expires = (now + timedelta(hours=49)).isoformat()
        records = [
            IOCRecord(
                TYPE_IPV4, line.strip(), "recent_attacker", expires_at=expires,
                source_url=FEED_URL, reference_url="https://www.blocklist.de/en/export.html",
                tags=["scanner", "brute-force"], raw={"window": "48h"},
            )
            for line in response.text.splitlines()
            if line.strip() and not line.startswith("#")
        ]
        stats = await upsert_ioc_records("blocklist_de", records)
        await update_connector_health(
            "blocklist_de", "Network Intelligence", "healthy",
            duration_seconds=round(time.time() - started, 2),
            items_received=stats["received"], items_created=stats["created"],
            items_updated=stats["updated"], items_dropped=stats["dropped"],
            http_code=response.status_code,
        )
        return stats["created"] + stats["updated"]
    except Exception as exc:
        logger.exception("blocklist.de ingestion failed")
        await update_connector_health(
            "blocklist_de", "Network Intelligence", "failed",
            duration_seconds=round(time.time() - started, 2),
            last_error=f"{type(exc).__name__}: blocklist.de ingestion failed",
        )
        return 0
