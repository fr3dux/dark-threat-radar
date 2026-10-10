"""Recent ransomware leak-site disclosures from the public RansomFeed API."""

import logging
import time

import httpx

from app.database import update_connector_health
from app.ingestion.exposure_incidents import ExposureRecord, upsert_exposure_records

logger = logging.getLogger("ingestion.ransomfeed")
API_URL = "https://api.ransomfeed.it/"


def parse_ransomfeed(payload: object) -> list[ExposureRecord]:
    items = payload if isinstance(payload, list) else []
    records = []
    for item in items[:1000]:
        if not isinstance(item, dict):
            continue
        source_id = str(item.get("hash") or item.get("id") or "")
        victim = str(item.get("victim") or "")
        if not source_id or not victim:
            continue
        records.append(ExposureRecord(
            source_record_id=source_id, victim_name=victim,
            group_name=str(item.get("gang") or "unknown"),
            country=str(item.get("country") or ""),
            activity=str(item.get("work_sector") or ""),
            domain=str(item.get("website") or ""),
            discovered=str(item.get("date") or ""),
            description=str(item.get("description") or item.get("victim_notes") or ""),
            reference_url="https://ransomfeed.it/",
            raw=item,
        ))
    return records


async def ingest_ransomfeed() -> int:
    started = time.time()
    try:
        async with httpx.AsyncClient(timeout=45, follow_redirects=True) as client:
            response = await client.get(API_URL, headers={"Accept": "application/json", "User-Agent": "DarkThreatRadar/1.13"})
        if response.status_code == 429:
            await update_connector_health("ransomfeed", "Ransomware & Data Breaches", "rate_limited", last_error="RansomFeed rate limit reached", http_code=429)
            return 0
        response.raise_for_status()
        records = parse_ransomfeed(response.json())
        stats = await upsert_exposure_records("RansomFeed", records)
        await update_connector_health(
            "ransomfeed", "Ransomware & Data Breaches", "healthy",
            duration_seconds=round(time.time() - started, 2), http_code=response.status_code,
            items_received=stats["received"], items_created=stats["created"],
            items_updated=stats["updated"], items_dropped=stats["dropped"],
            items_duplicated=stats["duplicated"],
        )
        return stats["created"] + stats["updated"]
    except Exception as exc:
        logger.exception("RansomFeed ingestion failed")
        await update_connector_health(
            "ransomfeed", "Ransomware & Data Breaches", "failed",
            duration_seconds=round(time.time() - started, 2),
            last_error=f"{type(exc).__name__}: RansomFeed ingestion failed",
        )
        return 0
