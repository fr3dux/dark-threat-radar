"""Public non-ransomware breach and exfiltration reporting from DataBreaches.net."""

import hashlib
import logging
import re
import time

import feedparser
import httpx

from app.database import update_connector_health
from app.ingestion.exposure_incidents import ExposureRecord, upsert_exposure_records

logger = logging.getLogger("ingestion.databreaches_net")
FEED_URL = "https://databreaches.net/feed/"


def _plain_text(value: str) -> str:
    return " ".join(re.sub(r"<[^>]+>", " ", value or "").split())[:8000]


def parse_databreaches_feed(payload: bytes) -> list[ExposureRecord]:
    feed = feedparser.parse(payload)
    records = []
    for item in feed.entries[:200]:
        title = _plain_text(str(item.get("title") or ""))
        link = str(item.get("link") or "")
        published = str(item.get("published") or item.get("updated") or "")
        source_id = str(item.get("id") or item.get("guid") or link)
        if not source_id:
            source_id = hashlib.sha256(f"{title}\0{published}".encode()).hexdigest()
        if not title:
            continue
        records.append(ExposureRecord(
            source_record_id=source_id, victim_name=title,
            group_name="data breach", incident_type="data_breach",
            discovered=published,
            description=_plain_text(str(item.get("summary") or item.get("description") or "")),
            reference_url=link, raw=dict(item),
        ))
    return records


async def ingest_databreaches_net() -> int:
    started = time.time()
    try:
        async with httpx.AsyncClient(timeout=45, follow_redirects=True) as client:
            response = await client.get(FEED_URL, headers={"Accept": "application/rss+xml, application/xml", "User-Agent": "DarkThreatRadar/1.13"})
        response.raise_for_status()
        if len(response.content) > 5_000_000:
            raise ValueError("DataBreaches.net feed exceeded the 5 MB safety limit")
        records = parse_databreaches_feed(response.content)
        if not records:
            raise ValueError("DataBreaches.net returned no valid feed records")
        stats = await upsert_exposure_records("DataBreaches.net", records)
        await update_connector_health(
            "databreaches_net", "Ransomware & Data Breaches", "healthy",
            duration_seconds=round(time.time() - started, 2), http_code=response.status_code,
            items_received=stats["received"], items_created=stats["created"],
            items_updated=stats["updated"], items_dropped=stats["dropped"],
            items_duplicated=stats["duplicated"],
        )
        return stats["created"] + stats["updated"]
    except Exception as exc:
        logger.exception("DataBreaches.net ingestion failed")
        await update_connector_health(
            "databreaches_net", "Ransomware & Data Breaches", "failed",
            duration_seconds=round(time.time() - started, 2),
            last_error=f"{type(exc).__name__}: DataBreaches.net ingestion failed",
        )
        return 0
