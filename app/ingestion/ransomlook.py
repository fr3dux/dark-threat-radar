"""Recent public leak-site observations from RansomLook."""

import logging
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import httpx

from app.database import update_connector_health
from app.ingestion.exposure_incidents import ExposureRecord, upsert_exposure_records

logger = logging.getLogger("ingestion.ransomlook")
API_URL = "https://www.ransomlook.io/api/recent"
RANSOMLOOK_TIMEZONE = ZoneInfo("Europe/Paris")


def normalize_ransomlook_timestamp(value: object) -> str:
    """Convert RansomLook's timezone-less Europe/Paris timestamps to UTC."""
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=RANSOMLOOK_TIMEZONE)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_ransomlook(payload: object) -> list[ExposureRecord]:
    if isinstance(payload, dict):
        items = payload.get("posts") or payload.get("results") or payload.get("data") or []
    else:
        items = payload
    if not isinstance(items, list):
        return []
    records = []
    for item in items[:1000]:
        if not isinstance(item, dict):
            continue
        victim = str(item.get("post_title") or item.get("title") or item.get("victim") or "")
        group = str(item.get("group_name") or item.get("group") or item.get("gang") or "unknown")
        discovered = normalize_ransomlook_timestamp(
            item.get("discovered") or item.get("date") or item.get("published")
        )
        source_id = str(item.get("misp_uuid") or item.get("id") or item.get("uuid") or item.get("post_url") or f"{group}:{victim}:{discovered}")
        if not victim:
            continue
        records.append(ExposureRecord(
            source_record_id=source_id, victim_name=victim, group_name=group,
            country=str(item.get("country") or ""),
            activity=str(item.get("activity") or item.get("sector") or ""),
            domain=str(item.get("domain") or item.get("website") or item.get("link") or ""),
            discovered=discovered,
            description=str(item.get("description") or item.get("content") or ""),
            claim_url=str(item.get("post_url") or item.get("url") or ""),
            reference_url="https://www.ransomlook.io/recent",
            raw=item,
        ))
    return records


async def ingest_ransomlook() -> int:
    started = time.time()
    try:
        async with httpx.AsyncClient(timeout=45, follow_redirects=True) as client:
            response = await client.get(API_URL, headers={"Accept": "application/json", "User-Agent": "DarkThreatRadar/1.13"})
        if response.status_code == 429:
            await update_connector_health("ransomlook", "Ransomware & Data Breaches", "rate_limited", last_error="RansomLook rate limit reached", http_code=429)
            return 0
        response.raise_for_status()
        records = parse_ransomlook(response.json())
        if not records:
            raise ValueError("RansomLook returned no valid recent records")
        stats = await upsert_exposure_records("RansomLook", records)
        await update_connector_health(
            "ransomlook", "Ransomware & Data Breaches", "healthy",
            duration_seconds=round(time.time() - started, 2), http_code=response.status_code,
            items_received=stats["received"], items_created=stats["created"],
            items_updated=stats["updated"], items_dropped=stats["dropped"],
            items_duplicated=stats["duplicated"],
        )
        return stats["created"] + stats["updated"]
    except Exception as exc:
        logger.exception("RansomLook ingestion failed")
        await update_connector_health(
            "ransomlook", "Ransomware & Data Breaches", "failed",
            duration_seconds=round(time.time() - started, 2),
            last_error=f"{type(exc).__name__}: RansomLook ingestion failed",
        )
        return 0
