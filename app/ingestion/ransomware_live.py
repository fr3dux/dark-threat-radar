"""Ransomware.live v2 connector backed by canonical exposure correlation."""

import hashlib
import logging
import time
from typing import Any

import httpx

from app.database import update_connector_health, update_feed_status
from app.ingestion.exposure_incidents import ExposureRecord, upsert_exposure_records

logger = logging.getLogger("ingestion.ransomware_live")
RECENT_VICTIMS_URL = "https://api.ransomware.live/v2/recentvictims"
BRAZIL_VICTIMS_URL = "https://api.ransomware.live/v2/countryvictims/BR"


def generate_victim_id(item: dict[str, Any]) -> str:
    if item.get("id"):
        return str(item["id"]).strip()
    url = str(item.get("url") or "")
    if "/id/" in url:
        return url.rstrip("/").split("/")[-1]
    material = "\0".join(str(item.get(key) or "") for key in ("victim", "group", "discovered", "country"))
    return hashlib.sha256(material.encode()).hexdigest()[:24]


def parse_ransomware_live(items: list[dict[str, Any]]) -> list[ExposureRecord]:
    records = []
    for item in items:
        victim = str(item.get("victim") or item.get("victim_name") or "")
        if not victim.strip():
            continue
        records.append(ExposureRecord(
            source_record_id=generate_victim_id(item), victim_name=victim,
            group_name=str(item.get("group") or item.get("group_name") or "unknown"),
            country=str(item.get("country") or ""), activity=str(item.get("activity") or ""),
            domain=str(item.get("domain") or item.get("website") or ""),
            discovered=str(item.get("discovered") or item.get("attackdate") or ""),
            attackdate=str(item.get("attackdate") or ""),
            description=str(item.get("description") or ""),
            claim_url=str(item.get("claim_url") or ""), screenshot=str(item.get("screenshot") or ""),
            reference_url=str(item.get("url") or "https://www.ransomware.live/"), raw=item,
        ))
    return records


async def fetch_endpoint(client: httpx.AsyncClient, url: str) -> list[dict[str, Any]]:
    response = await client.get(url, follow_redirects=True)
    response.raise_for_status()
    payload = response.json()
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict) and isinstance(payload.get("victims"), list):
        return [item for item in payload["victims"] if isinstance(item, dict)]
    raise ValueError("Ransomware.live returned an unexpected response schema")


async def ingest_ransomware_live() -> int:
    started = time.time()
    await update_feed_status("ransomware_live", "running", 0, "Ingesting Ransomware.live v2 catalog...")
    try:
        headers = {"User-Agent": "DarkThreatRadar/1.13", "Accept": "application/json"}
        async with httpx.AsyncClient(timeout=30, headers=headers) as client:
            recent = await fetch_endpoint(client, RECENT_VICTIMS_URL)
            brazil = await fetch_endpoint(client, BRAZIL_VICTIMS_URL)
        for item in brazil:
            item.setdefault("country", "BR")
        records = parse_ransomware_live(recent + brazil)
        stats = await upsert_exposure_records("Ransomware.live", records)
        total = stats["created"] + stats["updated"]
        message = f"Correlated {len(records)} Ransomware.live observations."
        await update_feed_status("ransomware_live", "success", len(records), message)
        await update_connector_health(
            "ransomware_live", "Ransomware & Data Breaches", "healthy",
            duration_seconds=round(time.time() - started, 2), items_received=stats["received"],
            items_created=stats["created"], items_updated=stats["updated"],
            items_dropped=stats["dropped"], items_duplicated=stats["duplicated"], http_code=200,
        )
        return total
    except Exception as exc:
        logger.exception("Ransomware.live ingestion failed")
        message = f"{type(exc).__name__}: Ransomware.live ingestion failed"
        await update_feed_status("ransomware_live", "error", 0, message)
        await update_connector_health(
            "ransomware_live", "Ransomware & Data Breaches", "failed",
            duration_seconds=round(time.time() - started, 2), last_error=message,
        )
        return 0
