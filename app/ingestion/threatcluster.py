"""Optional authenticated ransomware victim observations from ThreatCluster."""

import logging
import time

import httpx

from app.credential_store import get_provider_secret
from app.database import update_connector_health
from app.ingestion.exposure_incidents import ExposureRecord, upsert_exposure_records

logger = logging.getLogger("ingestion.threatcluster")
API_URL = "https://threatcluster.io/api/public/v1/darkweb/ransomware/victims"


def parse_threatcluster(payload: object) -> list[ExposureRecord]:
    if isinstance(payload, dict):
        items = payload.get("results") or payload.get("items") or payload.get("data") or payload.get("victims") or []
        if isinstance(items, dict):
            items = items.get("results") or items.get("items") or []
    else:
        items = payload
    if not isinstance(items, list):
        return []
    records = []
    for item in items[:1000]:
        if not isinstance(item, dict):
            continue
        victim = str(item.get("victim_name") or item.get("victim") or item.get("company") or item.get("name") or "")
        discovered = str(item.get("discovered") or item.get("discovered_at") or item.get("date") or item.get("published_at") or "")
        group = str(item.get("group_name") or item.get("group") or item.get("actor") or "unknown")
        source_id = str(item.get("id") or item.get("uuid") or item.get("slug") or f"{group}:{victim}:{discovered}")
        if not victim:
            continue
        records.append(ExposureRecord(
            source_record_id=source_id, victim_name=victim, group_name=group,
            country=str(item.get("country") or item.get("country_code") or ""),
            activity=str(item.get("sector") or item.get("industry") or ""),
            domain=str(item.get("domain") or item.get("website") or ""),
            discovered=discovered,
            description=str(item.get("description") or item.get("summary") or ""),
            claim_url=str(item.get("claim_url") or item.get("post_url") or ""),
            reference_url=str(item.get("url") or "https://threatcluster.io/"),
            raw=item,
        ))
    return records


async def ingest_threatcluster() -> int:
    started = time.time()
    key = get_provider_secret("threatcluster")
    if not key:
        await update_connector_health(
            "threatcluster", "Ransomware & Data Breaches", "auth_required",
            last_error="THREATCLUSTER_API_KEY is not configured",
        )
        return 0
    try:
        async with httpx.AsyncClient(timeout=45, follow_redirects=True) as client:
            response = await client.get(
                API_URL, params={"days": 7},
                headers={"X-API-Key": key, "Accept": "application/json", "User-Agent": "DarkThreatRadar/1.13"},
            )
        if response.status_code in {401, 403}:
            await update_connector_health("threatcluster", "Ransomware & Data Breaches", "failed", last_error="Credential rejected by ThreatCluster", http_code=response.status_code)
            return 0
        if response.status_code == 429:
            await update_connector_health("threatcluster", "Ransomware & Data Breaches", "rate_limited", last_error="ThreatCluster rate limit reached", http_code=429)
            return 0
        response.raise_for_status()
        records = parse_threatcluster(response.json())
        stats = await upsert_exposure_records("ThreatCluster", records)
        await update_connector_health(
            "threatcluster", "Ransomware & Data Breaches", "healthy",
            duration_seconds=round(time.time() - started, 2), http_code=response.status_code,
            items_received=stats["received"], items_created=stats["created"],
            items_updated=stats["updated"], items_dropped=stats["dropped"],
            items_duplicated=stats["duplicated"],
        )
        return stats["created"] + stats["updated"]
    except Exception as exc:
        logger.exception("ThreatCluster ingestion failed")
        await update_connector_health(
            "threatcluster", "Ransomware & Data Breaches", "failed",
            duration_seconds=round(time.time() - started, 2),
            last_error=f"{type(exc).__name__}: ThreatCluster ingestion failed",
        )
        return 0
