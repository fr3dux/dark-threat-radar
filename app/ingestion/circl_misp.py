"""Recent TLP:CLEAR events from the public CIRCL MISP OSINT feed."""

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone

import httpx

from app.database import update_connector_health
from app.ingestion.common import IOCRecord, upsert_ioc_records
from app.ingestion.normalization import (
    TYPE_DOMAIN, TYPE_HOSTNAME, TYPE_IPV4, TYPE_IPV6, TYPE_MD5,
    TYPE_SHA1, TYPE_SHA256, TYPE_URL,
)

logger = logging.getLogger("ingestion.circl_misp")
FEED_URL = "https://www.circl.lu/doc/misp/feed-osint/"
TYPE_MAP = {
    "ip-src": TYPE_IPV4, "ip-dst": TYPE_IPV4,
    "ip-src|port": TYPE_IPV4, "ip-dst|port": TYPE_IPV4,
    "domain": TYPE_DOMAIN, "domain|ip": TYPE_DOMAIN,
    "hostname": TYPE_HOSTNAME, "url": TYPE_URL,
    "md5": TYPE_MD5, "sha1": TYPE_SHA1, "sha256": TYPE_SHA256,
}


def _event_attributes(event: dict) -> list[dict]:
    attributes = list(event.get("Attribute") or [])
    for obj in event.get("Object") or []:
        attributes.extend(obj.get("Attribute") or [])
    return attributes


async def ingest_circl_misp() -> int:
    started = time.time()
    try:
        async with httpx.AsyncClient(timeout=45, follow_redirects=True) as client:
            manifest_response = await client.get(
                f"{FEED_URL}manifest.json", headers={"User-Agent": "DarkThreatRadar/1.10"}
            )
            manifest_response.raise_for_status()
            manifest = manifest_response.json()
            if not isinstance(manifest, dict):
                raise ValueError("CIRCL manifest is not a JSON object")
            ordered = sorted(
                manifest.items(),
                key=lambda item: str((item[1] or {}).get("timestamp", "")) if isinstance(item[1], dict) else "",
                reverse=True,
            )[:10]

            async def fetch_event(event_id: str) -> dict | None:
                response = await client.get(f"{FEED_URL}{event_id}.json")
                if response.status_code != 200 or len(response.content) > 5_000_000:
                    return None
                return response.json()

            documents = await asyncio.gather(
                *(fetch_event(str(event_id)) for event_id, _metadata in ordered),
                return_exceptions=True,
            )
            events = [item for item in documents if isinstance(item, dict)]

        expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        records: list[IOCRecord] = []
        for document in events:
            event = document.get("Event") or document
            event_id = str(event.get("uuid") or event.get("id") or "")
            event_info = str(event.get("info") or "CIRCL MISP event")
            event_tags = [
                str((tag.get("Tag") or {}).get("name") or tag.get("name") or "")[:80]
                for tag in (event.get("Tag") or []) if isinstance(tag, dict)
            ]
            for attribute in _event_attributes(event):
                misp_type = str(attribute.get("type") or "")
                indicator_type = TYPE_MAP.get(misp_type)
                value = str(attribute.get("value") or "")
                if not indicator_type or not value or not attribute.get("to_ids", True):
                    continue
                if "|" in misp_type and "|" in value:
                    value = value.split("|", 1)[0]
                records.append(IOCRecord(
                    indicator_type, value, str(attribute.get("category") or "misp_indicator").lower(),
                    source_id=str(attribute.get("uuid") or event_id),
                    first_seen=str(attribute.get("first_seen") or event.get("date") or ""),
                    last_seen=str(attribute.get("last_seen") or event.get("date") or ""),
                    expires_at=expires, source_url=FEED_URL,
                    reference_url=f"https://www.circl.lu/doc/misp/feed-osint/{event_id}.json",
                    tags=event_tags, raw={"event": event_info, "misp_type": misp_type},
                ))
        stats = await upsert_ioc_records("circl_misp", records)
        state = "healthy" if events else "degraded"
        await update_connector_health(
            "circl_misp", "Malware & IOCs", state,
            duration_seconds=round(time.time() - started, 2),
            items_received=stats["received"], items_created=stats["created"],
            items_updated=stats["updated"], items_dropped=stats["dropped"],
            http_code=manifest_response.status_code,
            last_error=None if events else "No recent MISP events could be retrieved",
        )
        return stats["created"] + stats["updated"]
    except Exception as exc:
        logger.exception("CIRCL MISP ingestion failed")
        await update_connector_health(
            "circl_misp", "Malware & IOCs", "failed",
            duration_seconds=round(time.time() - started, 2),
            last_error=f"{type(exc).__name__}: CIRCL MISP ingestion failed",
        )
        return 0
