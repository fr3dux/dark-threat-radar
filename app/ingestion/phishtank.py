"""Verified online phishing URLs from PhishTank."""

import logging
import time
from datetime import datetime, timedelta, timezone

import httpx

from app.credential_store import get_provider_secret
from app.database import update_connector_health
from app.ingestion.common import IOCRecord, upsert_ioc_records
from app.ingestion.normalization import TYPE_URL

logger = logging.getLogger("ingestion.phishtank")


async def ingest_phishtank() -> int:
    started = time.time()
    key = get_provider_secret("phishtank")
    if not key:
        await update_connector_health(
            "phishtank", "Phishing", "auth_required",
            last_error="PHISHTANK_API_KEY is not configured",
        )
        return 0
    url = f"https://data.phishtank.com/data/{key}/online-valid.json"
    try:
        async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
            response = await client.get(url, headers={"User-Agent": "DarkThreatRadar/1.10"})
        if response.status_code in {401, 403, 404}:
            await update_connector_health(
                "phishtank", "Phishing", "failed",
                duration_seconds=round(time.time() - started, 2),
                last_error="Credential rejected by PhishTank", http_code=response.status_code,
            )
            return 0
        response.raise_for_status()
        entries = response.json()
        if not isinstance(entries, list):
            raise ValueError("PhishTank returned an unexpected document")
        expires = (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat()
        records = [
            IOCRecord(
                TYPE_URL, str(item.get("url", "")), "phishing",
                source_id=str(item.get("phish_id") or ""),
                first_seen=str(item.get("submission_time") or ""),
                last_seen=str(item.get("verification_time") or ""),
                expires_at=expires,
                source_url="https://data.phishtank.com/", reference_url=str(item.get("phish_detail_url") or ""),
                tags=["phishing", "community-verified"],
                raw={"target": item.get("target"), "verified": item.get("verified")},
            ) for item in entries
        ]
        stats = await upsert_ioc_records("phishtank", records)
        await update_connector_health(
            "phishtank", "Phishing", "healthy",
            duration_seconds=round(time.time() - started, 2),
            items_received=stats["received"], items_created=stats["created"],
            items_updated=stats["updated"], items_dropped=stats["dropped"],
            http_code=response.status_code,
        )
        return stats["created"] + stats["updated"]
    except Exception as exc:
        # The provider key is part of the download path, so never log the
        # exception text or request URL.
        logger.error("PhishTank ingestion failed (%s)", type(exc).__name__)
        await update_connector_health(
            "phishtank", "Phishing", "failed",
            duration_seconds=round(time.time() - started, 2),
            last_error=f"{type(exc).__name__}: PhishTank ingestion failed",
        )
        return 0
