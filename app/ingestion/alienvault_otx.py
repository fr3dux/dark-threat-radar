"""Subscribed AlienVault OTX pulses and their public indicators."""

import logging
import time
from datetime import datetime, timedelta, timezone

import httpx

from app.http_security import safe_get

from app.credential_store import get_provider_secret
from app.database import update_connector_health
from app.ingestion.common import IOCRecord, upsert_ioc_records
from app.ingestion.normalization import (
    TYPE_CVE, TYPE_DOMAIN, TYPE_HOSTNAME, TYPE_IPV4, TYPE_IPV6,
    TYPE_MD5, TYPE_SHA1, TYPE_SHA256, TYPE_URL,
)

logger = logging.getLogger("ingestion.alienvault_otx")
API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
TYPE_MAP = {
    "IPv4": TYPE_IPV4, "IPv6": TYPE_IPV6,
    "domain": TYPE_DOMAIN, "hostname": TYPE_HOSTNAME,
    "URL": TYPE_URL, "URI": TYPE_URL,
    "FileHash-MD5": TYPE_MD5, "FileHash-SHA1": TYPE_SHA1,
    "FileHash-SHA256": TYPE_SHA256, "CVE": TYPE_CVE,
}


async def ingest_alienvault_otx() -> int:
    started = time.time()
    key = get_provider_secret("alienvault_otx")
    if not key:
        await update_connector_health(
            "alienvault_otx", "Malware & IOCs", "auth_required",
            last_error="OTX_API_KEY is not configured",
        )
        return 0
    modified_since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    try:
        async with httpx.AsyncClient(timeout=45) as client:
            response = await safe_get(
                client,
                API_URL,
                allowed_hosts={"otx.alienvault.com"},
                max_bytes=10 * 1024 * 1024,
                params={"modified_since": modified_since, "limit": 50},
                headers={"X-OTX-API-KEY": key, "User-Agent": "DarkThreatRadar/1.10"},
            )
        if response.status_code in {401, 403}:
            await update_connector_health(
                "alienvault_otx", "Malware & IOCs", "failed",
                duration_seconds=round(time.time() - started, 2),
                last_error="Credential rejected by AlienVault OTX", http_code=response.status_code,
            )
            return 0
        if response.status_code == 429:
            await update_connector_health(
                "alienvault_otx", "Malware & IOCs", "rate_limited",
                duration_seconds=round(time.time() - started, 2),
                last_error="AlienVault OTX rate limit reached", http_code=429,
            )
            return 0
        response.raise_for_status()
        payload = response.json()
        pulses = payload.get("results") or []
        records: list[IOCRecord] = []
        for pulse in pulses:
            pulse_id = str(pulse.get("id") or "")
            pulse_name = str(pulse.get("name") or "OTX pulse")
            tags = [str(tag)[:80] for tag in (pulse.get("tags") or [])[:20]]
            malware_names = pulse.get("malware_families") or []
            malware_family = ""
            if malware_names:
                first = malware_names[0]
                malware_family = str(first.get("display_name") if isinstance(first, dict) else first)
            for indicator in pulse.get("indicators") or []:
                indicator_type = TYPE_MAP.get(str(indicator.get("type") or ""))
                value = str(indicator.get("indicator") or "")
                if not indicator_type or not value:
                    continue
                records.append(IOCRecord(
                    indicator_type, value, "otx_pulse", source_id=pulse_id,
                    malware_family=malware_family,
                    first_seen=str(indicator.get("created") or pulse.get("created") or ""),
                    last_seen=str(indicator.get("modified") or pulse.get("modified") or ""),
                    expires_at=str(indicator.get("expiration") or ""),
                    source_url=API_URL,
                    reference_url=f"https://otx.alienvault.com/pulse/{pulse_id}",
                    tags=tags, tlp=str(pulse.get("TLP") or "CLEAR").upper(),
                    active=bool(indicator.get("is_active", True)),
                    raw={"pulse": pulse_name, "adversary": pulse.get("adversary")},
                ))
        stats = await upsert_ioc_records("alienvault_otx", records)
        await update_connector_health(
            "alienvault_otx", "Malware & IOCs", "healthy",
            duration_seconds=round(time.time() - started, 2),
            items_received=stats["received"], items_created=stats["created"],
            items_updated=stats["updated"], items_dropped=stats["dropped"],
            http_code=response.status_code,
        )
        return stats["created"] + stats["updated"]
    except httpx.HTTPStatusError as exc:
        status_code = exc.response.status_code if exc.response is not None else None
        provider_outage = status_code is not None and status_code >= 500
        state = "degraded" if provider_outage else "failed"
        error = (
            f"AlienVault OTX temporarily unavailable (HTTP {status_code})"
            if provider_outage
            else f"AlienVault OTX request failed (HTTP {status_code or 'unknown'})"
        )
        logger.warning(error)
        await update_connector_health(
            "alienvault_otx", "Malware & IOCs", state,
            duration_seconds=round(time.time() - started, 2),
            last_error=error, http_code=status_code,
        )
        return 0
    except httpx.RequestError as exc:
        logger.warning("AlienVault OTX network request failed: %s", type(exc).__name__)
        await update_connector_health(
            "alienvault_otx", "Malware & IOCs", "degraded",
            duration_seconds=round(time.time() - started, 2),
            last_error=f"AlienVault OTX network request failed: {type(exc).__name__}",
        )
        return 0
    except Exception as exc:
        logger.exception("AlienVault OTX ingestion failed")
        await update_connector_health(
            "alienvault_otx", "Malware & IOCs", "failed",
            duration_seconds=round(time.time() - started, 2),
            last_error=f"{type(exc).__name__}: AlienVault OTX ingestion failed",
        )
        return 0
