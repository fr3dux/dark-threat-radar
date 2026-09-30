"""ThreatFox Ingestion Module (abuse.ch)
Collects IPs, domains, URLs, hashes, threat types, malware families, and tags.
Uses THREATFOX_AUTH_KEY from environment variables.
"""

import httpx
import logging
import time
from datetime import datetime, timezone
from typing import Dict, Any

from app.config import THREATFOX_AUTH_KEY
from app.database import get_db, update_connector_health
from app.ingestion.normalization import (
    normalize_indicator, generate_ioc_id,
    TYPE_IPV4, TYPE_IPV6, TYPE_DOMAIN, TYPE_URL, TYPE_SHA256, TYPE_MD5, TYPE_JA3
)
from app.ingestion.confidence import calculate_confidence, get_confidence_severity_label

logger = logging.getLogger("ingestion.threatfox")

API_URL = "https://threatfox-api.abuse.ch/api/v1/"

TYPE_MAP = {
    "ip:port": TYPE_IPV4,
    "domain": TYPE_DOMAIN,
    "url": TYPE_URL,
    "md5_hash": TYPE_MD5,
    "sha256_hash": TYPE_SHA256,
    "ja3_fingerprint": TYPE_JA3,
}


async def ingest_threatfox() -> int:
    """Fetch active IOCs from ThreatFox API and store in normalized_iocs."""
    start_time = time.time()
    source_name = "threatfox"
    category = "Malware & IOCs"

    headers = {
        "User-Agent": "DarkThreatRadar/1.8.1",
        "Content-Type": "application/json"
    }
    if THREATFOX_AUTH_KEY:
        headers["Auth-Key"] = THREATFOX_AUTH_KEY

    payload = {"query": "get_iocs", "days": 1}

    items_received = 0
    items_created = 0
    items_updated = 0
    items_dropped = 0
    last_error = None
    http_code = None

    if not THREATFOX_AUTH_KEY:
        await update_connector_health(
            source_name,
            category,
            "auth_required",
            last_error="THREATFOX_AUTH_KEY is not configured",
        )
        return 0

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
            resp = await client.post(API_URL, json=payload, headers=headers)
            http_code = resp.status_code

            if resp.status_code != 200:
                last_error = f"HTTP {resp.status_code}"
                state = "auth_required" if resp.status_code in (401, 403) else "failed"
                await update_connector_health(
                    source_name, category, state,
                    duration_seconds=round(time.time() - start_time, 2),
                    last_error=last_error, http_code=http_code
                )
                return 0

            data = resp.json()
            if data.get("query_status") != "ok":
                last_error = f"API query status: {data.get('query_status')}"
                state = "auth_required" if "auth" in last_error.lower() else "degraded"
                await update_connector_health(
                    source_name, category, state,
                    duration_seconds=round(time.time() - start_time, 2),
                    last_error=last_error, http_code=http_code
                )
                return 0

            iocs = data.get("data") or []
            items_received = len(iocs)
            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            async with get_db() as conn:
                for item in iocs:
                    raw_type = item.get("ioc_type", "").lower()
                    target_type = TYPE_MAP.get(raw_type, TYPE_DOMAIN)
                    raw_val = item.get("ioc", "")

                    if raw_type == "ip:port" and raw_val.startswith("[") and "]:" in raw_val:
                        ip_part, port_part = raw_val[1:].rsplit("]:", 1)
                    elif raw_type == "ip:port" and raw_val.count(":") == 1:
                        ip_part, port_part = raw_val.rsplit(":", 1)
                    else:
                        ip_part = raw_val
                        port_part = None

                    norm_val, detected_type = normalize_indicator(target_type, ip_part)
                    if not norm_val or not detected_type:
                        items_dropped += 1
                        continue

                    ioc_id = generate_ioc_id(detected_type, norm_val)
                    malware_family = item.get("malware_printable") or item.get("fk_malware_handle") or "Unknown"
                    threat_type = item.get("threat_type") or "malware_ioc"
                    tags = ",".join(item.get("tags") or [])
                    first_seen = item.get("first_seen") or now_str
                    last_seen = item.get("last_seen") or first_seen
                    confidence = calculate_confidence("threatfox", detected_type, active=True)
                    severity = get_confidence_severity_label(confidence)
                    reference = item.get("reference") or "https://threatfox.abuse.ch/"

                    port_num = int(port_part) if port_part and port_part.isdigit() else None

                    # Upsert normalized_iocs
                    cur = await conn.execute("SELECT id, first_seen FROM normalized_iocs WHERE id = ?;", (ioc_id,))
                    existing = await cur.fetchone()

                    if existing:
                        items_updated += 1
                        earliest_fs = existing["first_seen"] if existing["first_seen"] < first_seen else first_seen
                        await conn.execute("""
                            UPDATE normalized_iocs SET
                                last_seen = ?,
                                active = 1,
                                confidence = MAX(confidence, ?),
                                malware_family = COALESCE(NULLIF(malware_family, 'Unknown'), ?),
                                tags = COALESCE(tags, ?),
                                updated_at = ?
                            WHERE id = ?;
                        """, (last_seen, confidence, malware_family, tags, now_str, ioc_id))
                    else:
                        items_created += 1
                        await conn.execute("""
                            INSERT INTO normalized_iocs (
                                id, indicator_type, indicator_value, normalized_value,
                                threat_type, malware_family, confidence, severity,
                                source_name, source_id, source_url, reference_url,
                                first_seen, last_seen, ingested_at, updated_at, active, tags, port
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?);
                        """, (
                            ioc_id, detected_type, raw_val, norm_val,
                            threat_type, malware_family, confidence, severity,
                            "threatfox", str(item.get("id")), "https://threatfox.abuse.ch/api/", reference,
                            first_seen, last_seen, now_str, now_str, tags, port_num
                        ))

                    # Insert source correlation
                    await conn.execute("""
                        INSERT INTO ioc_sources (ioc_id, source_name, source_id, first_seen, last_seen, confidence)
                        VALUES (?, 'threatfox', ?, ?, ?, ?)
                        ON CONFLICT(ioc_id, source_name) DO UPDATE SET
                            last_seen = excluded.last_seen,
                            confidence = excluded.confidence;
                    """, (ioc_id, str(item.get("id")), first_seen, last_seen, confidence))

                await conn.commit()

        duration = round(time.time() - start_time, 2)
        await update_connector_health(
            source_name, category, "healthy",
            duration_seconds=duration,
            items_received=items_received,
            items_created=items_created,
            items_updated=items_updated,
            items_dropped=items_dropped,
            http_code=http_code
        )
        logger.info(f"ThreatFox ingested {items_created} new, {items_updated} updated IOCs in {duration}s")
        return items_created + items_updated

    except Exception as e:
        last_error = f"{type(e).__name__}: ThreatFox ingestion failed"
        logger.error("ThreatFox ingestion error (%s)", type(e).__name__)
        await update_connector_health(
            source_name, category, "failed",
            duration_seconds=round(time.time() - start_time, 2),
            last_error=last_error
        )
        return 0
