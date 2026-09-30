"""Feodo Tracker Ingestion Module (abuse.ch)
Collects active botnet C2 servers (IP, port, malware family, first/last seen, status).
Source: https://feodotracker.abuse.ch/downloads/ipblocklist.json
"""

import httpx
import logging
import time
from datetime import datetime, timezone

from app.database import get_db, update_connector_health
from app.ingestion.normalization import (
    normalize_ip, generate_ioc_id, TYPE_IPV4
)
from app.ingestion.confidence import calculate_confidence, get_confidence_severity_label

logger = logging.getLogger("ingestion.feodo_tracker")

BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


async def ingest_feodo_tracker() -> int:
    """Fetch active botnet C2 blocklist from Feodo Tracker."""
    start_time = time.time()
    source_name = "feodo_tracker"
    category = "Network Intelligence"

    items_received = 0
    items_created = 0
    items_updated = 0
    items_dropped = 0
    last_error = None
    http_code = None

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            resp = await client.get(BLOCKLIST_URL, headers={"User-Agent": "DarkThreatRadar/1.8.0"})
            http_code = resp.status_code

            if resp.status_code != 200:
                last_error = f"HTTP {resp.status_code}"
                await update_connector_health(
                    source_name, category, "failed",
                    duration_seconds=round(time.time() - start_time, 2),
                    last_error=last_error, http_code=http_code
                )
                return 0

            data = resp.json()
            items_received = len(data)
            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            async with get_db() as conn:
                for item in data:
                    raw_ip = item.get("ip_address")
                    port = item.get("port")
                    status = (item.get("status") or "online").lower()
                    is_active = 1 if status == "online" else 0

                    norm_ip, ip_type = normalize_ip(raw_ip)
                    if not norm_ip:
                        items_dropped += 1
                        continue

                    ioc_id = generate_ioc_id(ip_type or TYPE_IPV4, norm_ip)
                    malware_family = item.get("malware") or "Botnet C2"
                    first_seen = item.get("first_seen") or now_str
                    last_seen = item.get("last_online") or now_str
                    asn_name = item.get("as_name")

                    confidence = calculate_confidence("feodo_tracker", TYPE_IPV4, active=bool(is_active), asn_name=asn_name)
                    severity = get_confidence_severity_label(confidence)

                    # Upsert normalized_iocs
                    cur = await conn.execute("SELECT id, first_seen FROM normalized_iocs WHERE id = ?;", (ioc_id,))
                    existing = await cur.fetchone()

                    if existing:
                        items_updated += 1
                        await conn.execute("""
                            UPDATE normalized_iocs SET
                                last_seen = ?,
                                active = ?,
                                confidence = MAX(confidence, ?),
                                malware_family = COALESCE(NULLIF(malware_family, 'Botnet C2'), ?),
                                port = COALESCE(port, ?),
                                updated_at = ?
                            WHERE id = ?;
                        """, (last_seen, is_active, confidence, malware_family, port, now_str, ioc_id))
                    else:
                        items_created += 1
                        await conn.execute("""
                            INSERT INTO normalized_iocs (
                                id, indicator_type, indicator_value, normalized_value,
                                threat_type, malware_family, confidence, severity,
                                source_name, source_url, reference_url,
                                first_seen, last_seen, ingested_at, updated_at, active, port
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """, (
                            ioc_id, ip_type or TYPE_IPV4, raw_ip, norm_ip,
                            "botnet_c2", malware_family, confidence, severity,
                            "feodo_tracker", BLOCKLIST_URL, "https://feodotracker.abuse.ch/",
                            first_seen, last_seen, now_str, now_str, is_active, port
                        ))

                    # Insert source correlation
                    await conn.execute("""
                        INSERT INTO ioc_sources (ioc_id, source_name, first_seen, last_seen, confidence)
                        VALUES (?, 'feodo_tracker', ?, ?, ?)
                        ON CONFLICT(ioc_id, source_name) DO UPDATE SET
                            last_seen = excluded.last_seen,
                            confidence = excluded.confidence;
                    """, (ioc_id, first_seen, last_seen, confidence))

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
        logger.info(f"Feodo Tracker ingested {items_created} new, {items_updated} updated C2 IPs in {duration}s")
        return items_created + items_updated

    except Exception as e:
        last_error = str(e)
        logger.error(f"Feodo Tracker ingestion error: {e}")
        await update_connector_health(
            source_name, category, "failed",
            duration_seconds=round(time.time() - start_time, 2),
            last_error=last_error
        )
        return 0
