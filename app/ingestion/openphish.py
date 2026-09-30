"""OpenPhish Ingestion Module
Collects active phishing URLs from OpenPhish Community Feed (or Premium API if key provided).
Extracts domain, host, path, protocol, and differentiates phishing from malware distribution.
URL: https://openphish.com/feed.txt
"""

import httpx
import logging
import time
from urllib.parse import urlparse
from datetime import datetime, timezone

from app.config import OPENPHISH_API_KEY
from app.database import get_db, update_connector_health
from app.ingestion.normalization import (
    normalize_url, generate_ioc_id, TYPE_URL
)
from app.ingestion.confidence import calculate_confidence, get_confidence_severity_label

logger = logging.getLogger("ingestion.openphish")

COMMUNITY_FEED_URL = "https://openphish.com/feed.txt"


async def ingest_openphish() -> int:
    """Fetch phishing URLs from OpenPhish feed."""
    start_time = time.time()
    source_name = "openphish"
    category = "Phishing"

    items_received = 0
    items_created = 0
    items_updated = 0
    items_dropped = 0
    last_error = None
    http_code = None

    feed_url = COMMUNITY_FEED_URL
    headers = {"User-Agent": "DarkThreatRadar/1.8.0"}
    if OPENPHISH_API_KEY:
        headers["X-API-Key"] = OPENPHISH_API_KEY

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            resp = await client.get(feed_url, headers=headers)
            http_code = resp.status_code

            if resp.status_code != 200:
                last_error = f"HTTP {resp.status_code}"
                await update_connector_health(
                    source_name, category, "failed",
                    duration_seconds=round(time.time() - start_time, 2),
                    last_error=last_error, http_code=http_code
                )
                return 0

            lines = [line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith("#")]
            items_received = len(lines)
            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            async with get_db() as conn:
                for raw_url in lines:
                    norm_url = normalize_url(raw_url)
                    if not norm_url:
                        items_dropped += 1
                        continue

                    ioc_id = generate_ioc_id(TYPE_URL, norm_url)
                    parsed = urlparse(norm_url)
                    protocol = parsed.scheme
                    port = parsed.port or (443 if protocol == 'https' else 80)

                    confidence = calculate_confidence("openphish", TYPE_URL, active=True)
                    severity = get_confidence_severity_label(confidence)

                    # Upsert into normalized_iocs
                    cur = await conn.execute("SELECT id FROM normalized_iocs WHERE id = ?;", (ioc_id,))
                    if await cur.fetchone():
                        items_updated += 1
                        await conn.execute("""
                            UPDATE normalized_iocs SET last_seen = ?, updated_at = ? WHERE id = ?;
                        """, (now_str, now_str, ioc_id))
                    else:
                        items_created += 1
                        await conn.execute("""
                            INSERT INTO normalized_iocs (
                                id, indicator_type, indicator_value, normalized_value,
                                threat_type, malware_family, confidence, severity,
                                source_name, source_url, reference_url,
                                first_seen, last_seen, ingested_at, updated_at, active, port, protocol
                            ) VALUES (?, ?, ?, ?, 'phishing_url', 'Phishing Campaign', ?, ?, 'openphish', ?, 'https://openphish.com/', ?, ?, ?, ?, 1, ?, ?);
                        """, (
                            ioc_id, TYPE_URL, raw_url, norm_url,
                            confidence, severity, feed_url, now_str, now_str, now_str, now_str, port, protocol
                        ))

                    # Insert source correlation
                    await conn.execute("""
                        INSERT INTO ioc_sources (ioc_id, source_name, first_seen, last_seen, confidence)
                        VALUES (?, 'openphish', ?, ?, ?)
                        ON CONFLICT(ioc_id, source_name) DO UPDATE SET last_seen = excluded.last_seen;
                    """, (ioc_id, now_str, now_str, confidence))

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
        logger.info(f"OpenPhish ingested {items_created} new, {items_updated} updated phishing URLs in {duration}s")
        return items_created + items_updated

    except Exception as e:
        last_error = str(e)
        logger.error(f"OpenPhish ingestion error: {e}")
        await update_connector_health(
            source_name, category, "failed",
            duration_seconds=round(time.time() - start_time, 2),
            last_error=last_error
        )
        return 0
