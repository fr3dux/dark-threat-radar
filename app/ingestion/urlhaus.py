"""URLhaus Ingestion Module (abuse.ch)
Collects URLs distributing malware, host/IP info, malware families, and online/offline status.
Uses URLHAUS_AUTH_KEY from environment variables.
"""

import csv
import httpx
import logging
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.config import URLHAUS_AUTH_KEY
from app.database import get_db, update_connector_health
from app.ingestion.normalization import (
    normalize_url, generate_ioc_id, TYPE_URL
)
from app.ingestion.confidence import calculate_confidence, get_confidence_severity_label

logger = logging.getLogger("ingestion.urlhaus")

EXPORT_URL = "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"


def parse_recent_csv(payload: str) -> list[dict]:
    """Parse URLhaus recent.csv without relying on its commented header."""
    rows = []
    for row in csv.reader(
        line for line in payload.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ):
        if len(row) < 8:
            continue
        rows.append({
            "id": row[0].strip(), "date_added": row[1].strip(), "url": row[2].strip(),
            "url_status": row[3].strip(), "last_online": row[4].strip(),
            "threat": row[5].strip(),
            "tags": [tag.strip() for tag in row[6].split(",") if tag.strip()],
            "urlhaus_reference": row[7].strip(),
        })
    return rows


async def ingest_urlhaus() -> int:
    """Fetch recent malware distribution URLs from URLhaus."""
    start_time = time.time()
    source_name = "urlhaus"
    category = "Malware & IOCs"

    headers = {
        "User-Agent": "DarkThreatRadar/1.8.1"
    }
    if URLHAUS_AUTH_KEY:
        headers["Auth-Key"] = URLHAUS_AUTH_KEY

    items_received = 0
    items_created = 0
    items_updated = 0
    items_dropped = 0
    last_error = None
    http_code = None

    if not URLHAUS_AUTH_KEY:
        await update_connector_health(
            source_name,
            category,
            "auth_required",
            last_error="URLHAUS_AUTH_KEY is not configured",
        )
        return 0

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
            resp = await client.get(EXPORT_URL.format(auth_key=URLHAUS_AUTH_KEY), headers=headers)
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

            urls = parse_recent_csv(resp.text)
            if not urls and resp.text.strip():
                raise ValueError("URLhaus recent.csv contained no valid records")
            items_received = len(urls)
            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            async with get_db() as conn:
                for item in urls:
                    raw_url = item.get("url")
                    norm_url = normalize_url(raw_url)
                    if not norm_url:
                        items_dropped += 1
                        continue

                    ioc_id = generate_ioc_id(TYPE_URL, norm_url)
                    url_status = (item.get("url_status") or "online").lower()
                    is_active = 1 if url_status == "online" else 0

                    malware_family = item.get("threat") or "malware_distribution"
                    tags = ",".join(item.get("tags") or [])
                    first_seen = item.get("date_added") or now_str
                    last_seen = now_str
                    ref_url = item.get("urlhaus_reference") or "https://urlhaus.abuse.ch/"

                    parsed = urlparse(norm_url)
                    protocol = parsed.scheme
                    port = parsed.port or (443 if protocol == 'https' else 80)

                    confidence = calculate_confidence("urlhaus", TYPE_URL, active=bool(is_active))
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
                                confidence = ?,
                                severity = ?,
                                malware_family = COALESCE(NULLIF(malware_family, 'malware_distribution'), ?),
                                tags = COALESCE(tags, ?),
                                updated_at = ?
                            WHERE id = ?;
                        """, (last_seen, is_active, confidence, severity, malware_family, tags, now_str, ioc_id))
                    else:
                        items_created += 1
                        await conn.execute("""
                            INSERT INTO normalized_iocs (
                                id, indicator_type, indicator_value, normalized_value,
                                threat_type, malware_family, confidence, severity,
                                source_name, source_id, source_url, reference_url,
                                first_seen, last_seen, ingested_at, updated_at, active, tags, port, protocol
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """, (
                            ioc_id, TYPE_URL, raw_url, norm_url,
                            "malware_url", malware_family, confidence, severity,
                            "urlhaus", str(item.get("id")), "https://urlhaus-api.abuse.ch/v2/files/exports/", ref_url,
                            first_seen, last_seen, now_str, now_str, is_active, tags, port, protocol
                        ))

                    # Insert source correlation
                    await conn.execute("""
                        INSERT INTO ioc_sources (ioc_id, source_name, source_id, first_seen, last_seen, confidence)
                        VALUES (?, 'urlhaus', ?, ?, ?, ?)
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
        logger.info(f"URLhaus ingested {items_created} new, {items_updated} updated URLs in {duration}s")
        return items_created + items_updated

    except Exception as e:
        last_error = f"{type(e).__name__}: URLhaus ingestion failed"
        logger.error("URLhaus ingestion error (%s)", type(e).__name__)
        await update_connector_health(
            source_name, category, "failed",
            duration_seconds=round(time.time() - start_time, 2),
            last_error=last_error
        )
        return 0
