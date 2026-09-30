"""Spamhaus DROP ingestion (IPv4, IPv6 and ASN NDJSON feeds)."""

import ipaddress
import json
import logging
import time
from datetime import datetime, timezone

import httpx

from app.database import get_db, update_connector_health
from app.ingestion.confidence import calculate_confidence, get_confidence_severity_label
from app.ingestion.normalization import TYPE_ASN, TYPE_CIDR, generate_ioc_id

logger = logging.getLogger("ingestion.spamhaus_drop")

DROP_FEEDS = (
    ("https://www.spamhaus.org/drop/drop_v4.json", TYPE_CIDR, "Spamhaus IPv4 DROP"),
    ("https://www.spamhaus.org/drop/drop_v6.json", TYPE_CIDR, "Spamhaus IPv6 DROP"),
    ("https://www.spamhaus.org/drop/asndrop.json", TYPE_ASN, "Spamhaus ASN-DROP"),
)


def parse_ndjson(payload: str) -> list[dict]:
    """Parse the documented Spamhaus newline-delimited JSON format."""
    rows = []
    for number, line in enumerate(payload.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid NDJSON on line {number}") from exc
        if isinstance(item, dict):
            rows.append(item)
    return rows


async def check_ip_in_drop_blocks(ip_str: str) -> bool:
    try:
        address = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False
    async with get_db() as conn:
        cursor = await conn.execute(
            "SELECT normalized_value FROM normalized_iocs "
            "WHERE source_name = 'spamhaus_drop' AND indicator_type = 'CIDR' AND active = 1"
        )
        for row in await cursor.fetchall():
            try:
                if address in ipaddress.ip_network(row["normalized_value"], strict=False):
                    return True
            except ValueError:
                continue
    return False


async def ingest_spamhaus_drop() -> int:
    started = time.time()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    received = created = updated = dropped = 0
    response_codes = []
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            responses = []
            for url, indicator_type, family in DROP_FEEDS:
                response = await client.get(url, headers={"User-Agent": "DarkThreatRadar/1.8.1"})
                response_codes.append(response.status_code)
                response.raise_for_status()
                responses.append((url, indicator_type, family, parse_ndjson(response.text)))

        async with get_db() as conn:
            for url, indicator_type, family, entries in responses:
                for item in entries:
                    raw_value = item.get("cidr") if indicator_type == TYPE_CIDR else item.get("asn")
                    if not raw_value:
                        dropped += 1
                        continue
                    try:
                        value = (str(ipaddress.ip_network(str(raw_value), strict=False))
                                 if indicator_type == TYPE_CIDR
                                 else f"AS{str(raw_value).upper().removeprefix('AS')}")
                    except ValueError:
                        dropped += 1
                        continue
                    received += 1
                    ioc_id = generate_ioc_id(indicator_type, value)
                    confidence = calculate_confidence("spamhaus_drop", indicator_type, active=True)
                    severity = get_confidence_severity_label(confidence)
                    cursor = await conn.execute("SELECT id FROM normalized_iocs WHERE id = ?", (ioc_id,))
                    if await cursor.fetchone():
                        updated += 1
                        await conn.execute(
                            "UPDATE normalized_iocs SET last_seen=?, active=1, updated_at=? WHERE id=?",
                            (now, now, ioc_id),
                        )
                    else:
                        created += 1
                        await conn.execute(
                            """INSERT INTO normalized_iocs
                            (id, indicator_type, indicator_value, normalized_value, threat_type,
                             malware_family, confidence, severity, source_name, source_url,
                             reference_url, first_seen, last_seen, ingested_at, updated_at, active)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'spamhaus_drop', ?,
                                    'https://www.spamhaus.org/drop/', ?, ?, ?, ?, 1)""",
                            (ioc_id, indicator_type, value, value,
                             "do_not_route_asn" if indicator_type == TYPE_ASN else "do_not_route",
                             family, confidence, severity, url, now, now, now, now),
                        )
                    await conn.execute(
                        """INSERT INTO ioc_sources
                        (ioc_id, source_name, first_seen, last_seen, confidence, raw_metadata)
                        VALUES (?, 'spamhaus_drop', ?, ?, ?, ?)
                        ON CONFLICT(ioc_id, source_name) DO UPDATE SET
                            last_seen=excluded.last_seen, confidence=excluded.confidence,
                            raw_metadata=excluded.raw_metadata""",
                        (ioc_id, now, now, confidence, json.dumps(item, separators=(",", ":"))),
                    )
            await conn.commit()

        await update_connector_health(
            "spamhaus_drop", "Network Intelligence", "healthy",
            duration_seconds=round(time.time() - started, 2), items_received=received,
            items_created=created, items_updated=updated, items_dropped=dropped, http_code=200,
        )
        return created + updated
    except Exception as exc:
        logger.exception("Spamhaus DROP ingestion failed")
        await update_connector_health(
            "spamhaus_drop", "Network Intelligence", "failed",
            duration_seconds=round(time.time() - started, 2),
            last_error=f"{type(exc).__name__}: {exc}",
            http_code=response_codes[-1] if response_codes else None,
        )
        return 0
