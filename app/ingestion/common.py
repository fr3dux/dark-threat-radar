"""Shared, source-aware IOC ingestion primitives."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.database import get_db
from app.ingestion.confidence import calculate_confidence, get_confidence_severity_label
from app.ingestion.normalization import generate_ioc_id, normalize_indicator


@dataclass(slots=True)
class IOCRecord:
    indicator_type: str
    value: str
    threat_type: str
    source_id: str = ""
    malware_family: str = ""
    first_seen: str = ""
    last_seen: str = ""
    expires_at: str = ""
    source_url: str = ""
    reference_url: str = ""
    tags: list[str] = field(default_factory=list)
    country: str = ""
    asn: int | None = None
    port: int | None = None
    protocol: str = ""
    tlp: str = "CLEAR"
    active: bool = True
    raw: dict[str, Any] = field(default_factory=dict)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def upsert_ioc_records(source_name: str, records: list[IOCRecord]) -> dict[str, int]:
    """Normalize and correlate records while retaining per-source lifecycle state."""
    now = utc_now()
    stats = {"received": len(records), "created": 0, "updated": 0, "dropped": 0}
    async with get_db() as conn:
        for record in records:
            normalized, detected_type = normalize_indicator(record.indicator_type, record.value)
            if not normalized or not detected_type:
                stats["dropped"] += 1
                continue
            ioc_id = generate_ioc_id(detected_type, normalized)
            confidence = calculate_confidence(source_name, detected_type, active=record.active)
            severity = get_confidence_severity_label(confidence)
            first_seen = record.first_seen or now
            last_seen = record.last_seen or first_seen
            raw_json = json.dumps(record.raw, ensure_ascii=False, separators=(",", ":"))[:16000]

            cursor = await conn.execute(
                "SELECT confidence FROM normalized_iocs WHERE id = ?", (ioc_id,)
            )
            existing = await cursor.fetchone()
            if existing:
                stats["updated"] += 1
                await conn.execute(
                    """UPDATE normalized_iocs SET
                       last_seen=?, updated_at=?,
                       active=CASE WHEN ?=1 THEN 1 ELSE active END,
                       revoked=CASE WHEN ?=1 THEN 0 ELSE revoked END,
                       confidence=MAX(confidence, ?),
                       severity=CASE WHEN ? > confidence THEN ? ELSE severity END,
                       expires_at=CASE
                           WHEN ? IS NULL THEN expires_at
                           WHEN expires_at IS NULL OR expires_at < ? THEN ?
                           ELSE expires_at END
                       WHERE id=?""",
                    (last_seen, now, int(record.active), int(record.active),
                     confidence, confidence, severity,
                     record.expires_at or None, record.expires_at or None,
                     record.expires_at or None, ioc_id),
                )
            else:
                stats["created"] += 1
                await conn.execute(
                    """INSERT INTO normalized_iocs (
                       id, indicator_type, indicator_value, normalized_value, threat_type,
                       malware_family, confidence, severity, source_name, source_id,
                       source_url, reference_url, first_seen, last_seen, ingested_at,
                       updated_at, expires_at, active, tags, country, asn, port,
                       protocol, tlp, raw_metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (ioc_id, detected_type, record.value, normalized, record.threat_type,
                     record.malware_family, confidence, severity, source_name,
                     record.source_id or None, record.source_url or None,
                     record.reference_url or None, first_seen, last_seen, now, now,
                     record.expires_at or None, int(record.active),
                     ",".join(sorted(set(record.tags))), record.country or None,
                     record.asn, record.port, record.protocol or None,
                     record.tlp or "CLEAR", raw_json),
                )

            await conn.execute(
                """INSERT INTO ioc_sources (
                   ioc_id, source_name, source_id, first_seen, last_seen,
                   confidence, raw_metadata, expires_at, active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ioc_id, source_name) DO UPDATE SET
                   source_id=excluded.source_id,
                   last_seen=excluded.last_seen,
                   confidence=excluded.confidence,
                   raw_metadata=excluded.raw_metadata,
                   expires_at=excluded.expires_at,
                   active=excluded.active""",
                (ioc_id, source_name, record.source_id or None, first_seen, last_seen,
                 confidence, raw_json, record.expires_at or None, int(record.active)),
            )
        await conn.commit()
    return stats


async def expire_stale_iocs() -> int:
    """Expire provider observations and deactivate IOCs with no live source."""
    async with get_db() as conn:
        cursor = await conn.execute(
            """UPDATE ioc_sources SET active=0
               WHERE active=1 AND expires_at IS NOT NULL
                 AND datetime(expires_at) <= datetime('now')"""
        )
        expired = cursor.rowcount
        await conn.execute(
            """UPDATE normalized_iocs SET active=0, updated_at=?
               WHERE active=1 AND NOT EXISTS (
                   SELECT 1 FROM ioc_sources s
                   WHERE s.ioc_id=normalized_iocs.id AND s.active=1
               )""",
            (utc_now(),),
        )
        await conn.commit()
    return max(0, expired)
