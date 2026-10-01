"""MITRE ATT&CK Enterprise knowledge base in STIX 2.1."""

import json
import logging
import time
from datetime import datetime, timezone

import httpx

from app.database import get_db, update_connector_health

logger = logging.getLogger("ingestion.mitre_attack")
STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
SUPPORTED_TYPES = {"attack-pattern", "intrusion-set", "malware", "tool", "campaign"}


async def ingest_mitre_attack() -> int:
    started = time.time()
    created = updated = dropped = 0
    try:
        async with httpx.AsyncClient(timeout=90, follow_redirects=True) as client:
            response = await client.get(STIX_URL, headers={"User-Agent": "DarkThreatRadar/1.10"})
        response.raise_for_status()
        objects = response.json().get("objects") or []
        now = datetime.now(timezone.utc).isoformat()
        async with get_db() as conn:
            for item in objects:
                if item.get("type") not in SUPPORTED_TYPES or not item.get("id") or not item.get("name"):
                    dropped += 1
                    continue
                external_refs = item.get("external_references") or []
                primary_ref = next((ref for ref in external_refs if ref.get("source_name") == "mitre-attack"), {})
                phases = item.get("kill_chain_phases") or []
                cursor = await conn.execute("SELECT id FROM attack_knowledge WHERE id=?", (item["id"],))
                exists = await cursor.fetchone()
                await conn.execute(
                    """INSERT INTO attack_knowledge (
                       id, object_type, name, description, external_id, aliases,
                       platforms, tactics, reference_url, modified, revoked,
                       raw_json, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET name=excluded.name,
                       description=excluded.description, aliases=excluded.aliases,
                       platforms=excluded.platforms, tactics=excluded.tactics,
                       reference_url=excluded.reference_url, modified=excluded.modified,
                       revoked=excluded.revoked, raw_json=excluded.raw_json,
                       updated_at=excluded.updated_at""",
                    (item["id"], item["type"], item["name"], item.get("description", "")[:12000],
                     primary_ref.get("external_id"),
                     json.dumps(item.get("aliases") or item.get("x_mitre_aliases") or []),
                     json.dumps(item.get("x_mitre_platforms") or []),
                     json.dumps([phase.get("phase_name") for phase in phases if phase.get("phase_name")]),
                     primary_ref.get("url"), item.get("modified"),
                     int(bool(item.get("revoked") or item.get("x_mitre_deprecated"))),
                     json.dumps(item, ensure_ascii=False, separators=(",", ":"))[:50000], now),
                )
                created += 0 if exists else 1
                updated += 1 if exists else 0
            await conn.commit()
        await update_connector_health(
            "mitre_attack", "Threat Knowledge", "healthy",
            duration_seconds=round(time.time() - started, 2), items_received=len(objects),
            items_created=created, items_updated=updated, items_dropped=dropped,
            http_code=response.status_code,
        )
        return created + updated
    except Exception as exc:
        logger.exception("MITRE ATT&CK ingestion failed")
        await update_connector_health(
            "mitre_attack", "Threat Knowledge", "failed",
            duration_seconds=round(time.time() - started, 2),
            last_error=f"{type(exc).__name__}: MITRE ATT&CK ingestion failed",
        )
        return 0
