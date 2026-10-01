"""Recent Red Hat CVE and remediation metadata."""

import json
import logging
import time
from datetime import datetime, timedelta, timezone

import httpx

from app.database import get_db, update_connector_health
from app.ingestion.normalization import normalize_cve

logger = logging.getLogger("ingestion.redhat_security")
API_URL = "https://access.redhat.com/hydra/rest/securitydata/cve.json"


async def ingest_redhat_security() -> int:
    started = time.time()
    created = updated = dropped = 0
    after = (datetime.now(timezone.utc) - timedelta(days=14)).date().isoformat()
    try:
        async with httpx.AsyncClient(timeout=45, follow_redirects=True) as client:
            response = await client.get(
                API_URL, params={"after": after},
                headers={"User-Agent": "DarkThreatRadar/1.10", "Accept": "application/json"},
            )
        response.raise_for_status()
        entries = response.json()
        if not isinstance(entries, list):
            raise ValueError("Red Hat returned an unexpected document")
        now = datetime.now(timezone.utc).isoformat()
        async with get_db() as conn:
            for item in entries[:1000]:
                cve = normalize_cve(item.get("CVE"))
                if not cve:
                    dropped += 1
                    continue
                advisory_id = f"redhat:{cve}"
                cursor = await conn.execute("SELECT id FROM vendor_advisories WHERE id=?", (advisory_id,))
                exists = await cursor.fetchone()
                severity = str(item.get("severity") or "MODERATE").upper()
                await conn.execute(
                    """INSERT INTO vendor_advisories (
                       id, vendor, product, advisory_id, title, severity, cve_ids,
                       affected_versions, fixed_versions, reference_url,
                       published_date, updated_at, raw_json
                    ) VALUES (?, 'Red Hat', 'Red Hat Products', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET title=excluded.title,
                       severity=excluded.severity, affected_versions=excluded.affected_versions,
                       fixed_versions=excluded.fixed_versions, updated_at=excluded.updated_at,
                       raw_json=excluded.raw_json""",
                    (advisory_id, cve, str(item.get("bugzilla_description") or cve)[:500],
                     severity, cve,
                     json.dumps(item.get("affected_packages") or [], separators=(",", ":")),
                     json.dumps(item.get("advisories") or [], separators=(",", ":")),
                     f"https://access.redhat.com/security/cve/{cve}",
                     str(item.get("public_date") or "")[:10], now,
                     json.dumps(item, ensure_ascii=False, separators=(",", ":"))[:50000]),
                )
                created += 0 if exists else 1
                updated += 1 if exists else 0
            await conn.commit()
        await update_connector_health(
            "redhat_security", "Vulnerabilities", "healthy",
            duration_seconds=round(time.time() - started, 2), items_received=len(entries),
            items_created=created, items_updated=updated, items_dropped=dropped,
            http_code=response.status_code,
        )
        return created + updated
    except Exception as exc:
        logger.exception("Red Hat security ingestion failed")
        await update_connector_health(
            "redhat_security", "Vulnerabilities", "failed",
            duration_seconds=round(time.time() - started, 2),
            last_error=f"{type(exc).__name__}: Red Hat ingestion failed",
        )
        return 0
