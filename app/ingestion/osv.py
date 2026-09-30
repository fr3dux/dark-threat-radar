"""OSV.dev Ingestion and On-Demand Enrichment Module (Google Open Source Vulnerabilities)
Queries OSV.dev API for packages registered in Watchlist or CVE/GHSA aliases.
URL: https://api.osv.dev/v1/query
"""

import json
import httpx
import logging
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from app.database import get_db, update_connector_health
from app.ingestion.normalization import (
    normalize_cve, normalize_ghsa, generate_ioc_id, TYPE_CVE, TYPE_GHSA, TYPE_PACKAGE
)
from app.ingestion.confidence import calculate_confidence, get_confidence_severity_label

logger = logging.getLogger("ingestion.osv")

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"


async def query_osv_package(package_name: str, ecosystem: Optional[str] = None) -> List[Dict[str, Any]]:
    """Query OSV.dev for vulnerabilities affecting a specific package on demand."""
    payload = {"package": {"name": package_name}}
    if ecosystem:
        payload["package"]["ecosystem"] = ecosystem

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(OSV_QUERY_URL, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("vulns") or []
    except Exception as e:
        logger.warning(f"OSV query error for package {package_name}: {e}")
    return []


async def ingest_osv() -> int:
    """Perform targeted OSV.dev enrichment only for packages in the Watchlist."""
    start_time = time.time()
    source_name = "osv_dev"
    category = "Vulnerabilities"

    items_received = 0
    items_created = 0
    items_updated = 0
    items_dropped = 0
    last_error = None
    http_code = 200

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    try:
        # Fetch targets from Watchlist
        async with get_db() as conn:
            cur = await conn.execute("SELECT value FROM watchlist WHERE item_type = 'product';")
            watchlist_items = [r["value"] for r in await cur.fetchall()]

        # OSV requires an ecosystem when querying by name. Operators can use
        # Watchlist values such as "PyPI:django" or "npm:lodash".
        targets = set()
        for item in watchlist_items:
            if item and ":" in item:
                ecosystem, package = item.split(":", 1)
                if ecosystem.strip() and package.strip():
                    targets.add((ecosystem.strip(), package.strip()))

        if not targets:
            await update_connector_health(
                source_name, category, "healthy",
                duration_seconds=round(time.time() - start_time, 2),
                items_received=0, http_code=None,
            )
            return 0

        async with get_db() as conn:
            for ecosystem, target in targets:
                vulns = await query_osv_package(target, ecosystem)
                items_received += len(vulns)

                for v in vulns:
                    osv_id = v.get("id") or ""
                    summary = v.get("summary") or v.get("details", "")[:200] or "OSV Security Advisory"
                    aliases = v.get("aliases") or []
                    published = v.get("published") or now_str

                    cve_alias = None
                    ghsa_alias = None
                    for alias in aliases:
                        if alias.startswith("CVE-"):
                            cve_alias = normalize_cve(alias)
                        elif alias.startswith("GHSA-"):
                            ghsa_alias = normalize_ghsa(alias)

                    # Store OSV entry in vendor_advisories table
                    adv_id = f"osv:{osv_id}"
                    ref_url = f"https://osv.dev/vulnerability/{osv_id}"

                    affected = v.get("affected") or []
                    affected_str = str(affected[:3])

                    cursor = await conn.execute(
                        "SELECT id FROM vendor_advisories WHERE id = ?", (adv_id,)
                    )
                    existed = await cursor.fetchone() is not None
                    await conn.execute("""
                        INSERT INTO vendor_advisories (
                            id, vendor, product, advisory_id, title, severity,
                            cve_ids, ghsa_ids, affected_versions, reference_url, published_date, updated_at, raw_json
                        ) VALUES (?, 'OpenSource', ?, ?, ?, 'MEDIUM', ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET
                            title = excluded.title,
                            updated_at = excluded.updated_at;
                    """, (
                        adv_id, target, osv_id, summary,
                        cve_alias or "", ghsa_alias or "",
                        affected_str, ref_url, published[:10], now_str,
                        json.dumps(v, separators=(",", ":"))
                    ))
                    if existed:
                        items_updated += 1
                    else:
                        items_created += 1

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
        logger.info(f"OSV.dev ingested/enriched {items_created} vulnerabilities in {duration}s")
        return items_created + items_updated

    except Exception as e:
        last_error = str(e)
        logger.error(f"OSV.dev ingestion error: {e}")
        await update_connector_health(
            source_name, category, "failed",
            duration_seconds=round(time.time() - start_time, 2),
            last_error=last_error
        )
        return 0
