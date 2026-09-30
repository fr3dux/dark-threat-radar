"""GitHub Advisory Database Ingestion Module
Fetches global security advisories from GitHub REST API, supporting ecosystems (npm, PyPI, Maven, Go, Rust, etc.).
Complements existing NVD records without duplicating independent CVE records.
"""

import json
import httpx
import logging
import time
from datetime import datetime, timezone

from app.config import GITHUB_TOKEN
from app.database import get_db, update_connector_health
from app.ingestion.normalization import (
    normalize_cve, normalize_ghsa, generate_ioc_id, TYPE_CVE, TYPE_GHSA
)
from app.ingestion.confidence import calculate_confidence, get_confidence_severity_label

logger = logging.getLogger("ingestion.github_advisories")

API_URL = "https://api.github.com/advisories"


async def ingest_github_advisories() -> int:
    """Fetch global advisories from GitHub Security Advisory database."""
    start_time = time.time()
    source_name = "github_advisories"
    category = "Vulnerabilities"

    headers = {
        "User-Agent": "DarkThreatRadar/1.8.1",
        "Accept": "application/vnd.github+json",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    items_received = 0
    items_created = 0
    items_updated = 0
    items_dropped = 0
    last_error = None
    http_code = None

    params = {
        "per_page": 50,
        "direction": "desc",
        "sort": "updated"
    }

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            resp = await client.get(API_URL, headers=headers, params=params)
            http_code = resp.status_code

            if resp.status_code != 200:
                last_error = f"HTTP {resp.status_code}"
                state = "rate_limited" if resp.status_code in (403, 429) else "failed"
                await update_connector_health(
                    source_name, category, state,
                    duration_seconds=round(time.time() - start_time, 2),
                    last_error=last_error, http_code=http_code
                )
                return 0

            advisories = resp.json()
            items_received = len(advisories)
            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            async with get_db() as conn:
                for adv in advisories:
                    ghsa_id = normalize_ghsa(adv.get("ghsa_id"))
                    cve_id = normalize_cve(adv.get("cve_id"))
                    summary = adv.get("summary") or "GitHub Security Advisory"
                    severity = (adv.get("severity") or "HIGH").upper()
                    published_at = adv.get("published_at") or now_str
                    updated_at = adv.get("updated_at") or published_at
                    ref_url = adv.get("html_url") or f"https://github.com/advisories/{ghsa_id}"

                    cvss = adv.get("cvss") or {}
                    cvss_score = cvss.get("score")

                    # Extract affected ecosystems and packages
                    vulnerabilities = adv.get("vulnerabilities") or []
                    affected_packages = []
                    for v in vulnerabilities:
                        pkg = v.get("package") or {}
                        ecosystem = pkg.get("ecosystem")
                        pkg_name = pkg.get("name")
                        v_range = v.get("vulnerable_version_range")
                        patched_data = v.get("first_patched_version") or {}
                        patched = (
                            patched_data.get("identifier")
                            if isinstance(patched_data, dict)
                            else str(patched_data)
                        )
                        if pkg_name:
                            affected_packages.append({
                                "ecosystem": ecosystem,
                                "package": pkg_name,
                                "vulnerable_range": v_range,
                                "patched_version": patched
                            })

                    # Rule: If corresponding CVE exists, complement NVD record rather than creating a duplicate primary key
                    if cve_id:
                        cur = await conn.execute("SELECT cve_id FROM cve_records WHERE cve_id = ?;", (cve_id,))
                        cve_row = await cur.fetchone()
                        if cve_row:
                            # Update existing CVE record with GHSA reference and package details
                            await conn.execute("""
                                UPDATE cve_records SET
                                    short_description = COALESCE(NULLIF(short_description, ''), ?),
                                    cvss_score = COALESCE(cvss_score, ?),
                                    updated_at = ?
                                WHERE cve_id = ?;
                            """, (summary, cvss_score, now_str, cve_id))
                            items_updated += 1
                        else:
                            # Insert into cve_records with GHSA reference
                            await conn.execute("""
                                INSERT INTO cve_records (
                                    cve_id, source, vulnerability_name, date_added,
                                    short_description, cvss_score, cvss_severity, updated_at
                                ) VALUES (?, 'github_advisories', ?, ?, ?, ?, ?, ?);
                            """, (cve_id, summary, published_at[:10], summary, cvss_score, severity, now_str))
                            items_created += 1

                    # Save normalized GHSA IOC
                    if ghsa_id:
                        ioc_id = generate_ioc_id(TYPE_GHSA, ghsa_id)
                        confidence = calculate_confidence("github_advisories", TYPE_GHSA, active=True)

                        cur = await conn.execute("SELECT id FROM normalized_iocs WHERE id = ?;", (ioc_id,))
                        if await cur.fetchone():
                            await conn.execute("""
                                UPDATE normalized_iocs SET last_seen = ?, updated_at = ? WHERE id = ?;
                            """, (now_str, now_str, ioc_id))
                        else:
                            await conn.execute("""
                                INSERT INTO normalized_iocs (
                                    id, indicator_type, indicator_value, normalized_value,
                                    threat_type, malware_family, confidence, severity,
                                    source_name, source_id, source_url, reference_url,
                                    first_seen, last_seen, ingested_at, updated_at, active, tags
                                ) VALUES (?, ?, ?, ?, 'vulnerability', ?, ?, ?, 'github_advisories', ?, ?, ?, ?, ?, ?, ?, 1, ?);
                            """, (
                                ioc_id, TYPE_GHSA, ghsa_id, ghsa_id,
                                cve_id or "GHSA Advisory", confidence, severity,
                                ghsa_id, API_URL, ref_url,
                                published_at, updated_at, now_str, now_str,
                                ",".join(sorted({p.get("ecosystem") or "generic" for p in affected_packages}))
                            ))

                        await conn.execute("""
                            INSERT INTO ioc_sources (ioc_id, source_name, source_id, first_seen, last_seen, confidence)
                            VALUES (?, 'github_advisories', ?, ?, ?, ?)
                            ON CONFLICT(ioc_id, source_name) DO UPDATE SET last_seen = excluded.last_seen;
                        """, (ioc_id, ghsa_id, published_at, updated_at, confidence))

                    # Also store vendor advisory representation
                    adv_id = f"github:{ghsa_id or cve_id}"
                    await conn.execute("""
                        INSERT INTO vendor_advisories (
                            id, vendor, product, advisory_id, title, severity,
                            cve_ids, ghsa_ids, affected_versions, reference_url, published_date, updated_at
                        ) VALUES (?, 'GitHub', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET
                            title = excluded.title,
                            updated_at = excluded.updated_at;
                    """, (
                        adv_id,
                        affected_packages[0]["package"] if affected_packages else "Software Package",
                        ghsa_id or cve_id,
                        summary,
                        severity,
                        cve_id or "",
                        ghsa_id or "",
                        json.dumps(affected_packages, separators=(",", ":")),
                        ref_url,
                        published_at[:10],
                        now_str
                    ))

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
        logger.info(f"GitHub Advisories ingested {items_created} new, {items_updated} updated in {duration}s")
        return items_created + items_updated

    except Exception as e:
        last_error = str(e)
        logger.error(f"GitHub Advisories ingestion error: {e}")
        await update_connector_health(
            source_name, category, "failed",
            duration_seconds=round(time.time() - start_time, 2),
            last_error=last_error
        )
        return 0
