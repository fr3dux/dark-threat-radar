import logging
from datetime import datetime, timezone
import httpx
from app.database import get_db, update_feed_status

logger = logging.getLogger("ingestion.epss")

EPSS_API_URL = "https://api.first.org/data/v1/epss"

async def ingest_epss(batch_size: int = 80) -> int:
    """Enrich tracked CVE records with FIRST.org EPSS exploit probability scores."""
    logger.info("Starting EPSS exploit prediction scoring...")
    await update_feed_status("epss", "running", 0, "Querying FIRST.org EPSS scores...")

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total_updated = 0

    try:
        # Retrieve CVEs needing EPSS scores (prioritizing critical, kev, and recently added)
        async with get_db() as conn:
            cur = await conn.execute("""
                SELECT cve_id FROM cve_records
                ORDER BY 
                    CASE WHEN source = 'cisa_kev' THEN 1 ELSE 2 END,
                    cvss_score DESC
                LIMIT 500;
            """)
            rows = await cur.fetchall()
            cve_ids = [r["cve_id"] for r in rows if r["cve_id"]]

        if not cve_ids:
            logger.info("No CVE records to enrich with EPSS.")
            await update_feed_status("epss", "success", 0, "No CVEs found to enrich.")
            return 0

        headers = {"User-Agent": "ThreatRadar-CTI/1.2"}

        # Process in batches of 50 to avoid URL length issues
        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            for i in range(0, len(cve_ids), batch_size):
                batch = cve_ids[i:i + batch_size]
                cve_param = ",".join(batch)
                try:
                    resp = await client.get(EPSS_API_URL, params={"cve": cve_param})
                    if resp.status_code == 200:
                        data = resp.json()
                        epss_items = data.get("data", [])
                        async with get_db() as conn:
                            for item in epss_items:
                                cve = item.get("cve")
                                epss = float(item.get("epss", 0))
                                percentile = float(item.get("percentile", 0))
                                await conn.execute("""
                                    UPDATE cve_records
                                    SET epss_score = ?,
                                        epss_percentile = ?,
                                        updated_at = ?
                                    WHERE cve_id = ?;
                                """, (epss, percentile, now_str, cve))
                                total_updated += 1
                            await conn.commit()
                except Exception as batch_err:
                    logger.warning(f"Error querying EPSS batch {i}-{i+batch_size}: {batch_err}")

        msg = f"Enriched {total_updated} CVE records with EPSS probability scores."
        logger.info(msg)
        await update_feed_status("epss", "success", total_updated, msg)
        return total_updated

    except Exception as e:
        err_msg = f"Error during EPSS ingestion: {str(e)}"
        logger.error(err_msg, exc_info=True)
        await update_feed_status("epss", "error", total_updated, err_msg)
        return total_updated
