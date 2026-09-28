import logging
import json
import httpx
from datetime import datetime, timezone
from app.database import get_db, update_feed_status

logger = logging.getLogger("ingestion.cisa_kev")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

async def ingest_cisa_kev() -> int:
    logger.info("Starting CISA KEV ingestion...")
    await update_feed_status("cisa_kev", "running", 0, "Ingesting CISA KEV catalog...")
    
    count = 0
    try:
        async with httpx.AsyncClient(timeout=30.0, headers={"User-Agent": "ThreatRadar-CTI/1.0"}) as client:
            resp = await client.get(CISA_KEV_URL)
            resp.raise_for_status()
            data = resp.json()

        vulnerabilities = data.get("vulnerabilities", [])
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        async with get_db() as conn:
            for item in vulnerabilities:
                cve_id = item.get("cveID", "").strip()
                if not cve_id:
                    continue

                vendor_project = item.get("vendorProject", "")
                product = item.get("product", "")
                vulnerability_name = item.get("vulnerabilityName", "")
                date_added = item.get("dateAdded", "")
                short_description = item.get("shortDescription", "")
                required_action = item.get("requiredAction", "")
                due_date = item.get("dueDate", "")
                known_ransomware = item.get("knownRansomwareCampaignUse", "Unknown")
                raw_json = json.dumps(item)

                await conn.execute("""
                    INSERT INTO cve_records (
                        cve_id, source, vendor_project, product, vulnerability_name,
                        date_added, short_description, required_action, due_date,
                        known_ransomware_campaign_use, raw_json, updated_at
                    ) VALUES (?, 'cisa_kev', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        source = 'cisa_kev',
                        vendor_project = excluded.vendor_project,
                        product = excluded.product,
                        vulnerability_name = excluded.vulnerability_name,
                        date_added = excluded.date_added,
                        short_description = excluded.short_description,
                        required_action = excluded.required_action,
                        due_date = excluded.due_date,
                        known_ransomware_campaign_use = excluded.known_ransomware_campaign_use,
                        raw_json = excluded.raw_json,
                        updated_at = excluded.updated_at;
                """, (
                    cve_id, vendor_project, product, vulnerability_name,
                    date_added, short_description, required_action, due_date,
                    known_ransomware, raw_json, now_str
                ))
                count += 1

            await conn.commit()

        msg = f"Synced {count} CISA KEV entries successfully."
        logger.info(msg)
        await update_feed_status("cisa_kev", "success", count, msg)
        return count

    except Exception as e:
        err_msg = f"Error ingesting CISA KEV: {str(e)}"
        logger.error(err_msg, exc_info=True)
        await update_feed_status("cisa_kev", "error", count, err_msg)
        return count
