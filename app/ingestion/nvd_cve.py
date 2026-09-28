import logging
import json
import httpx
from datetime import datetime, timedelta, timezone
from app.database import get_db, update_feed_status
from app.config import NVD_API_KEY

logger = logging.getLogger("ingestion.nvd_cve")

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def extract_cvss(metrics: dict):
    # Try cvssMetricV31
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40"]:
        if key in metrics and metrics[key]:
            data = metrics[key][0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or metrics[key][0].get("baseSeverity")
            if score is not None:
                return float(score), str(severity).upper() if severity else "UNKNOWN"

    # Fallback to cvssMetricV2
    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        data = metrics["cvssMetricV2"][0].get("cvssData", {})
        score = data.get("baseScore")
        severity = metrics["cvssMetricV2"][0].get("baseSeverity")
        if score is not None:
            return float(score), str(severity).upper() if severity else "UNKNOWN"

    return None, "UNKNOWN"

async def ingest_nvd_cve(days_back: int = 7) -> int:
    logger.info(f"Starting NVD CVE ingestion (last {days_back} days)...")
    await update_feed_status("nvd_cve", "running", 0, "Ingesting NIST NVD 2.0 CVEs...")

    now = datetime.now(timezone.utc)
    start_dt = now - timedelta(days=days_back)
    start_str = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
    end_str = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    now_str = now.strftime("%Y-%m-%d %H:%M:%S UTC")

    headers = {"User-Agent": "ThreatRadar-CTI/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    params = {
        "pubStartDate": start_str,
        "pubEndDate": end_str,
        "resultsPerPage": 100
    }

    count = 0
    try:
        async with httpx.AsyncClient(timeout=45.0, headers=headers) as client:
            resp = await client.get(NVD_BASE_URL, params=params)
            if resp.status_code == 403 or resp.status_code == 429:
                # Rate limited - log warning
                logger.warning(f"NVD rate limit hit (HTTP {resp.status_code})")
                await update_feed_status("nvd_cve", "error", 0, f"Rate limited by NIST NVD (HTTP {resp.status_code})")
                return 0

            resp.raise_for_status()
            data = resp.json()

        vulnerabilities = data.get("vulnerabilities", [])

        async with get_db() as conn:
            for item in vulnerabilities:
                cve_obj = item.get("cve", {})
                cve_id = cve_obj.get("id", "").strip()
                if not cve_id:
                    continue

                published = cve_obj.get("published", "")
                descriptions = cve_obj.get("descriptions", [])
                desc_en = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc_en = d.get("value", "")
                        break
                if not desc_en and descriptions:
                    desc_en = descriptions[0].get("value", "")

                metrics = cve_obj.get("metrics", {})
                score, severity = extract_cvss(metrics)

                # Extract vendor/product from configurations if available
                vendor = ""
                product = ""
                configs = cve_obj.get("configurations", [])
                for cfg in configs:
                    nodes = cfg.get("nodes", [])
                    for node in nodes:
                        cpe_matches = node.get("cpeMatch", [])
                        for cpe in cpe_matches:
                            criteria = cpe.get("criteria", "")
                            # cpe:2.3:a:vendor:product:...
                            parts = criteria.split(":")
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4]
                                break
                        if vendor:
                            break
                    if vendor:
                        break

                raw_json = json.dumps(item)

                # Upsert into cve_records. If it's already there (e.g. from KEV), preserve KEV info while updating CVSS
                await conn.execute("""
                    INSERT INTO cve_records (
                        cve_id, source, vendor_project, product, vulnerability_name,
                        date_added, short_description, cvss_score, cvss_severity,
                        raw_json, updated_at
                    ) VALUES (?, 'nvd', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        cvss_score = COALESCE(excluded.cvss_score, cve_records.cvss_score),
                        cvss_severity = COALESCE(excluded.cvss_severity, cve_records.cvss_severity),
                        vendor_project = CASE WHEN cve_records.vendor_project IS NULL OR cve_records.vendor_project = '' THEN excluded.vendor_project ELSE cve_records.vendor_project END,
                        product = CASE WHEN cve_records.product IS NULL OR cve_records.product = '' THEN excluded.product ELSE cve_records.product END,
                        short_description = CASE WHEN cve_records.short_description IS NULL OR cve_records.short_description = '' THEN excluded.short_description ELSE cve_records.short_description END,
                        updated_at = excluded.updated_at;
                """, (
                    cve_id, vendor, product, cve_id,
                    published, desc_en, score, severity,
                    raw_json, now_str
                ))
                count += 1

            await conn.commit()

        msg = f"Synced {count} recent CVEs from NIST NVD."
        logger.info(msg)
        await update_feed_status("nvd_cve", "success", count, msg)
        return count

    except Exception as e:
        err_msg = f"Error ingesting NVD CVEs: {str(e)}"
        logger.error(err_msg, exc_info=True)
        await update_feed_status("nvd_cve", "error", count, err_msg)
        return count
