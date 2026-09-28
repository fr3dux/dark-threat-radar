import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx

from app.database import get_db, update_feed_status

logger = logging.getLogger("ingestion.ransomware_live")

RECENT_VICTIMS_URL = "https://api.ransomware.live/v2/recentvictims"
BRAZIL_VICTIMS_URL = "https://api.ransomware.live/v2/countryvictims/BR"


def generate_victim_id(item: Dict[str, Any]) -> str:
    """Generate a stable unique identifier for a ransomware victim entry."""
    if item.get("id"):
        return str(item["id"]).strip()
    url = item.get("url", "")
    if "/id/" in url:
        return url.rstrip("/").split("/")[-1]
    victim = item.get("victim") or item.get("victim_name") or "unknown"
    group = item.get("group") or item.get("group_name") or "unknown"
    disc = item.get("discovered") or item.get("attackdate") or ""
    country = item.get("country") or ""
    raw_key = f"{victim.lower()}_{group.lower()}_{disc}_{country.lower()}"
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:24]


async def fetch_endpoint(client: httpx.AsyncClient, url: str) -> List[Dict[str, Any]]:
    """Fetch and parse JSON from Ransomware.live endpoints with graceful fallback."""
    try:
        resp = await client.get(url, follow_redirects=True)
        if resp.status_code == 200:
            content_type = resp.headers.get("content-type", "")
            if "application/json" in content_type:
                data = resp.json()
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict) and "victims" in data:
                    return data["victims"]
            else:
                try:
                    data = resp.json()
                    if isinstance(data, list):
                        return data
                except Exception:
                    logger.warning(f"Endpoint {url} returned non-JSON content: {resp.text[:100]}")
        else:
            logger.warning(f"Endpoint {url} responded with HTTP {resp.status_code}")
    except Exception as e:
        logger.warning(f"Failed to query {url}: {e}")
    return []


async def ingest_ransomware_live() -> int:
    """Ingest recent victims and Brazil telemetry from Ransomware.live v2."""
    logger.info("Starting Ransomware.live v2 ingestion...")
    await update_feed_status("ransomware_live", "running", 0, "Ingesting Ransomware.live v2 catalog...")

    count = 0
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    try:
        headers = {
            "User-Agent": "ThreatRadar-CTI/1.2",
            "Accept": "application/json",
        }
        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            recent_victims = await fetch_endpoint(client, RECENT_VICTIMS_URL)
            brazil_victims = await fetch_endpoint(client, BRAZIL_VICTIMS_URL)

        # Ensure country is tagged BR for victims from the Brazil endpoint
        for b_item in brazil_victims:
            if not b_item.get("country"):
                b_item["country"] = "BR"

        # Combine all victim records
        all_victims: List[Dict[str, Any]] = recent_victims + brazil_victims
        logger.info(f"Retrieved {len(recent_victims)} recent victims and {len(brazil_victims)} Brazil victims from Ransomware.live")

        async with get_db() as conn:
            for item in all_victims:
                victim_name = item.get("victim") or item.get("victim_name") or ""
                victim_name = victim_name.strip()
                if not victim_name:
                    continue

                group_name = item.get("group") or item.get("group_name") or "unknown"
                group_name = group_name.strip().lower()
                discovered = item.get("discovered") or item.get("attackdate") or ""
                attackdate = item.get("attackdate") or ""
                country = (item.get("country") or "").strip().upper()
                activity = item.get("activity") or ""
                domain = item.get("domain") or ""
                description = item.get("description") or ""
                claim_url = item.get("claim_url") or ""
                screenshot = item.get("screenshot") or ""
                url = item.get("url") or ""
                victim_id = generate_victim_id(item)
                raw_json = json.dumps(item)

                await conn.execute("""
                    INSERT INTO ransomware_victims (
                        id, victim_name, group_name, country, activity, domain,
                        discovered, attackdate, description, claim_url, screenshot,
                        url, raw_json, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        victim_name = excluded.victim_name,
                        group_name = excluded.group_name,
                        country = excluded.country,
                        activity = excluded.activity,
                        domain = excluded.domain,
                        discovered = excluded.discovered,
                        attackdate = excluded.attackdate,
                        description = excluded.description,
                        claim_url = excluded.claim_url,
                        screenshot = excluded.screenshot,
                        url = excluded.url,
                        raw_json = excluded.raw_json,
                        updated_at = excluded.updated_at;
                """, (
                    victim_id, victim_name, group_name, country, activity, domain,
                    discovered, attackdate, description, claim_url, screenshot,
                    url, raw_json, now_str
                ))
                count += 1

            await conn.commit()

        msg = f"Synced {count} ransomware victims successfully (including Brazil telemetry)."
        logger.info(msg)
        await update_feed_status("ransomware_live", "success", count, msg)
        return count

    except Exception as e:
        err_msg = f"Error ingesting Ransomware.live: {str(e)}"
        logger.error(err_msg, exc_info=True)
        await update_feed_status("ransomware_live", "error", count, err_msg)
        return count
