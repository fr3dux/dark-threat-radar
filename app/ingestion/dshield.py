import logging
import json
import httpx
from datetime import datetime, timezone
from app.database import get_db, update_feed_status

logger = logging.getLogger("ingestion.dshield")

INFOCON_URL = "https://isc.sans.edu/api/infocon?json"
TOP_SOURCES_URL = "https://isc.sans.edu/api/sources/attacks/25?json"
TOP_PORTS_URL = "https://isc.sans.edu/api/topports/records/25?json"

PORT_SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    2375: "Docker-HTTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB"
}

async def ingest_dshield() -> int:
    logger.info("Starting DShield telemetry ingestion...")
    await update_feed_status("dshield", "running", 0, "Ingesting SANS ISC DShield telemetry...")

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total_records = 0

    try:
        async with httpx.AsyncClient(timeout=20.0, headers={"User-Agent": "ThreatRadar-CTI/1.0"}) as client:
            # 1. Infocon
            infocon_resp = await client.get(INFOCON_URL)
            infocon_resp.raise_for_status()
            infocon_data = infocon_resp.json()
            infocon_status = str(infocon_data.get("status", "green")).lower()

            # 2. Top Sources
            sources_resp = await client.get(TOP_SOURCES_URL)
            sources_resp.raise_for_status()
            sources_data = sources_resp.json()

            # 3. Top Ports
            ports_resp = await client.get(TOP_PORTS_URL)
            ports_resp.raise_for_status()
            ports_data = ports_resp.json()

        async with get_db() as conn:
            # Save infocon
            await conn.execute("""
                INSERT INTO dshield_infocon (id, status, updated_at, raw_json)
                VALUES (1, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status = excluded.status,
                    updated_at = excluded.updated_at,
                    raw_json = excluded.raw_json;
            """, (infocon_status, now_str, json.dumps(infocon_data)))

            # Save top attacking sources
            if isinstance(sources_data, list):
                for src in sources_data:
                    ip = src.get("ip")
                    if not ip:
                        continue
                    attacks = int(src.get("attacks", 0))
                    count = int(src.get("count", 0))
                    firstseen = str(src.get("firstseen", ""))
                    lastseen = str(src.get("lastseen", ""))
                    as_name = str(src.get("asname", "") or src.get("name", ""))

                    await conn.execute("""
                        INSERT INTO dshield_sources (ip, attacks, count, firstseen, lastseen, as_name, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(ip) DO UPDATE SET
                            attacks = excluded.attacks,
                            count = excluded.count,
                            firstseen = excluded.firstseen,
                            lastseen = excluded.lastseen,
                            as_name = excluded.as_name,
                            updated_at = excluded.updated_at;
                    """, (ip, attacks, count, firstseen, lastseen, as_name, now_str))
                    total_records += 1

            # Save top targeted ports
            if isinstance(ports_data, dict):
                for k, v in ports_data.items():
                    if isinstance(v, dict) and "targetport" in v:
                        port = int(v.get("targetport", 0))
                        records = int(v.get("records", 0))
                        targets = int(v.get("targets", 0))
                        sources = int(v.get("sources", 0))
                        service = PORT_SERVICE_MAP.get(port, f"Port/{port}")

                        await conn.execute("""
                            INSERT INTO dshield_ports (port, count, records, targets, service, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                            ON CONFLICT(port) DO UPDATE SET
                                count = excluded.count,
                                records = excluded.records,
                                targets = excluded.targets,
                                service = excluded.service,
                                updated_at = excluded.updated_at;
                        """, (port, sources, records, targets, service, now_str))
                        total_records += 1

            await conn.commit()

        msg = f"Synced Infocon ({infocon_status.upper()}) and {total_records} telemetry indicators."
        logger.info(msg)
        await update_feed_status("dshield", "success", total_records, msg)
        return total_records

    except Exception as e:
        err_msg = f"Error ingesting DShield: {str(e)}"
        logger.error(err_msg, exc_info=True)
        await update_feed_status("dshield", "error", total_records, err_msg)
        return total_records
