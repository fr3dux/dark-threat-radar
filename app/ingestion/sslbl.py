"""SSLBL Ingestion Module (SSL Blacklist abuse.ch)
Collects malicious TLS certificates (SHA1), C2 IP blacklists, and JA3 fingerprints.
Uses recommended low-risk feeds only (excludes aggressive list).
"""

import csv
import httpx
import logging
import time
from io import StringIO
from datetime import datetime, timezone, timedelta

from app.database import get_db, update_connector_health
from app.ingestion.normalization import (
    normalize_ip, normalize_hash, generate_ioc_id,
    TYPE_IPV4, TYPE_TLS_CERT, TYPE_JA3
)
from app.ingestion.confidence import calculate_confidence, get_confidence_severity_label

logger = logging.getLogger("ingestion.sslbl")

SSL_IP_CSV_URL = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"
SSL_CERT_CSV_URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
JA3_CSV_URL = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"


def _recent(last_seen: str, days: int = 90) -> bool:
    """JA3 values are contextual; do not keep very old observations active."""
    try:
        value = datetime.strptime(last_seen[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return value >= datetime.now(timezone.utc) - timedelta(days=days)
    except (TypeError, ValueError):
        return False


async def ingest_sslbl() -> int:
    """Fetch recommended SSLBL CSV feeds and process into normalized_iocs."""
    start_time = time.time()
    source_name = "sslbl"
    category = "Network Intelligence"

    items_received = 0
    items_created = 0
    items_updated = 0
    items_dropped = 0
    last_error = None
    http_code = 200

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            # 1. Ingest SSL C2 IP Blacklist
            resp_ip = await client.get(SSL_IP_CSV_URL, headers={"User-Agent": "DarkThreatRadar/1.8.0"})
            resp_ip.raise_for_status()
            if resp_ip.status_code == 200:
                lines = [line for line in resp_ip.text.splitlines() if line and not line.startswith("#")]
                reader = csv.reader(lines)
                async with get_db() as conn:
                    for row in reader:
                        if len(row) >= 3:
                            items_received += 1
                            first_seen, raw_ip, port_str = row[0].strip(), row[1].strip(), row[2].strip()
                            reason = row[3].strip() if len(row) > 3 else "SSL C2 Botnet"
                            
                            norm_ip, ip_type = normalize_ip(raw_ip)
                            if not norm_ip:
                                items_dropped += 1
                                continue

                            ioc_id = generate_ioc_id(ip_type or TYPE_IPV4, norm_ip)
                            confidence = calculate_confidence("sslbl", ip_type or TYPE_IPV4, active=True)
                            severity = get_confidence_severity_label(confidence)
                            port = int(port_str) if port_str.isdigit() else None

                            cur = await conn.execute("SELECT id FROM normalized_iocs WHERE id = ?;", (ioc_id,))
                            if await cur.fetchone():
                                items_updated += 1
                                await conn.execute("""
                                    UPDATE normalized_iocs SET last_seen = ?, updated_at = ? WHERE id = ?;
                                """, (now_str, now_str, ioc_id))
                            else:
                                items_created += 1
                                await conn.execute("""
                                    INSERT INTO normalized_iocs (
                                        id, indicator_type, indicator_value, normalized_value,
                                        threat_type, malware_family, confidence, severity,
                                        source_name, source_url, reference_url,
                                        first_seen, last_seen, ingested_at, updated_at, active, port
                                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'https://sslbl.abuse.ch/', ?, ?, ?, ?, 1, ?);
                                """, (
                                    ioc_id, ip_type or TYPE_IPV4, raw_ip, norm_ip,
                                    "ssl_c2_botnet", reason, confidence, severity,
                                    "sslbl", SSL_IP_CSV_URL, first_seen or now_str, now_str, now_str, now_str, port
                                ))

                            await conn.execute("""
                                INSERT INTO ioc_sources (ioc_id, source_name, first_seen, last_seen, confidence)
                                VALUES (?, 'sslbl', ?, ?, ?)
                                ON CONFLICT(ioc_id, source_name) DO UPDATE SET last_seen = excluded.last_seen;
                            """, (ioc_id, first_seen or now_str, now_str, confidence))

                    await conn.commit()

            # 2. Ingest SSL Cert Fingerprints (SHA1)
            resp_cert = await client.get(SSL_CERT_CSV_URL, headers={"User-Agent": "DarkThreatRadar/1.8.0"})
            resp_cert.raise_for_status()
            if resp_cert.status_code == 200:
                lines = [line for line in resp_cert.text.splitlines() if line and not line.startswith("#")]
                reader = csv.reader(lines)
                async with get_db() as conn:
                    for row in reader:
                        if len(row) >= 3:
                            items_received += 1
                            first_seen, sha1_fingerprint, reason = row[0].strip(), row[1].strip(), row[2].strip()
                            norm_sha1, _ = normalize_hash(sha1_fingerprint)
                            if not norm_sha1:
                                items_dropped += 1
                                continue

                            ioc_id = generate_ioc_id(TYPE_TLS_CERT, norm_sha1)
                            confidence = calculate_confidence("sslbl", TYPE_TLS_CERT, active=True)
                            severity = get_confidence_severity_label(confidence)

                            cur = await conn.execute("SELECT id FROM normalized_iocs WHERE id = ?;", (ioc_id,))
                            if await cur.fetchone():
                                items_updated += 1
                                await conn.execute("""
                                    UPDATE normalized_iocs SET last_seen = ?, updated_at = ? WHERE id = ?;
                                """, (now_str, now_str, ioc_id))
                            else:
                                items_created += 1
                                await conn.execute("""
                                    INSERT INTO normalized_iocs (
                                        id, indicator_type, indicator_value, normalized_value,
                                        threat_type, malware_family, confidence, severity,
                                        source_name, source_url, reference_url,
                                        first_seen, last_seen, ingested_at, updated_at, active
                                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'https://sslbl.abuse.ch/', ?, ?, ?, ?, 1);
                                """, (
                                    ioc_id, TYPE_TLS_CERT, sha1_fingerprint, norm_sha1,
                                    "malicious_ssl_cert", reason, confidence, severity,
                                    "sslbl", SSL_CERT_CSV_URL, first_seen or now_str, now_str, now_str, now_str
                                ))

                            await conn.execute("""
                                INSERT INTO ioc_sources (ioc_id, source_name, first_seen, last_seen, confidence)
                                VALUES (?, 'sslbl', ?, ?, ?)
                                ON CONFLICT(ioc_id, source_name) DO UPDATE SET last_seen = excluded.last_seen;
                            """, (ioc_id, first_seen or now_str, now_str, confidence))

                    await conn.commit()

            # 3. Ingest JA3 Fingerprints (capped lower confidence)
            resp_ja3 = await client.get(JA3_CSV_URL, headers={"User-Agent": "DarkThreatRadar/1.8.0"})
            resp_ja3.raise_for_status()
            if resp_ja3.status_code == 200:
                lines = [line for line in resp_ja3.text.splitlines() if line and not line.startswith("#")]
                reader = csv.reader(lines)
                async with get_db() as conn:
                    for row in reader:
                        if len(row) >= 4:
                            items_received += 1
                            ja3_md5, first_seen, observed_last_seen, reason = (
                                row[0].strip(), row[1].strip(), row[2].strip(), row[3].strip()
                            )
                            if len(ja3_md5) != 32:
                                items_dropped += 1
                                continue
                            norm_ja3 = ja3_md5.lower()
                            ioc_id = generate_ioc_id(TYPE_JA3, norm_ja3)

                            # JA3 capped confidence max 45 due to FP risk
                            is_active = _recent(observed_last_seen)
                            confidence = calculate_confidence("sslbl", TYPE_JA3, active=is_active)
                            severity = get_confidence_severity_label(confidence)

                            cur = await conn.execute("SELECT id FROM normalized_iocs WHERE id = ?;", (ioc_id,))
                            if await cur.fetchone():
                                items_updated += 1
                                await conn.execute("""
                                    UPDATE normalized_iocs SET last_seen = ?, active = ?,
                                        confidence = ?, severity = ?, updated_at = ? WHERE id = ?;
                                """, (observed_last_seen or now_str, int(is_active), confidence,
                                      severity, now_str, ioc_id))
                            else:
                                items_created += 1
                                await conn.execute("""
                                    INSERT INTO normalized_iocs (
                                        id, indicator_type, indicator_value, normalized_value,
                                        threat_type, malware_family, confidence, severity,
                                        source_name, source_url, reference_url,
                                        first_seen, last_seen, ingested_at, updated_at, active
                                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'https://sslbl.abuse.ch/', ?, ?, ?, ?, ?);
                                """, (
                                    ioc_id, TYPE_JA3, ja3_md5, norm_ja3,
                                    "ja3_fingerprint", reason, confidence, severity,
                                    "sslbl", JA3_CSV_URL, first_seen or now_str,
                                    observed_last_seen or now_str, now_str, now_str, int(is_active)
                                ))

                            await conn.execute("""
                                INSERT INTO ioc_sources (ioc_id, source_name, first_seen, last_seen, confidence)
                                VALUES (?, 'sslbl', ?, ?, ?)
                                ON CONFLICT(ioc_id, source_name) DO UPDATE SET last_seen = excluded.last_seen;
                            """, (ioc_id, first_seen or now_str, observed_last_seen or now_str, confidence))

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
        logger.info(f"SSLBL ingested {items_created} new, {items_updated} updated items in {duration}s")
        return items_created + items_updated

    except Exception as e:
        last_error = str(e)
        logger.error(f"SSLBL ingestion error: {e}")
        await update_connector_health(
            source_name, category, "failed",
            duration_seconds=round(time.time() - start_time, 2),
            last_error=last_error,
            http_code=getattr(getattr(e, "response", None), "status_code", None)
        )
        return 0
