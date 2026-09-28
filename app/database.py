import aiosqlite
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from app.config import DB_PATH

@asynccontextmanager
async def get_db():
    conn = await aiosqlite.connect(DB_PATH)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA journal_mode = WAL;")
    await conn.execute("PRAGMA busy_timeout = 5000;")
    await conn.execute("PRAGMA synchronous = NORMAL;")
    try:
        yield conn
    finally:
        await conn.close()

SCHEMA_MIGRATIONS = [
    ("1.0.0", "Initial CTI engine schema (cve, malware, dshield, news, ingestion_status)"),
    ("1.1.0", "Centralized semantic versioning and schema migrations control table"),
    ("1.2.0", "Add ransomware_victims table, Brazil telemetry, and EPSS scoring columns"),
    ("1.3.0", "Add critical vendor threats query and recent ransomware spotlight"),
    ("1.5.0", "Add Live Attack Map real-time telemetry streaming and geo coordinates"),
]

async def apply_migrations(conn: aiosqlite.Connection):
    """Ensure database schema migration tracking table exists and current migrations are registered."""
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL,
            description TEXT
        );
    """)

    # Check cve_records columns for 1.2.0 migration (epss_score, epss_percentile)
    cur = await conn.execute("PRAGMA table_info(cve_records);")
    cve_cols = [row[1] for row in await cur.fetchall()]
    if cve_cols:
        if "epss_score" not in cve_cols:
            await conn.execute("ALTER TABLE cve_records ADD COLUMN epss_score REAL;")
        if "epss_percentile" not in cve_cols:
            await conn.execute("ALTER TABLE cve_records ADD COLUMN epss_percentile REAL;")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_epss ON cve_records(epss_score DESC);")

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    for version, description in SCHEMA_MIGRATIONS:
        cur = await conn.execute("SELECT version FROM schema_migrations WHERE version = ?;", (version,))
        row = await cur.fetchone()
        if not row:
            await conn.execute("""
                INSERT INTO schema_migrations (version, applied_at, description)
                VALUES (?, ?, ?);
            """, (version, now_str, description))

# For backwards compatibility if imported
get_db_connection = get_db

async def init_db():
    async with get_db() as conn:
        # CVE Records table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_records (
                cve_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                vendor_project TEXT,
                product TEXT,
                vulnerability_name TEXT,
                date_added TEXT,
                short_description TEXT,
                required_action TEXT,
                due_date TEXT,
                known_ransomware_campaign_use TEXT,
                cvss_score REAL,
                cvss_severity TEXT,
                epss_score REAL,
                epss_percentile REAL,
                raw_json TEXT,
                updated_at TEXT
            );
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_date ON cve_records(date_added DESC);")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_score ON cve_records(cvss_score DESC);")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_source ON cve_records(source);")
        

        # Malware Samples table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS malware_samples (
                sha256_hash TEXT PRIMARY KEY,
                md5_hash TEXT,
                sha1_hash TEXT,
                first_seen TEXT,
                file_name TEXT,
                file_type TEXT,
                signature TEXT,
                reporter TEXT,
                delivery_method TEXT,
                tags TEXT,
                raw_json TEXT,
                updated_at TEXT
            );
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_malware_date ON malware_samples(first_seen DESC);")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_malware_sig ON malware_samples(signature);")

        # Ransomware Victims table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS ransomware_victims (
                id TEXT PRIMARY KEY,
                victim_name TEXT NOT NULL,
                group_name TEXT NOT NULL,
                country TEXT,
                activity TEXT,
                domain TEXT,
                discovered TEXT,
                attackdate TEXT,
                description TEXT,
                claim_url TEXT,
                screenshot TEXT,
                url TEXT,
                raw_json TEXT,
                updated_at TEXT
            );
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_ransomware_group ON ransomware_victims(group_name);")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_ransomware_country ON ransomware_victims(country);")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_ransomware_discovered ON ransomware_victims(discovered DESC);")

        # DShield Infocon
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS dshield_infocon (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                status TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                raw_json TEXT
            );
        """)

        # DShield Top Attacking Sources
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS dshield_sources (
                ip TEXT PRIMARY KEY,
                attacks INTEGER,
                count INTEGER,
                firstseen TEXT,
                lastseen TEXT,
                as_name TEXT,
                updated_at TEXT
            );
        """)

        # DShield Top Targeted Ports
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS dshield_ports (
                port INTEGER PRIMARY KEY,
                count INTEGER,
                records INTEGER,
                targets INTEGER,
                service TEXT,
                updated_at TEXT
            );
        """)

        # CTI News
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS cti_news (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                link TEXT NOT NULL,
                source TEXT NOT NULL,
                published_date TEXT,
                snippet TEXT,
                updated_at TEXT
            );
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_news_date ON cti_news(published_date DESC);")

        # Feeds ingestion status
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS ingestion_status (
                feed_name TEXT PRIMARY KEY,
                last_sync TEXT,
                status TEXT,
                items_count INTEGER DEFAULT 0,
                message TEXT
            );
        """)

        # Seed feeds in ingestion_status if not present
        feeds = ["cisa_kev", "nvd_cve", "dshield", "malware_bazaar", "news_feed", "ransomware_live", "epss"]
        for feed in feeds:
            await conn.execute("""
                INSERT OR IGNORE INTO ingestion_status (feed_name, last_sync, status, items_count, message)
                VALUES (?, NULL, 'never_run', 0, 'Awaiting initial ingestion');
            """, (feed,))

        # Apply schema migrations tracking
        await apply_migrations(conn)

        await conn.commit()

async def get_schema_migrations() -> List[Dict[str, Any]]:
    """Return all applied schema migrations ordered by applied_at."""
    async with get_db() as conn:
        cursor = await conn.execute("SELECT version, applied_at, description FROM schema_migrations ORDER BY applied_at ASC;")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

async def update_feed_status(feed_name: str, status: str, items_count: int = 0, message: str = ""):
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    async with get_db() as conn:
        await conn.execute("""
            INSERT INTO ingestion_status (feed_name, last_sync, status, items_count, message)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(feed_name) DO UPDATE SET
                last_sync = excluded.last_sync,
                status = excluded.status,
                items_count = excluded.items_count,
                message = excluded.message;
        """, (feed_name, now_str, status, items_count, message))
        await conn.commit()

async def get_all_feed_statuses() -> List[Dict[str, Any]]:
    async with get_db() as conn:
        cursor = await conn.execute("SELECT feed_name, last_sync, status, items_count, message FROM ingestion_status;")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

async def get_dashboard_stats() -> Dict[str, Any]:
    async with get_db() as conn:
        # Total CVEs
        cur = await conn.execute("SELECT COUNT(*) as count FROM cve_records;")
        row = await cur.fetchone()
        total_cves = row["count"] if row else 0

        # KEV CVEs
        cur = await conn.execute("SELECT COUNT(*) as count FROM cve_records WHERE source = 'cisa_kev';")
        row = await cur.fetchone()
        total_kev = row["count"] if row else 0

        # Critical CVEs
        cur = await conn.execute("SELECT COUNT(*) as count FROM cve_records WHERE cvss_score >= 9.0 OR UPPER(cvss_severity) = 'CRITICAL';")
        row = await cur.fetchone()
        total_critical_cves = row["count"] if row else 0

        # High CVEs
        cur = await conn.execute("SELECT COUNT(*) as count FROM cve_records WHERE (cvss_score >= 7.0 AND cvss_score < 9.0) OR UPPER(cvss_severity) = 'HIGH';")
        row = await cur.fetchone()
        total_high_cves = row["count"] if row else 0

        # Medium CVEs
        cur = await conn.execute("SELECT COUNT(*) as count FROM cve_records WHERE (cvss_score >= 4.0 AND cvss_score < 7.0) OR UPPER(cvss_severity) = 'MEDIUM';")
        row = await cur.fetchone()
        total_medium_cves = row["count"] if row else 0

        # Low CVEs
        cur = await conn.execute("SELECT COUNT(*) as count FROM cve_records WHERE (cvss_score > 0 AND cvss_score < 4.0) OR UPPER(cvss_severity) = 'LOW';")
        row = await cur.fetchone()
        total_low_cves = row["count"] if row else 0

        # Ransomware linked
        cur = await conn.execute("SELECT COUNT(*) as count FROM cve_records WHERE known_ransomware_campaign_use = 'Known';")
        row = await cur.fetchone()
        total_ransomware = row["count"] if row else 0

        # Malware samples
        cur = await conn.execute("SELECT COUNT(*) as count FROM malware_samples;")
        row = await cur.fetchone()
        total_malware = row["count"] if row else 0

        # DShield Infocon
        cur = await conn.execute("SELECT status, updated_at FROM dshield_infocon WHERE id = 1;")
        infocon_row = await cur.fetchone()
        infocon = dict(infocon_row) if infocon_row else {"status": "unknown", "updated_at": None}

        # DShield Sources count
        cur = await conn.execute("SELECT COUNT(*) as count FROM dshield_sources;")
        row = await cur.fetchone()
        total_dshield_ips = row["count"] if row else 0

        # DShield Ports count
        cur = await conn.execute("SELECT COUNT(*) as count FROM dshield_ports;")
        row = await cur.fetchone()
        total_dshield_ports = row["count"] if row else 0

        # News count
        cur = await conn.execute("SELECT COUNT(*) as count FROM cti_news;")
        row = await cur.fetchone()
        total_news = row["count"] if row else 0

        # Top 5 vendors
        cur = await conn.execute("""
            SELECT vendor_project, COUNT(*) as count 
            FROM cve_records 
            WHERE vendor_project IS NOT NULL AND TRIM(vendor_project) != '' 
            GROUP BY vendor_project 
            ORDER BY count DESC 
            LIMIT 5;
        """)
        top_vendors = [dict(r) for r in await cur.fetchall()]

        # Top 5 malware signatures/families
        cur = await conn.execute("""
            SELECT signature, COUNT(*) as count 
            FROM malware_samples 
            WHERE signature IS NOT NULL AND TRIM(signature) != '' AND LOWER(signature) != 'n/a'
            GROUP BY signature 
            ORDER BY count DESC 
            LIMIT 5;
        """)
        top_malware = [dict(r) for r in await cur.fetchall()]

        # Top 5 recent KEVs (spotlight)
        cur = await conn.execute("""
            SELECT cve_id, vendor_project, product, vulnerability_name, date_added, due_date, known_ransomware_campaign_use, cvss_score, cvss_severity
            FROM cve_records 
            WHERE source = 'cisa_kev'
            ORDER BY date_added DESC 
            LIMIT 5;
        """)
        recent_kevs = [dict(r) for r in await cur.fetchall()]

        # Top 5 attacked ports
        cur = await conn.execute("""
            SELECT port, service, count, records, targets 
            FROM dshield_ports 
            ORDER BY records DESC 
            LIMIT 5;
        """)
        top_ports = [dict(r) for r in await cur.fetchall()]

        # Top 5 recent CTI alerts
        cur = await conn.execute("""
            SELECT id, title, source, published_date, link, snippet
            FROM cti_news 
            ORDER BY published_date DESC, updated_at DESC 
            LIMIT 5;
        """)
        recent_news = [dict(r) for r in await cur.fetchall()]

        # Total Ransomware Victims
        cur = await conn.execute("SELECT COUNT(*) as count FROM ransomware_victims;")
        row = await cur.fetchone()
        total_ransomware_victims = row["count"] if row else 0

        # Brazil Ransomware Victims
        cur = await conn.execute("SELECT COUNT(*) as count FROM ransomware_victims WHERE UPPER(country) = 'BR' OR UPPER(country) = 'BRAZIL';")
        row = await cur.fetchone()
        total_brazil_victims = row["count"] if row else 0

        # Top 5 Ransomware Groups
        cur = await conn.execute("""
            SELECT group_name, COUNT(*) as count 
            FROM ransomware_victims 
            WHERE group_name IS NOT NULL AND TRIM(group_name) != '' 
            GROUP BY group_name 
            ORDER BY count DESC 
            LIMIT 5;
        """)
        top_ransomware_groups = [dict(r) for r in await cur.fetchall()]

        cvss_distribution = {
            "critical": total_critical_cves,
            "high": total_high_cves,
            "medium": total_medium_cves,
            "low": total_low_cves,
            "scored_total": total_critical_cves + total_high_cves + total_medium_cves + total_low_cves
        }

        
        # Recent Critical Vendors (Vendors with recent critical/KEV exploits)
        cur = await conn.execute("""
            SELECT c1.vendor_project, c1.product, c1.cve_id, c1.vulnerability_name, 
                   c1.cvss_score, c1.cvss_severity, c1.source, c1.date_added, 
                   c1.known_ransomware_campaign_use, c1.epss_score
            FROM cve_records c1
            INNER JOIN (
                SELECT vendor_project, MAX(date_added) as max_date
                FROM cve_records
                WHERE (source = 'cisa_kev' OR cvss_score >= 8.5)
                  AND vendor_project IS NOT NULL AND TRIM(vendor_project) != ''
                GROUP BY vendor_project
            ) c2 ON c1.vendor_project = c2.vendor_project AND c1.date_added = c2.max_date
            ORDER BY c1.date_added DESC
            LIMIT 5;
        """)
        recent_critical_vendors = [dict(r) for r in await cur.fetchall()]

        # Recent Ransomware Victims (Top 5)
        cur = await conn.execute("""
            SELECT id, victim_name, group_name, country, activity, domain, discovered, attackdate
            FROM ransomware_victims
            ORDER BY discovered DESC, updated_at DESC
            LIMIT 5;
        """)
        recent_ransomware_victims = [dict(r) for r in await cur.fetchall()]

        return {
            "recent_critical_vendors": recent_critical_vendors,
            "recent_ransomware_victims": recent_ransomware_victims,
            "total_cves": total_cves,
            "total_kev": total_kev,
            "total_critical_cves": total_critical_cves,
            "total_high_cves": total_high_cves,
            "total_medium_cves": total_medium_cves,
            "total_low_cves": total_low_cves,
            "total_ransomware": total_ransomware,
            "total_malware": total_malware,
            "infocon": infocon,
            "total_dshield_ips": total_dshield_ips,
            "total_dshield_ports": total_dshield_ports,
            "total_news": total_news,
            "total_ransomware_victims": total_ransomware_victims,
            "total_brazil_victims": total_brazil_victims,
            "top_ransomware_groups": top_ransomware_groups,
            "cvss_distribution": cvss_distribution,
            "top_vendors": top_vendors,
            "top_malware": top_malware,
            "recent_kevs": recent_kevs,
            "top_ports": top_ports,
            "recent_news": recent_news
        }
