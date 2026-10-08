import aiosqlite
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from app.config import DB_PATH
from app.credential_store import openphish_is_enabled
from app.news_dates import normalize_news_date

@asynccontextmanager
async def get_db():
    conn = await aiosqlite.connect(DB_PATH)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA foreign_keys = ON;")
    await conn.execute("PRAGMA journal_mode = WAL;")
    await conn.execute("PRAGMA busy_timeout = 30000;")
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
    ("1.6.0", "Add credential leak check validation and breach lookup endpoints"),
    ("1.7.0", "Add asset watchlist table and remediation tracking"),
    ("1.8.1", "Add normalized IOC correlation and connector health without changing the v1.7 dashboard"),
    ("1.10.0", "Add source-aware IOC expiry and ATT&CK knowledge storage for expanded public CTI"),
    ("1.11.7", "Add normalized CTI news publication timestamps for chronological ordering"),
    ("1.12.0", "Add persistent organization exposure alerts to the Watchlist"),
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

    cur = await conn.execute("PRAGMA table_info(ioc_sources);")
    source_cols = [row[1] for row in await cur.fetchall()]
    if source_cols:
        if "expires_at" not in source_cols:
            await conn.execute("ALTER TABLE ioc_sources ADD COLUMN expires_at TEXT;")
        if "active" not in source_cols:
            await conn.execute("ALTER TABLE ioc_sources ADD COLUMN active INTEGER NOT NULL DEFAULT 1;")

    cur = await conn.execute("PRAGMA table_info(cti_news);")
    news_cols = [row[1] for row in await cur.fetchall()]
    if news_cols:
        if "published_at" not in news_cols:
            await conn.execute("ALTER TABLE cti_news ADD COLUMN published_at TEXT;")
        cur = await conn.execute(
            "SELECT id, published_date FROM cti_news WHERE published_at IS NULL;"
        )
        for row in await cur.fetchall():
            normalized = normalize_news_date(row[1])
            if normalized:
                await conn.execute(
                    "UPDATE cti_news SET published_at = ? WHERE id = ?;",
                    (normalized, row[0]),
                )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_news_published_at "
            "ON cti_news(published_at DESC);"
        )

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
                published_at TEXT,
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

        await conn.executescript("""
        CREATE TABLE IF NOT EXISTS watchlist (
            id TEXT PRIMARY KEY,
            item_type TEXT NOT NULL, -- vendor, product, cve
            value TEXT NOT NULL,
            notes TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_watchlist_type ON watchlist(item_type);
        CREATE INDEX IF NOT EXISTS idx_watchlist_val ON watchlist(value);

        CREATE TABLE IF NOT EXISTS watchlist_alerts (
            id TEXT PRIMARY KEY,
            watchlist_id TEXT NOT NULL,
            source_type TEXT NOT NULL,
            source_name TEXT NOT NULL,
            artifact_id TEXT NOT NULL,
            title TEXT NOT NULL,
            matched_value TEXT NOT NULL,
            matched_field TEXT,
            severity TEXT NOT NULL DEFAULT 'HIGH',
            evidence TEXT,
            reference_url TEXT,
            source_date TEXT,
            detected_at TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(watchlist_id, source_type, artifact_id),
            FOREIGN KEY(watchlist_id) REFERENCES watchlist(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_watchlist_alerts_target
            ON watchlist_alerts(watchlist_id, detected_at DESC);
        CREATE INDEX IF NOT EXISTS idx_watchlist_alerts_date
            ON watchlist_alerts(source_date DESC, detected_at DESC);
""")

        # Normalized threat indicators. The deterministic id is derived from
        # indicator type + normalized value, allowing several providers to
        # correlate observations without duplicating the IOC itself.
        await conn.executescript("""
        CREATE TABLE IF NOT EXISTS normalized_iocs (
            id TEXT PRIMARY KEY,
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL,
            normalized_value TEXT NOT NULL,
            threat_type TEXT,
            malware_family TEXT,
            confidence INTEGER NOT NULL DEFAULT 50 CHECK(confidence BETWEEN 0 AND 100),
            severity TEXT NOT NULL DEFAULT 'MEDIUM',
            source_name TEXT NOT NULL,
            source_id TEXT,
            source_url TEXT,
            reference_url TEXT,
            first_seen TEXT,
            last_seen TEXT,
            ingested_at TEXT,
            updated_at TEXT,
            expires_at TEXT,
            active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
            revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1)),
            tags TEXT,
            country TEXT,
            asn INTEGER,
            port INTEGER,
            protocol TEXT,
            tlp TEXT NOT NULL DEFAULT 'CLEAR',
            raw_metadata TEXT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_ioc_type_value
            ON normalized_iocs(indicator_type, normalized_value);
        CREATE INDEX IF NOT EXISTS idx_ioc_active_confidence
            ON normalized_iocs(active, confidence DESC);
        CREATE INDEX IF NOT EXISTS idx_ioc_threat ON normalized_iocs(threat_type);
        CREATE INDEX IF NOT EXISTS idx_ioc_malware ON normalized_iocs(malware_family);

        CREATE TABLE IF NOT EXISTS ioc_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_id TEXT NOT NULL,
            source_name TEXT NOT NULL,
            source_id TEXT,
            first_seen TEXT,
            last_seen TEXT,
            confidence INTEGER,
            raw_metadata TEXT,
            UNIQUE(ioc_id, source_name),
            FOREIGN KEY(ioc_id) REFERENCES normalized_iocs(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_ioc_sources_ioc ON ioc_sources(ioc_id);

        CREATE TABLE IF NOT EXISTS connector_health (
            source_name TEXT PRIMARY KEY,
            category TEXT NOT NULL,
            state TEXT NOT NULL,
            last_attempt TEXT,
            last_success TEXT,
            duration_seconds REAL NOT NULL DEFAULT 0,
            items_received INTEGER NOT NULL DEFAULT 0,
            items_created INTEGER NOT NULL DEFAULT 0,
            items_updated INTEGER NOT NULL DEFAULT 0,
            items_dropped INTEGER NOT NULL DEFAULT 0,
            items_duplicated INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            http_code INTEGER,
            rate_limit_info TEXT,
            next_run TEXT,
            latency_ms REAL NOT NULL DEFAULT 0,
            newest_data_age TEXT,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS vendor_advisories (
            id TEXT PRIMARY KEY,
            vendor TEXT NOT NULL,
            product TEXT,
            advisory_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT,
            cve_ids TEXT,
            ghsa_ids TEXT,
            affected_versions TEXT,
            fixed_versions TEXT,
            workaround TEXT,
            reference_url TEXT,
            published_date TEXT,
            updated_at TEXT,
            raw_json TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_vendor_advisories_vendor
            ON vendor_advisories(vendor);
        CREATE INDEX IF NOT EXISTS idx_vendor_advisories_product
            ON vendor_advisories(product);

        CREATE TABLE IF NOT EXISTS attack_knowledge (
            id TEXT PRIMARY KEY,
            object_type TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            external_id TEXT,
            aliases TEXT,
            platforms TEXT,
            tactics TEXT,
            reference_url TEXT,
            modified TEXT,
            revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1)),
            raw_json TEXT,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_attack_knowledge_type
            ON attack_knowledge(object_type, name);
        CREATE INDEX IF NOT EXISTS idx_attack_knowledge_external
            ON attack_knowledge(external_id);
        """)

        connector_sources = [
            ("cisa_kev", "Vulnerabilities"),
            ("nvd_cve", "Vulnerabilities"),
            ("epss", "Vulnerabilities"),
            ("github_advisories", "Vulnerabilities"),
            ("osv_dev", "Vulnerabilities"),
            ("malware_bazaar", "Malware & IOCs"),
            ("threatfox", "Malware & IOCs"),
            ("urlhaus", "Malware & IOCs"),
            ("dshield", "Network Intelligence"),
            ("feodo_tracker", "Network Intelligence"),
            ("sslbl", "Network Intelligence"),
            ("spamhaus_drop", "Network Intelligence"),
            ("openphish", "Phishing"),
            ("ransomware_live", "Ransomware"),
            ("news_feed", "News"),
            ("alienvault_otx", "Malware & IOCs"),
            ("circl_misp", "Malware & IOCs"),
            ("phishtank", "Phishing"),
            ("abuseipdb", "Network Intelligence"),
            ("blocklist_de", "Network Intelligence"),
            ("msrc_csaf", "Vulnerabilities"),
            ("redhat_security", "Vulnerabilities"),
            ("mitre_attack", "Threat Knowledge"),
        ]
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        for source_name, category in connector_sources:
            await conn.execute("""
                INSERT OR IGNORE INTO connector_health (
                    source_name, category, state, updated_at
                ) VALUES (?, ?, 'never_run', ?)
            """, (source_name, category, now_str))

        if not openphish_is_enabled():
            await conn.execute(
                """UPDATE connector_health SET state='disabled',
                    last_error='Disabled by configuration', updated_at=?
                    WHERE source_name='openphish'""",
                (now_str,),
            )

        # Register migrations only after every schema change above succeeded.
        await apply_migrations(conn)

        await conn.commit()

async def get_schema_migrations() -> List[Dict[str, Any]]:
    """Return all applied schema migrations ordered by applied_at."""
    async with get_db() as conn:
        cursor = await conn.execute("SELECT version, applied_at, description FROM schema_migrations ORDER BY applied_at ASC;")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

async def update_connector_health(
    source_name: str,
    category: str,
    state: str,
    duration_seconds: float = 0.0,
    items_received: int = 0,
    items_created: int = 0,
    items_updated: int = 0,
    items_dropped: int = 0,
    items_duplicated: int = 0,
    last_error: Optional[str] = None,
    http_code: Optional[int] = None,
    rate_limit_info: Optional[str] = None,
    latency_ms: float = 0.0,
    newest_data_age: Optional[str] = None,
):
    """Persist connector health without exposing credentials or response bodies."""
    valid_states = {
        "healthy", "degraded", "failed", "disabled", "rate_limited",
        "auth_required", "never_run",
    }
    if state not in valid_states:
        raise ValueError(f"Unsupported connector state: {state}")

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    safe_error = last_error[:500] if last_error else None
    async with get_db() as conn:
        cursor = await conn.execute(
            "SELECT last_success FROM connector_health WHERE source_name = ?",
            (source_name,),
        )
        existing = await cursor.fetchone()
        last_success = existing["last_success"] if existing else None
        if state == "healthy":
            last_success = now_str

        await conn.execute("""
            INSERT INTO connector_health (
                source_name, category, state, last_attempt, last_success,
                duration_seconds, items_received, items_created, items_updated,
                items_dropped, items_duplicated, last_error, http_code,
                rate_limit_info, latency_ms, newest_data_age, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_name) DO UPDATE SET
                category = excluded.category,
                state = excluded.state,
                last_attempt = excluded.last_attempt,
                last_success = COALESCE(excluded.last_success, connector_health.last_success),
                duration_seconds = excluded.duration_seconds,
                items_received = excluded.items_received,
                items_created = excluded.items_created,
                items_updated = excluded.items_updated,
                items_dropped = excluded.items_dropped,
                items_duplicated = excluded.items_duplicated,
                last_error = excluded.last_error,
                http_code = excluded.http_code,
                rate_limit_info = excluded.rate_limit_info,
                latency_ms = excluded.latency_ms,
                newest_data_age = excluded.newest_data_age,
                updated_at = excluded.updated_at
        """, (
            source_name, category, state, now_str, last_success,
            duration_seconds, items_received, items_created, items_updated,
            items_dropped, items_duplicated, safe_error, http_code,
            rate_limit_info, latency_ms, newest_data_age, now_str,
        ))
        await conn.commit()

async def get_connector_health(source_name: str) -> Optional[Dict[str, Any]]:
    """Return one connector state for provider-aware scheduling decisions."""
    async with get_db() as conn:
        cursor = await conn.execute(
            "SELECT * FROM connector_health WHERE source_name = ?",
            (source_name,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

async def get_all_connector_health() -> List[Dict[str, Any]]:
    configured_sources = {
        "cisa_kev", "nvd_cve", "epss", "github_advisories", "osv_dev",
        "malware_bazaar", "threatfox", "urlhaus", "dshield", "feodo_tracker",
        "sslbl", "spamhaus_drop", "openphish", "ransomware_live", "news_feed",
        "alienvault_otx", "circl_misp", "phishtank", "abuseipdb",
        "blocklist_de", "msrc_csaf", "redhat_security", "mitre_attack",
    }
    async with get_db() as conn:
        cursor = await conn.execute("""
            SELECT * FROM connector_health
            ORDER BY category, source_name
        """)
        connectors = [
            dict(row) for row in await cursor.fetchall()
            if row["source_name"] in configured_sources
        ]
        cursor = await conn.execute(
            "SELECT feed_name, last_sync, status, items_count, message FROM ingestion_status"
        )
        legacy = {row["feed_name"]: dict(row) for row in await cursor.fetchall()}

    state_map = {"success": "healthy", "running": "degraded", "error": "failed"}
    legacy_sources = {
        "cisa_kev", "nvd_cve", "epss", "malware_bazaar", "dshield",
        "ransomware_live", "news_feed",
    }
    for connector in connectors:
        old = legacy.get(connector["source_name"]) if connector["source_name"] in legacy_sources else None
        if old:
            connector["state"] = state_map.get(old["status"], old["status"])
            connector["last_attempt"] = old["last_sync"]
            connector["last_success"] = old["last_sync"] if connector["state"] == "healthy" else connector["last_success"]
            connector["items_received"] = old["items_count"]
            connector["last_error"] = old["message"] if connector["state"] == "failed" else None
    return connectors

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
            ORDER BY COALESCE(published_at, updated_at) DESC, updated_at DESC
            LIMIT 5;
        """)
        recent_news = [dict(r) for r in await cur.fetchall()]

        # Cross-provider IOC and knowledge metrics used by the analyst dashboard.
        cur = await conn.execute("SELECT COUNT(*) AS count FROM normalized_iocs WHERE active=1;")
        row = await cur.fetchone()
        total_active_iocs = row["count"] if row else 0

        cur = await conn.execute(
            "SELECT COUNT(*) AS count FROM normalized_iocs WHERE active=1 AND indicator_type IN ('IPv4', 'IPv6');"
        )
        row = await cur.fetchone()
        total_malicious_ips = row["count"] if row else 0

        cur = await conn.execute(
            """SELECT COUNT(*) AS count FROM normalized_iocs
               WHERE active=1 AND indicator_type='URL'
                 AND (LOWER(threat_type) LIKE '%phish%' OR source_name IN ('phishtank', 'openphish'));"""
        )
        row = await cur.fetchone()
        total_phishing_urls = row["count"] if row else 0

        cur = await conn.execute(
            """SELECT COUNT(*) AS count FROM normalized_iocs n
               WHERE n.active=1 AND (
                   SELECT COUNT(*) FROM ioc_sources s
                   WHERE s.ioc_id=n.id AND s.active=1
               ) >= 2;"""
        )
        row = await cur.fetchone()
        total_correlated_iocs = row["count"] if row else 0

        cur = await conn.execute("SELECT COUNT(*) AS count FROM vendor_advisories;")
        row = await cur.fetchone()
        total_vendor_advisories = row["count"] if row else 0

        cur = await conn.execute("SELECT COUNT(*) AS count FROM attack_knowledge WHERE revoked=0;")
        row = await cur.fetchone()
        total_attack_objects = row["count"] if row else 0

        cur = await conn.execute(
            """SELECT n.id, n.indicator_type, n.normalized_value, n.threat_type,
                      n.confidence, n.severity, n.last_seen,
                      (SELECT COUNT(*) FROM ioc_sources s
                       WHERE s.ioc_id=n.id AND s.active=1) AS source_count,
                      (SELECT GROUP_CONCAT(s.source_name, ', ')
                       FROM ioc_sources s WHERE s.ioc_id=n.id AND s.active=1) AS sources
               FROM normalized_iocs n
               WHERE n.active=1
               ORDER BY n.confidence DESC, n.last_seen DESC LIMIT 6;"""
        )
        recent_iocs = [dict(r) for r in await cur.fetchall()]

        cur = await conn.execute(
            """SELECT indicator_type, COUNT(*) AS count
               FROM normalized_iocs WHERE active=1
               GROUP BY indicator_type ORDER BY count DESC LIMIT 6;"""
        )
        top_ioc_types = [dict(r) for r in await cur.fetchall()]

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
            "total_active_iocs": total_active_iocs,
            "total_malicious_ips": total_malicious_ips,
            "total_phishing_urls": total_phishing_urls,
            "total_correlated_iocs": total_correlated_iocs,
            "total_vendor_advisories": total_vendor_advisories,
            "total_attack_objects": total_attack_objects,
            "total_ransomware_victims": total_ransomware_victims,
            "total_brazil_victims": total_brazil_victims,
            "top_ransomware_groups": top_ransomware_groups,
            "cvss_distribution": cvss_distribution,
            "top_vendors": top_vendors,
            "top_malware": top_malware,
            "recent_kevs": recent_kevs,
            "top_ports": top_ports,
            "recent_news": recent_news,
            "recent_iocs": recent_iocs,
            "top_ioc_types": top_ioc_types
        }
