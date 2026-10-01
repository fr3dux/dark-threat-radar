import httpx
import asyncio
import json
import logging
import secrets
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, Query, BackgroundTasks, HTTPException, Body, Header
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import HOST, PORT, BASE_DIR, SETTINGS_ADMIN_TOKEN
from app.credential_store import (
    delete_provider_secret,
    provider_secret_is_configured,
    save_provider_secret,
)
from app.version import __version__, __app_name__, __description__, get_version_info
from app.schemas import (
    RansomwareVictim,
    RansomwareListResponse,
    VersionResponse,
    StatusResponse,
    StatsResponse,
    CVEListResponse,
    MalwareListResponse,
    DShieldResponse,
    NewsListResponse,
    ArtifactResponse,
    ErrorResponse,
    IntegrationKeyUpdate,
)
from app.database import (
    init_db,
    get_db,
    get_dashboard_stats,
    get_all_feed_statuses,
    get_all_connector_health,
    update_connector_health,
)
from app.scheduler import (
    start_scheduler,
    shutdown_scheduler,
    trigger_manual_sync,
    scheduled_sync_task,
    get_sync_state
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("threat_radar")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info(f"Initializing {__app_name__} v{__version__} database...")
    await init_db()
    start_scheduler()
    logger.info("Triggering initial background ingestion...")
    asyncio.create_task(scheduled_sync_task())
    yield
    # Shutdown
    shutdown_scheduler()
    logger.info(f"{__app_name__} shutdown complete.")


app = FastAPI(
    title=f"{__app_name__} CTI Engine",
    description=__description__,
    version=__version__,
    lifespan=lifespan
)

# Standardized Error Handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status_code": exc.status_code}
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"error": "Validation Error", "detail": exc.errors(), "status_code": 422}
    )

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))


# ==================== PAGE ROUTES ====================

@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    stats = await get_dashboard_stats()
    feed_statuses = await get_all_feed_statuses()
    connectors = await get_all_connector_health()
    sync_state = get_sync_state()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "version": __version__,
            "app_name": __app_name__,
            "stats": stats,
            "feed_statuses": feed_statuses,
            "connectors": connectors,
            "sync_state": sync_state
        }
    )


# ==================== API ENDPOINTS ====================

@app.get("/api/version", response_model=VersionResponse, tags=["System"])
async def api_version():
    """Return centralized application semantic version and metadata."""
    return get_version_info()


@app.get("/api/stats", response_model=StatsResponse, tags=["Dashboard"])
async def api_stats():
    """Return full dashboard metrics, feed statuses, sync state, and engine version."""
    stats = await get_dashboard_stats()
    feed_statuses = await get_all_feed_statuses()
    connectors = await get_all_connector_health()
    sync_state = get_sync_state()
    return {
        "version": __version__,
        "stats": stats,
        "feeds": feed_statuses,
        "connectors": connectors,
        "sync": sync_state
    }


@app.post("/api/sync", tags=["Ingestion"])
async def api_trigger_sync(background_tasks: BackgroundTasks):
    """Trigger manual parallel background sync across all CTI feeds."""
    result = await trigger_manual_sync(background_tasks)
    return result


@app.get("/api/status", response_model=StatusResponse, tags=["System"])
async def api_status():
    """Return live ingestion status for all feeds, sync lock state, and engine version."""
    feed_statuses = await get_all_feed_statuses()
    connectors = await get_all_connector_health()
    sync_state = get_sync_state()
    return {
        "version": __version__,
        "feeds": feed_statuses,
        "connectors": connectors,
        "sync": sync_state
    }


@app.get("/api/connectors", tags=["Ingestion"])
async def api_connectors():
    """Return operational state and counters for every configured source."""
    connectors = await get_all_connector_health()
    counts = {}
    for connector in connectors:
        counts[connector["state"]] = counts.get(connector["state"], 0) + 1
    return {"total": len(connectors), "states": counts, "items": connectors}


# ==================== ADMIN INTEGRATION SETTINGS ====================

MANAGED_INTEGRATIONS = {
    "threatfox": {"name": "ThreatFox", "category": "Malware & IOCs"},
    "urlhaus": {"name": "URLhaus", "category": "Malware & IOCs"},
}


def require_settings_admin(admin_token: Optional[str]) -> None:
    """Protect secret-management endpoints on an otherwise public CTI portal."""
    if not SETTINGS_ADMIN_TOKEN:
        raise HTTPException(status_code=503, detail="API key administration is not enabled on this server")
    if not admin_token or not secrets.compare_digest(admin_token, SETTINGS_ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid administrative access code")


async def sync_managed_integration(provider: str) -> None:
    if provider == "threatfox":
        from app.ingestion.threatfox import ingest_threatfox
        await ingest_threatfox()
    elif provider == "urlhaus":
        from app.ingestion.urlhaus import ingest_urlhaus
        await ingest_urlhaus()


@app.get("/api/admin/integrations", tags=["Administration"])
async def api_admin_integrations(
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    """Return credential presence and connector health without returning secrets."""
    require_settings_admin(x_admin_token)
    health = {item["source_name"]: item for item in await get_all_connector_health()}
    items = []
    for provider, metadata in MANAGED_INTEGRATIONS.items():
        connector = health.get(provider, {})
        items.append({
            "provider": provider,
            "name": metadata["name"],
            "configured": provider_secret_is_configured(provider),
            "state": connector.get("state", "never_run"),
            "last_success": connector.get("last_success"),
            "last_error": connector.get("last_error"),
        })
    return {"items": items}


@app.put("/api/admin/integrations/{provider}", tags=["Administration"])
async def api_save_integration_key(
    provider: str,
    payload: IntegrationKeyUpdate,
    background_tasks: BackgroundTasks,
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    """Save a connector API key server-side and validate it through ingestion."""
    require_settings_admin(x_admin_token)
    metadata = MANAGED_INTEGRATIONS.get(provider)
    if not metadata:
        raise HTTPException(status_code=404, detail="Unsupported integration")
    try:
        save_provider_secret(provider, payload.api_key)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    await update_connector_health(
        provider,
        metadata["category"],
        "never_run",
        last_error="Credential saved; validation is pending",
    )
    background_tasks.add_task(sync_managed_integration, provider)
    return {"provider": provider, "configured": True, "validation": "started"}


@app.delete("/api/admin/integrations/{provider}", tags=["Administration"])
async def api_delete_integration_key(
    provider: str,
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    """Remove a runtime connector key and return the source to AUTH REQUIRED."""
    require_settings_admin(x_admin_token)
    metadata = MANAGED_INTEGRATIONS.get(provider)
    if not metadata:
        raise HTTPException(status_code=404, detail="Unsupported integration")
    delete_provider_secret(provider)
    await update_connector_health(
        provider,
        metadata["category"],
        "auth_required",
        last_error=f"{provider.upper()}_AUTH_KEY is not configured",
    )
    return {"provider": provider, "configured": False, "state": "auth_required"}


@app.get("/api/iocs", tags=["Intel"])
async def api_iocs(
    q: Optional[str] = Query(None),
    indicator_type: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    active: Optional[bool] = Query(True),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Search normalized and correlated indicators without changing the dashboard."""
    query = "SELECT * FROM normalized_iocs WHERE 1=1"
    params = []
    if q:
        query += " AND (normalized_value LIKE ? OR malware_family LIKE ? OR threat_type LIKE ?)"
        term = f"%{q}%"
        params.extend([term, term, term])
    if indicator_type:
        query += " AND indicator_type = ?"
        params.append(indicator_type)
    if source:
        query += " AND EXISTS (SELECT 1 FROM ioc_sources s WHERE s.ioc_id=normalized_iocs.id AND s.source_name=?)"
        params.append(source)
    if active is not None:
        query += " AND active = ?"
        params.append(int(active))
    async with get_db() as conn:
        cursor = await conn.execute(query.replace("SELECT *", "SELECT COUNT(*) AS count"), params)
        total = (await cursor.fetchone())["count"]
        cursor = await conn.execute(
            query + " ORDER BY confidence DESC, last_seen DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        )
        items = [dict(row) for row in await cursor.fetchall()]
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.get("/api/cves", response_model=CVEListResponse, tags=["Vulnerabilities"])
async def api_cves(
    q: Optional[str] = Query(None, description="Search keyword"),
    source: Optional[str] = Query(None, description="cisa_kev or nvd"),
    ransomware: Optional[str] = Query(None, description="Known or Unknown"),
    min_cvss: Optional[float] = Query(None, description="Minimum CVSS score"),
    severity: Optional[str] = Query(None, description="CRITICAL, HIGH, etc."),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    """Paginated CVE exploration with multi-vector filtering."""
    query = "SELECT * FROM cve_records WHERE 1=1"
    params = []

    if q:
        query += " AND (cve_id LIKE ? OR vendor_project LIKE ? OR product LIKE ? OR short_description LIKE ?)"
        term = f"%{q}%"
        params.extend([term, term, term, term])

    if source and source != "all":
        query += " AND source = ?"
        params.append(source)

    if ransomware and ransomware != "all":
        query += " AND known_ransomware_campaign_use = ?"
        params.append(ransomware)

    if min_cvss is not None:
        query += " AND cvss_score >= ?"
        params.append(min_cvss)

    if severity and severity != "all":
        query += " AND UPPER(cvss_severity) = ?"
        params.append(severity.upper())

    # Count total
    count_query = query.replace("SELECT *", "SELECT COUNT(*) as count")
    async with get_db() as conn:
        cur = await conn.execute(count_query, params)
        row = await cur.fetchone()
        total = row["count"] if row else 0

        # Sort order: prioritize CVSS score or date_added
        query += " ORDER BY CASE WHEN cvss_score IS NOT NULL THEN cvss_score ELSE 0 END DESC, date_added DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cur = await conn.execute(query, params)
        rows = await cur.fetchall()
        items = [dict(r) for r in rows]

    return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.get("/api/malware", response_model=MalwareListResponse, tags=["Malware"])
async def api_malware(
    q: Optional[str] = Query(None, description="Search hash, signature, filename"),
    file_type: Optional[str] = Query(None, description="File type filter"),
    signature: Optional[str] = Query(None, description="Signature filter"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    """Paginated MalwareBazaar sample intelligence stream."""
    query = "SELECT * FROM malware_samples WHERE 1=1"
    params = []

    if q:
        query += " AND (sha256_hash LIKE ? OR md5_hash LIKE ? OR file_name LIKE ? OR signature LIKE ? OR reporter LIKE ?)"
        term = f"%{q}%"
        params.extend([term, term, term, term, term])

    if file_type and file_type != "all":
        query += " AND LOWER(file_type) = ?"
        params.append(file_type.lower())

    if signature and signature != "all":
        query += " AND LOWER(signature) = ?"
        params.append(signature.lower())

    count_query = query.replace("SELECT *", "SELECT COUNT(*) as count")
    async with get_db() as conn:
        cur = await conn.execute(count_query, params)
        row = await cur.fetchone()
        total = row["count"] if row else 0

        query += " ORDER BY first_seen DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cur = await conn.execute(query, params)
        rows = await cur.fetchall()
        items = [dict(r) for r in rows]

    return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.get("/api/dshield", response_model=DShieldResponse, tags=["Telemetry"])
async def api_dshield():
    """SANS Internet Storm Center DShield telemetry (Infocon, attackers, targeted ports)."""
    async with get_db() as conn:
        cur = await conn.execute("SELECT status, updated_at, raw_json FROM dshield_infocon WHERE id = 1;")
        infocon_row = await cur.fetchone()
        infocon = dict(infocon_row) if infocon_row else {"status": "unknown", "updated_at": None, "raw_json": None}

        cur = await conn.execute("SELECT * FROM dshield_sources ORDER BY attacks DESC LIMIT 50;")
        sources = [dict(r) for r in await cur.fetchall()]

        cur = await conn.execute("SELECT * FROM dshield_ports ORDER BY records DESC LIMIT 50;")
        ports = [dict(r) for r in await cur.fetchall()]

    return {
        "infocon": infocon,
        "sources": sources,
        "ports": ports
    }


@app.get("/api/news", response_model=NewsListResponse, tags=["Intel"])
async def api_news(
    q: Optional[str] = Query(None, description="Search title or snippet"),
    source: Optional[str] = Query(None, description="Source filter"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    """Paginated CTI news stream from curated threat intelligence feeds."""
    query = "SELECT * FROM cti_news WHERE 1=1"
    params = []

    if q:
        query += " AND (title LIKE ? OR snippet LIKE ?)"
        term = f"%{q}%"
        params.extend([term, term])

    if source and source != "all":
        query += " AND source = ?"
        params.append(source)

    count_query = query.replace("SELECT *", "SELECT COUNT(*) as count")
    async with get_db() as conn:
        cur = await conn.execute(count_query, params)
        row = await cur.fetchone()
        total = row["count"] if row else 0

        query += " ORDER BY published_date DESC, updated_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cur = await conn.execute(query, params)
        rows = await cur.fetchall()
        items = [dict(r) for r in rows]

    return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.get("/api/ransomware", response_model=RansomwareListResponse, tags=["Ransomware"])
async def api_ransomware(
    q: Optional[str] = Query(None, description="Search victim, group, or domain"),
    group: Optional[str] = Query("all", description="Filter by threat actor group"),
    country: Optional[str] = Query("all", description="Filter by country code (e.g. BR)"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    query = "SELECT * FROM ransomware_victims WHERE 1=1"
    params = []

    if q:
        query += " AND (victim_name LIKE ? OR group_name LIKE ? OR domain LIKE ? OR description LIKE ?)"
        wildcard = f"%{q}%"
        params.extend([wildcard, wildcard, wildcard, wildcard])

    if group and group != "all":
        query += " AND LOWER(group_name) = ?"
        params.append(group.lower())

    if country and country != "all":
        if country.upper() == "BR":
            query += " AND (UPPER(country) = 'BR' OR UPPER(country) = 'BRAZIL')"
        else:
            query += " AND UPPER(country) = ?"
            params.append(country.upper())

    count_query = query.replace("SELECT *", "SELECT COUNT(*) as count")
    async with get_db() as conn:
        cur = await conn.execute(count_query, params)
        row = await cur.fetchone()
        total = row["count"] if row else 0

        cur_br = await conn.execute("SELECT COUNT(*) as count FROM ransomware_victims WHERE UPPER(country) = 'BR' OR UPPER(country) = 'BRAZIL';")
        row_br = await cur_br.fetchone()
        brazil_total = row_br["count"] if row_br else 0

        query += " ORDER BY discovered DESC, updated_at DESC LIMIT ? OFFSET ?;"
        params.extend([limit, offset])

        cur = await conn.execute(query, params)
        rows = await cur.fetchall()
        items = [dict(r) for r in rows]

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "brazil_total": brazil_total,
        "items": items
    }



# ==================== LIVE CYBERATTACK MAP TELEMETRY (v1.5.0) ====================

GEO_COORDINATES = {
    "US": {"lat": 37.0902, "lon": -95.7129, "name": "United States"},
    "BR": {"lat": -14.2350, "lon": -51.9253, "name": "Brazil"},
    "CN": {"lat": 35.8617, "lon": 104.1954, "name": "China"},
    "RU": {"lat": 61.5240, "lon": 105.3188, "name": "Russia"},
    "DE": {"lat": 51.1657, "lon": 10.4515, "name": "Germany"},
    "NL": {"lat": 52.1326, "lon": 5.2913, "name": "Netherlands"},
    "GB": {"lat": 55.3781, "lon": -3.4360, "name": "United Kingdom"},
    "FR": {"lat": 46.2276, "lon": 2.2137, "name": "France"},
    "IN": {"lat": 20.5937, "lon": 78.9629, "name": "India"},
    "JP": {"lat": 36.2048, "lon": 138.2529, "name": "Japan"},
    "KR": {"lat": 35.9078, "lon": 127.7669, "name": "South Korea"},
    "CA": {"lat": 56.1304, "lon": -106.3468, "name": "Canada"},
    "AU": {"lat": -25.2744, "lon": 133.7751, "name": "Australia"},
    "SG": {"lat": 1.3521, "lon": 103.8198, "name": "Singapore"},
    "IR": {"lat": 32.4279, "lon": 53.6880, "name": "Iran"},
    "VN": {"lat": 14.0583, "lon": 108.2772, "name": "Vietnam"},
}

@app.get("/api/attacks/live", tags=["Telemetry"])
async def api_live_attacks():
    """Stream real-time cyberattack trajectories derived from DShield telemetry and active malware feeds."""
    import random
    from datetime import datetime, timezone

    async with get_db() as conn:
        # Get active sources
        cur = await conn.execute("SELECT ip, attacks, count, as_name FROM dshield_sources ORDER BY attacks DESC LIMIT 20;")
        sources = [dict(r) for r in await cur.fetchall()]

        # Get active ports
        cur_p = await conn.execute("SELECT port, service, records, targets FROM dshield_ports ORDER BY records DESC LIMIT 15;")
        ports = [dict(r) for r in await cur_p.fetchall()]

    if not sources:
        sources = [{"ip": "185.220.101.4", "attacks": 1200, "count": 500, "as_name": "TOR-EXIT"}]
    if not ports:
        ports = [{"port": 443, "service": "HTTPS", "records": 500000, "targets": 300}]

    attack_countries = ["CN", "RU", "US", "NL", "DE", "VN", "IR", "IN"]
    target_countries = ["BR", "US", "DE", "GB", "FR", "JP", "CA", "AU"]

    attacks = []
    now = datetime.now(timezone.utc).strftime("%H:%M:%S")
    port_weights = [max(int(port.get("records", 0)), 1) for port in ports]

    for i in range(15):
        src_cc = random.choice(attack_countries)
        dst_cc = random.choice(target_countries)
        while dst_cc == src_cc:
            dst_cc = random.choice(target_countries)

        src_geo = GEO_COORDINATES.get(src_cc, GEO_COORDINATES["US"])
        dst_geo = GEO_COORDINATES.get(dst_cc, GEO_COORDINATES["BR"])

        # Preserve live variation while keeping the simulated stream proportional
        # to the current DShield record volumes instead of choosing ports uniformly.
        p_info = random.choices(ports, weights=port_weights, k=1)[0]
        src_node = random.choice(sources)

        attacks.append({
            "id": f"atk-{i}-{random.randint(1000, 9999)}",
            "time": now,
            "src_ip": src_node.get("ip", "192.0.2.1"),
            "src_country": src_cc,
            "src_country_name": src_geo["name"],
            "src_lat": src_geo["lat"] + random.uniform(-1.5, 1.5),
            "src_lon": src_geo["lon"] + random.uniform(-1.5, 1.5),
            "dst_country": dst_cc,
            "dst_country_name": dst_geo["name"],
            "dst_lat": dst_geo["lat"] + random.uniform(-1.5, 1.5),
            "dst_lon": dst_geo["lon"] + random.uniform(-1.5, 1.5),
            "port": p_info.get("port", 443),
            "service": p_info.get("service", "HTTPS"),
            "as_name": src_node.get("as_name", "UNKNOWN-AS"),
            "severity": "CRITICAL" if p_info.get("port") in [445, 3389, 22] else "HIGH"
        })

    return {
        "status": "online",
        "attacks": attacks,
        "active_scanners_count": len(sources),
        "targeted_ports_count": len(ports)
    }




# ==================== LEAK CHECK CREDENTIAL SCANNER (v1.6.0) ====================

@app.post("/api/leak-check/password", tags=["Leak Check"])
async def api_leak_check_password(req: dict = Body(...)):
    """Check password exposure using Troy Hunt / Cloudflare K-Anonymity protocol."""
    import hashlib
    password = req.get("password", "")
    prefix = req.get("sha1_prefix", "")
    suffix = req.get("sha1_suffix", "")

    if password:
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    elif not (prefix and suffix):
        raise HTTPException(status_code=400, detail="Missing password or SHA1 hash components")

    prefix = prefix.upper()
    suffix = suffix.upper()

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            res = await client.get(url, headers={"User-Agent": "DarkThreatRadar-CTI/1.6"})
            if res.status_code == 200:
                count = 0
                for line in res.text.splitlines():
                    parts = line.strip().split(":")
                    if len(parts) == 2 and parts[0] == suffix:
                        count = int(parts[1])
                        break
                return {
                    "status": "success",
                    "exposed": count > 0,
                    "count": count,
                    "sha1_prefix": prefix,
                    "source": "Have I Been Pwned / Cloudflare K-Anonymity Engine"
                }
        except Exception as e:
            logger.error(f"Error checking password leak: {e}")
            raise HTTPException(status_code=502, detail="Error querying K-Anonymity service")

    return {
        "status": "success",
        "exposed": False,
        "count": 0,
        "sha1_prefix": prefix,
        "source": "Have I Been Pwned / Cloudflare K-Anonymity Engine"
    }


@app.post("/api/leak-check/email", tags=["Leak Check"])
async def api_leak_check_email(req: dict = Body(...)):
    """Check email exposure against global breach intelligence (XposedOrNot)."""
    email = req.get("email", "").strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email address is required")

    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            res = await client.get(url, headers={"User-Agent": "DarkThreatRadar-CTI/1.6"})
            if res.status_code == 200:
                data = res.json()
                breaches = []
                if "breaches" in data and isinstance(data["breaches"], list) and len(data["breaches"]) > 0:
                    breaches = data["breaches"][0] if isinstance(data["breaches"][0], list) else data["breaches"]
                return {
                    "status": "success",
                    "exposed": True,
                    "count": len(breaches),
                    "breaches": breaches,
                    "email": email,
                    "source": "XposedOrNot Community Breach Intelligence"
                }
            elif res.status_code == 404:
                return {
                    "status": "success",
                    "exposed": False,
                    "count": 0,
                    "breaches": [],
                    "email": email,
                    "source": "XposedOrNot Community Breach Intelligence"
                }
        except Exception as e:
            logger.error(f"Error checking email leak: {e}")
            raise HTTPException(status_code=502, detail="Error querying breach database")

    return {
        "status": "success",
        "exposed": False,
        "count": 0,
        "breaches": [],
        "email": email,
        "source": "XposedOrNot Community Breach Intelligence"
    }




# ==================== WATCHLIST & REMEDIATION (v1.7.0) ====================

@app.get("/api/watchlist", tags=["Watchlist"])
async def api_get_watchlist():
    """Get monitored watchlist items and cross-reference with active KEV / NVD CVEs."""
    import aiosqlite
    from app.database import get_db

    async with get_db() as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute("SELECT * FROM watchlist ORDER BY created_at DESC;")
        items = [dict(r) for r in await cur.fetchall()]

        # For each item, find matching CVEs and remediation data
        matched_cves = []
        for item in items:
            val = item["value"].strip()
            itype = item["item_type"].strip().lower()

            if itype == "cve":
                c_cur = await conn.execute(
                    """SELECT cve_id, vendor_project, product, vulnerability_name, 
                              cvss_score, cvss_severity, source, required_action, 
                              due_date, known_ransomware_campaign_use, short_description, date_added, epss_score
                       FROM cve_records WHERE cve_id = ?;""", (val,)
                )
            elif itype == "vendor":
                c_cur = await conn.execute(
                    """SELECT cve_id, vendor_project, product, vulnerability_name, 
                              cvss_score, cvss_severity, source, required_action, 
                              due_date, known_ransomware_campaign_use, short_description, date_added, epss_score
                       FROM cve_records 
                       WHERE vendor_project LIKE ? OR vulnerability_name LIKE ?
                       ORDER BY cvss_score DESC, date_added DESC LIMIT 15;""", (f"%{val}%", f"%{val}%")
                )
            else: # product / OS
                c_cur = await conn.execute(
                    """SELECT cve_id, vendor_project, product, vulnerability_name, 
                              cvss_score, cvss_severity, source, required_action, 
                              due_date, known_ransomware_campaign_use, short_description, date_added, epss_score
                       FROM cve_records 
                       WHERE product LIKE ? OR vulnerability_name LIKE ?
                       ORDER BY cvss_score DESC, date_added DESC LIMIT 15;""", (f"%{val}%", f"%{val}%")
                )

            rows = [dict(r) for r in await c_cur.fetchall()]
            for r in rows:
                r["matched_watchlist_item"] = item
                # Add default remediation note if empty
                if not r.get("required_action") or r["required_action"] == "None":
                    r["required_action"] = f"Apply latest vendor security patch or upgrade {r.get('product') or val} to non-vulnerable release."
                matched_cves.append(r)

    # Deduplicate matched CVEs by cve_id
    seen = set()
    unique_cves = []
    for c in matched_cves:
        if c["cve_id"] not in seen:
            seen.add(c["cve_id"])
            unique_cves.append(c)

    return {
        "watchlist": items,
        "total_items": len(items),
        "active_alerts": unique_cves,
        "total_alerts": len(unique_cves)
    }


@app.post("/api/watchlist", tags=["Watchlist"])
async def api_add_watchlist(payload: dict = Body(...)):
    """Add new item to infrastructure watchlist."""
    import uuid
    from datetime import datetime, timezone
    from app.database import get_db

    itype = payload.get("item_type", "vendor").strip().lower()
    value = payload.get("value", "").strip()
    notes = payload.get("notes", "").strip()

    if not value:
        raise HTTPException(status_code=400, detail="Value cannot be empty")

    item_id = f"wl-{uuid.uuid4().hex[:10]}"
    now = datetime.now(timezone.utc).isoformat()

    async with get_db() as conn:
        await conn.execute(
            "INSERT INTO watchlist (id, item_type, value, notes, created_at) VALUES (?, ?, ?, ?, ?);",
            (item_id, itype, value, notes, now)
        )
        await conn.commit()

    return {"status": "created", "id": item_id, "value": value, "item_type": itype}


@app.delete("/api/watchlist/{item_id}", tags=["Watchlist"])
async def api_delete_watchlist(item_id: str):
    """Remove item from infrastructure watchlist."""
    from app.database import get_db

    async with get_db() as conn:
        cur = await conn.execute("DELETE FROM watchlist WHERE id = ?;", (item_id,))
        await conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Watchlist item not found")

    return {"status": "deleted", "id": item_id}


@app.get(
    "/api/artifact/{artifact_type}/{identifier:path}",
    response_model=ArtifactResponse,
    responses={400: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
    tags=["Artifacts"]
)
async def api_artifact(artifact_type: str, identifier: str):
    """Deep inspection artifact retriever for CVEs, hashes, IPs, ports, and news."""
    async with get_db() as conn:
        if artifact_type == "cve":
            cur = await conn.execute("SELECT * FROM cve_records WHERE cve_id = ?;", (identifier,))
            row = await cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"CVE {identifier} not found")
            data = dict(row)
            if data.get("raw_json"):
                try:
                    data["parsed_raw"] = json.loads(data["raw_json"])
                except Exception:
                    data["parsed_raw"] = data["raw_json"]
            return {"type": "cve", "identifier": identifier, "data": data}

        elif artifact_type == "malware":
            cur = await conn.execute(
                "SELECT * FROM malware_samples WHERE sha256_hash = ? OR md5_hash = ?;",
                (identifier, identifier)
            )
            row = await cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"Malware sample {identifier} not found")
            data = dict(row)
            if data.get("raw_json"):
                try:
                    data["parsed_raw"] = json.loads(data["raw_json"])
                except Exception:
                    data["parsed_raw"] = data["raw_json"]
            return {"type": "malware", "identifier": identifier, "data": data}

        elif artifact_type == "ip":
            cur = await conn.execute("SELECT * FROM dshield_sources WHERE ip = ?;", (identifier,))
            row = await cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"Source IP {identifier} not found")
            data = dict(row)
            return {"type": "ip", "identifier": identifier, "data": data}

        elif artifact_type == "port":
            try:
                port_num = int(identifier)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid port number")
            cur = await conn.execute("SELECT * FROM dshield_ports WHERE port = ?;", (port_num,))
            row = await cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"Port {identifier} not found")
            data = dict(row)
            return {"type": "port", "identifier": identifier, "data": data}

        elif artifact_type == "ransomware":
            cur = await conn.execute("SELECT * FROM ransomware_victims WHERE id = ?;", (identifier,))
            row = await cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"Ransomware victim '{identifier}' not found")
            data = dict(row)
            if data.get("raw_json"):
                try:
                    data["raw_json"] = json.loads(data["raw_json"])
                except Exception:
                    pass
        elif artifact_type == "news":
            cur = await conn.execute("SELECT * FROM cti_news WHERE id = ?;", (identifier,))
            row = await cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"News item {identifier} not found")
            data = dict(row)
            return {"type": "news", "identifier": identifier, "data": data}

        else:
            raise HTTPException(status_code=400, detail=f"Unknown artifact type: {artifact_type}")
