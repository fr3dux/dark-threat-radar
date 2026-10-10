import httpx
import asyncio
import json
import logging
import secrets
from contextlib import asynccontextmanager
from typing import Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import FastAPI, Request, Query, BackgroundTasks, HTTPException, Security
from fastapi.exceptions import RequestValidationError
from fastapi.security import APIKeyHeader
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import HOST, PORT, BASE_DIR, SETTINGS_ADMIN_TOKEN
from app.credential_store import (
    delete_provider_secret,
    openphish_is_enabled,
    openphish_terms_accepted,
    provider_secret_is_configured,
    save_openphish_settings,
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
    OpenPhishSettingsUpdate,
    GeneralSettingsUpdate,
    PasswordLeakCheckRequest,
    EmailLeakCheckRequest,
    WatchlistCreate,
    WatchlistAlertAcknowledge,
)
from app.security import RequestBodyLimitMiddleware, security_middleware
from app.database import (
    init_db,
    get_db,
    get_dashboard_stats,
    get_all_feed_statuses,
    get_all_connector_health,
    get_app_settings,
    save_app_settings,
    update_connector_health,
)
from app.scheduler import (
    start_scheduler,
    shutdown_scheduler,
    trigger_manual_sync,
    scheduled_sync_task,
    get_sync_state
)
from app.updater import get_update_status, queue_latest_update
from app.watchlist_monitor import EXPOSURE_TYPES, refresh_watchlist_alerts

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("threat_radar")

DISPLAY_TIMEZONES = [
    "UTC",
    "America/Sao_Paulo", "America/Manaus", "America/Recife", "America/Fortaleza",
    "America/Belem", "America/Cuiaba", "America/Rio_Branco", "America/Noronha",
    "America/Buenos_Aires", "America/Santiago", "America/Bogota", "America/Lima",
    "America/Mexico_City", "America/New_York", "America/Chicago", "America/Denver",
    "America/Los_Angeles", "America/Toronto", "America/Vancouver",
    "Europe/Lisbon", "Europe/London", "Europe/Madrid", "Europe/Paris", "Europe/Berlin",
    "Europe/Rome", "Europe/Amsterdam", "Europe/Moscow",
    "Asia/Dubai", "Asia/Kolkata", "Asia/Singapore", "Asia/Tokyo", "Asia/Shanghai",
    "Australia/Sydney", "Pacific/Auckland",
]


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

app.add_middleware(RequestBodyLimitMiddleware)
app.middleware("http")(security_middleware)

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
admin_token_header = APIKeyHeader(name="X-Admin-Token", auto_error=False)


def require_settings_admin(
    admin_token: Optional[str] = Security(admin_token_header),
) -> None:
    """Protect state-changing endpoints on an otherwise public CTI portal."""
    if not SETTINGS_ADMIN_TOKEN:
        raise HTTPException(status_code=503, detail="Administration is not enabled on this server")
    if not admin_token or not secrets.compare_digest(admin_token, SETTINGS_ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid administrative access code")


# ==================== PAGE ROUTES ====================

@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    stats = await get_dashboard_stats()
    feed_statuses = await get_all_feed_statuses()
    connectors = await get_all_connector_health()
    app_settings = await get_app_settings()
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
            "app_settings": app_settings,
            "sync_state": sync_state
        }
    )


# ==================== API ENDPOINTS ====================

@app.get("/api/version", response_model=VersionResponse, tags=["System"])
async def api_version():
    """Return centralized application semantic version and metadata."""
    return get_version_info()


@app.get("/api/update/status", tags=["System"])
async def api_update_status(
    force: bool = Query(False, description="Bypass the in-memory release cache"),
):
    """Check the fixed official repository for a newer stable release."""
    return await get_update_status(force=force)


@app.get("/api/settings", tags=["System"])
async def api_public_settings():
    """Return non-secret presentation preferences and supported values."""
    settings = await get_app_settings()
    timezones = list(DISPLAY_TIMEZONES)
    if settings["timezone"] not in timezones:
        timezones.append(settings["timezone"])
        timezones.sort()
    return {
        **settings,
        "supported_locales": ["en", "pt-BR", "es"],
        "supported_timezones": timezones,
    }


@app.put("/api/admin/settings/general", tags=["Administration"])
async def api_save_general_settings(
    payload: GeneralSettingsUpdate,
    _admin: None = Security(require_settings_admin),
):
    """Persist validated global display settings without changing stored UTC data."""
    timezone_name = payload.timezone.strip()
    try:
        ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Unknown IANA timezone") from exc
    return await save_app_settings(timezone_name, payload.locale)


@app.post("/api/admin/update", status_code=202, tags=["Administration"])
async def api_install_update(
    _admin: None = Security(require_settings_admin),
):
    """Queue the latest validated release for the external system updater."""
    try:
        return await queue_latest_update()
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


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
async def api_trigger_sync(
    background_tasks: BackgroundTasks,
    _admin: None = Security(require_settings_admin),
):
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
    "openphish": {"name": "OpenPhish", "category": "Phishing"},
    "alienvault_otx": {"name": "AlienVault OTX", "category": "Malware & IOCs"},
    "phishtank": {"name": "PhishTank", "category": "Phishing"},
    "abuseipdb": {"name": "AbuseIPDB", "category": "Network Intelligence"},
    "threatcluster": {
        "name": "ThreatCluster", "category": "Ransomware & Data Breaches",
        "env_var": "THREATCLUSTER_API_KEY",
    },
}


async def sync_managed_integration(provider: str) -> None:
    if provider == "threatfox":
        from app.ingestion.threatfox import ingest_threatfox
        await ingest_threatfox()
    elif provider == "urlhaus":
        from app.ingestion.urlhaus import ingest_urlhaus
        await ingest_urlhaus()
    elif provider == "openphish":
        from app.ingestion.openphish import ingest_openphish
        await ingest_openphish()
    elif provider == "alienvault_otx":
        from app.ingestion.alienvault_otx import ingest_alienvault_otx
        await ingest_alienvault_otx()
    elif provider == "phishtank":
        from app.ingestion.phishtank import ingest_phishtank
        await ingest_phishtank()
    elif provider == "abuseipdb":
        from app.ingestion.abuseipdb import ingest_abuseipdb
        await ingest_abuseipdb()
    elif provider == "threatcluster":
        from app.ingestion.threatcluster import ingest_threatcluster
        await ingest_threatcluster()


@app.get("/api/admin/integrations", tags=["Administration"])
async def api_admin_integrations(
    _admin: None = Security(require_settings_admin),
):
    """Return credential presence and connector health without returning secrets."""
    health = {item["source_name"]: item for item in await get_all_connector_health()}
    items = []
    for provider, metadata in MANAGED_INTEGRATIONS.items():
        connector = health.get(provider, {})
        items.append({
            "provider": provider,
            "name": metadata["name"],
            "configured": provider_secret_is_configured(provider) if provider != "openphish" else False,
            "enabled": openphish_is_enabled() if provider == "openphish" else True,
            "terms_accepted": openphish_terms_accepted() if provider == "openphish" else None,
            "state": connector.get("state", "never_run"),
            "last_attempt": connector.get("last_attempt"),
            "last_success": connector.get("last_success"),
            "last_error": connector.get("last_error"),
        })
    return {"items": items}


@app.put("/api/admin/integrations/openphish/settings", tags=["Administration"])
async def api_save_openphish_settings(
    payload: OpenPhishSettingsUpdate,
    background_tasks: BackgroundTasks,
    _admin: None = Security(require_settings_admin),
):
    """Explicitly opt into OpenPhish and validate its Community feed."""
    try:
        save_openphish_settings(
            enabled=payload.enabled,
            terms_accepted=payload.terms_accepted,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if payload.enabled:
        await update_connector_health(
            "openphish",
            "Phishing",
            "never_run",
            last_error="Configuration saved; feed validation is pending",
        )
        background_tasks.add_task(sync_managed_integration, "openphish")
        state = "never_run"
        validation = "started"
    else:
        await update_connector_health(
            "openphish",
            "Phishing",
            "disabled",
            last_error="Disabled by administrator",
        )
        state = "disabled"
        validation = "disabled"
    return {
        "provider": "openphish",
        "configured": False,
        "enabled": payload.enabled,
        "terms_accepted": payload.terms_accepted,
        "state": state,
        "validation": validation,
    }


@app.put("/api/admin/integrations/{provider}", tags=["Administration"])
async def api_save_integration_key(
    provider: str,
    payload: IntegrationKeyUpdate,
    background_tasks: BackgroundTasks,
    _admin: None = Security(require_settings_admin),
):
    """Save a connector API key server-side and validate it through ingestion."""
    metadata = MANAGED_INTEGRATIONS.get(provider)
    if not metadata:
        raise HTTPException(status_code=404, detail="Unsupported integration")
    if provider == "openphish":
        raise HTTPException(status_code=409, detail="Use the OpenPhish settings endpoint")
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
    _admin: None = Security(require_settings_admin),
):
    """Remove a runtime connector key and return the source to AUTH REQUIRED."""
    metadata = MANAGED_INTEGRATIONS.get(provider)
    if not metadata:
        raise HTTPException(status_code=404, detail="Unsupported integration")
    if provider == "openphish":
        raise HTTPException(status_code=409, detail="OpenPhish does not use an API key")
    delete_provider_secret(provider)
    await update_connector_health(
        provider,
        metadata["category"],
        "auth_required",
        last_error=f"{metadata.get('env_var', provider.upper() + '_AUTH_KEY')} is not configured",
    )
    return {"provider": provider, "configured": False, "state": "auth_required"}


@app.get("/api/iocs", tags=["Intel"])
async def api_iocs(
    q: Optional[str] = Query(None, max_length=300),
    indicator_type: Optional[str] = Query(None, max_length=40),
    source: Optional[str] = Query(None, max_length=80),
    active: Optional[bool] = Query(True),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Search normalized indicators with live source attribution and correlation."""
    where = "WHERE 1=1"
    params = []
    if q:
        where += " AND (n.normalized_value LIKE ? OR n.malware_family LIKE ? OR n.threat_type LIKE ?)"
        term = f"%{q}%"
        params.extend([term, term, term])
    if indicator_type:
        where += " AND LOWER(n.indicator_type) = LOWER(?)"
        params.append(indicator_type)
    if source:
        where += " AND EXISTS (SELECT 1 FROM ioc_sources s WHERE s.ioc_id=n.id AND s.source_name=? AND s.active=1)"
        params.append(source)
    if active is not None:
        where += " AND n.active = ?"
        params.append(int(active))
    async with get_db() as conn:
        # `where` contains only server-authored clauses; all user values remain bound.
        cursor = await conn.execute(f"SELECT COUNT(*) AS count FROM normalized_iocs n {where}", params)  # nosec B608
        total = (await cursor.fetchone())["count"]
        # Every clause is server-authored; all request values use bound parameters.
        ioc_select_query = (
                "SELECT n.*, "  # nosec B608
                "(SELECT COUNT(*) FROM ioc_sources s "
                "WHERE s.ioc_id=n.id AND s.active=1) AS source_count, "
                "(SELECT GROUP_CONCAT(s.source_name, ', ') "
                "FROM ioc_sources s WHERE s.ioc_id=n.id AND s.active=1) AS sources "
                "FROM normalized_iocs n " + where +
                " ORDER BY n.confidence DESC, n.last_seen DESC LIMIT ? OFFSET ?"
        )
        cursor = await conn.execute(
            ioc_select_query,
            [*params, limit, offset],
        )
        items = [dict(row) for row in await cursor.fetchall()]
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.get("/api/attack-knowledge", tags=["Intel"])
async def api_attack_knowledge(
    q: Optional[str] = Query(None, max_length=200),
    object_type: Optional[str] = Query(None, max_length=40),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Search the locally synchronized MITRE ATT&CK knowledge base."""
    query = "SELECT * FROM attack_knowledge WHERE revoked=0"
    params = []
    if q:
        query += " AND (name LIKE ? OR external_id LIKE ? OR description LIKE ? OR aliases LIKE ?)"
        term = f"%{q}%"
        params.extend([term, term, term, term])
    if object_type:
        query += " AND object_type=?"
        params.append(object_type)
    async with get_db() as conn:
        cursor = await conn.execute(query.replace("SELECT *", "SELECT COUNT(*) AS count"), params)
        total = (await cursor.fetchone())["count"]
        cursor = await conn.execute(
            query + " ORDER BY object_type, name LIMIT ? OFFSET ?",
            [*params, limit, offset],
        )
        items = [dict(row) for row in await cursor.fetchall()]
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.get("/api/vendor-advisories", tags=["Vulnerabilities"])
async def api_vendor_advisories(
    q: Optional[str] = Query(None, max_length=200),
    vendor: Optional[str] = Query(None, max_length=100),
    severity: Optional[str] = Query(None, max_length=20),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Search official Microsoft MSRC and Red Hat vendor advisories."""
    where = "WHERE 1=1"
    params = []
    if q:
        where += " AND (title LIKE ? OR cve_ids LIKE ? OR product LIKE ? OR advisory_id LIKE ?)"
        term = f"%{q}%"
        params.extend([term, term, term, term])
    if vendor:
        where += " AND LOWER(vendor)=LOWER(?)"
        params.append(vendor)
    if severity:
        where += " AND UPPER(severity)=UPPER(?)"
        params.append(severity)
    async with get_db() as conn:
        # `where` contains only server-authored clauses; all user values remain bound.
        cursor = await conn.execute(f"SELECT COUNT(*) AS count FROM vendor_advisories {where}", params)  # nosec B608
        total = (await cursor.fetchone())["count"]
        # Every clause is server-authored; all request values use bound parameters.
        advisory_query = (
            "SELECT * FROM vendor_advisories " + where +  # nosec B608
            " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        )
        cursor = await conn.execute(
            advisory_query,
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

        query += (
            " ORDER BY COALESCE(published_at, updated_at) DESC, updated_at DESC"
            " LIMIT ? OFFSET ?"
        )
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

        query += " ORDER BY COALESCE(discovered, last_seen, updated_at) DESC, updated_at DESC LIMIT ? OFFSET ?;"
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
async def api_leak_check_password(req: PasswordLeakCheckRequest):
    """Check password exposure using Troy Hunt / Cloudflare K-Anonymity protocol."""
    prefix = req.sha1_prefix.upper()
    suffix = req.sha1_suffix.upper()

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
async def api_leak_check_email(req: EmailLeakCheckRequest):
    """Check email exposure against global breach intelligence (XposedOrNot)."""
    from urllib.parse import quote

    email = req.email

    url = f"https://api.xposedornot.com/v1/check-email/{quote(email, safe='')}"
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
    """Get monitored assets, vulnerability matches, and public exposure alerts."""
    import aiosqlite
    from app.database import get_db

    async with get_db() as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute("SELECT * FROM watchlist ORDER BY created_at DESC;")
        items = [dict(r) for r in await cur.fetchall()]

        alert_cur = await conn.execute(
            """SELECT
                   MIN(a.id) AS id,
                   a.source_type,
                   MAX(a.source_name) AS source_name,
                   a.artifact_id,
                   MAX(a.title) AS title,
                   GROUP_CONCAT(DISTINCT a.matched_value) AS matched_values,
                   GROUP_CONCAT(DISTINCT a.watchlist_id) AS matched_watchlist_ids,
                   GROUP_CONCAT(DISTINCT w.item_type) AS watchlist_types,
                   MAX(a.matched_field) AS matched_field,
                   MAX(a.severity) AS severity,
                   MAX(a.evidence) AS evidence,
                   MAX(a.reference_url) AS reference_url,
                   MAX(a.source_date) AS source_date,
                   MIN(a.detected_at) AS detected_at,
                   MAX(a.last_seen) AS last_seen,
                   CASE WHEN COUNT(a.acknowledged_at)=COUNT(*) THEN 1 ELSE 0 END AS acknowledged,
                   MAX(a.acknowledged_at) AS acknowledged_at
               FROM watchlist_alerts a
               JOIN watchlist w ON w.id = a.watchlist_id
               GROUP BY a.source_type, a.artifact_id
               ORDER BY COALESCE(source_date, detected_at) DESC, detected_at DESC
               LIMIT 250"""
        )
        exposure_alerts = [dict(r) for r in await alert_cur.fetchall()]
        exposure_count_row = await (await conn.execute(
            """SELECT COUNT(*) AS total FROM (
                   SELECT source_type, artifact_id FROM watchlist_alerts
                   GROUP BY source_type, artifact_id
               )"""
        )).fetchone()
        total_exposure_alerts = int(exposure_count_row["total"] or 0)
        unread_count_row = await (await conn.execute(
            """SELECT COUNT(*) AS total FROM (
                   SELECT source_type, artifact_id FROM watchlist_alerts
                   GROUP BY source_type, artifact_id
                   HAVING COUNT(acknowledged_at) < COUNT(*)
               )"""
        )).fetchone()
        total_unacknowledged_alerts = int(unread_count_row["total"] or 0)

        # For each item, find matching CVEs and remediation data
        matched_cves = []
        for item in items:
            val = item["value"].strip()
            itype = item["item_type"].strip().lower()

            if itype in EXPOSURE_TYPES:
                continue

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

            # Official MSRC and Red Hat advisories supplement the CISA/NVD
            # catalog so monitored products benefit from the expanded feeds.
            if itype == "cve":
                a_cur = await conn.execute(
                    """SELECT * FROM vendor_advisories
                       WHERE UPPER(cve_ids)=UPPER(?) OR UPPER(cve_ids) LIKE UPPER(?)
                       ORDER BY updated_at DESC LIMIT 15;""",
                    (val, f"%{val}%"),
                )
            elif itype == "vendor":
                a_cur = await conn.execute(
                    """SELECT * FROM vendor_advisories
                       WHERE vendor LIKE ? OR title LIKE ?
                       ORDER BY updated_at DESC LIMIT 15;""",
                    (f"%{val}%", f"%{val}%"),
                )
            else:
                a_cur = await conn.execute(
                    """SELECT * FROM vendor_advisories
                       WHERE product LIKE ? OR title LIKE ?
                       ORDER BY updated_at DESC LIMIT 15;""",
                    (f"%{val}%", f"%{val}%"),
                )
            for advisory in await a_cur.fetchall():
                advisory = dict(advisory)
                matched_cves.append({
                    "cve_id": advisory.get("cve_ids") or advisory.get("advisory_id"),
                    "vendor_project": advisory.get("vendor"),
                    "product": advisory.get("product"),
                    "vulnerability_name": advisory.get("title"),
                    "cvss_score": None,
                    "cvss_severity": advisory.get("severity"),
                    "source": "msrc_csaf" if advisory.get("vendor") == "Microsoft" else "redhat_security",
                    "required_action": "Review and apply the remediation in the official vendor advisory.",
                    "due_date": None,
                    "known_ransomware_campaign_use": "Unknown",
                    "short_description": advisory.get("title"),
                    "date_added": advisory.get("published_date"),
                    "epss_score": None,
                    "reference_url": advisory.get("reference_url"),
                    "advisory_artifact_id": advisory.get("id"),
                    "matched_watchlist_item": item,
                })

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
        "total_vulnerability_alerts": len(unique_cves),
        "exposure_alerts": exposure_alerts,
        "total_exposure_alerts": total_exposure_alerts,
        "total_unacknowledged_alerts": total_unacknowledged_alerts,
        "total_alerts": len(unique_cves) + total_exposure_alerts,
    }


@app.get("/api/watchlist/summary", tags=["Watchlist"])
async def api_watchlist_summary():
    """Return lightweight counts for automatic Watchlist alert signaling."""
    async with get_db() as conn:
        row = await (await conn.execute(
            """SELECT COUNT(*) AS total,
                      SUM(CASE WHEN acknowledged=0 THEN 1 ELSE 0 END) AS unacknowledged,
                      SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) AS critical
               FROM (
                   SELECT source_type, artifact_id, MAX(severity) AS severity,
                          CASE WHEN COUNT(acknowledged_at)=COUNT(*) THEN 1 ELSE 0 END AS acknowledged
                   FROM watchlist_alerts
                   GROUP BY source_type, artifact_id
               )"""
        )).fetchone()
    return {
        "total_exposure_alerts": int(row["total"] or 0),
        "total_unacknowledged_alerts": int(row["unacknowledged"] or 0),
        "critical_exposure_alerts": int(row["critical"] or 0),
    }


@app.post("/api/watchlist/alerts/acknowledge", tags=["Watchlist"])
async def api_acknowledge_watchlist_alert(
    payload: WatchlistAlertAcknowledge,
    _admin: None = Security(require_settings_admin),
):
    """Acknowledge every Watchlist match belonging to one public incident."""
    from datetime import datetime, timezone

    acknowledged_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    async with get_db() as conn:
        cursor = await conn.execute(
            """UPDATE watchlist_alerts SET acknowledged_at = ?
               WHERE source_type = ? AND artifact_id = ? AND acknowledged_at IS NULL""",
            (acknowledged_at, payload.source_type, payload.artifact_id),
        )
        await conn.commit()
        existing = await (await conn.execute(
            """SELECT MAX(acknowledged_at) AS acknowledged_at
               FROM watchlist_alerts WHERE source_type=? AND artifact_id=?""",
            (payload.source_type, payload.artifact_id),
        )).fetchone()
        if not existing or not existing["acknowledged_at"]:
            raise HTTPException(status_code=404, detail="Watchlist alert not found")
        acknowledged_at = existing["acknowledged_at"]
    return {
        "status": "acknowledged",
        "source_type": payload.source_type,
        "artifact_id": payload.artifact_id,
        "acknowledged_at": acknowledged_at,
    }


@app.post("/api/watchlist", tags=["Watchlist"])
async def api_add_watchlist(
    payload: WatchlistCreate,
    _admin: None = Security(require_settings_admin),
):
    """Add new item to infrastructure watchlist."""
    import uuid
    from datetime import datetime, timezone
    from app.database import get_db

    itype = payload.item_type
    value = payload.value
    notes = payload.notes

    item_id = f"wl-{uuid.uuid4().hex[:10]}"
    now = datetime.now(timezone.utc).isoformat()

    async with get_db() as conn:
        await conn.execute(
            "INSERT INTO watchlist (id, item_type, value, notes, created_at) VALUES (?, ?, ?, ?, ?);",
            (item_id, itype, value, notes, now)
        )
        await conn.commit()

    if itype in EXPOSURE_TYPES:
        await refresh_watchlist_alerts(item_id)

    return {"status": "created", "id": item_id, "value": value, "item_type": itype}


@app.delete("/api/watchlist/{item_id}", tags=["Watchlist"])
async def api_delete_watchlist(
    item_id: str,
    _admin: None = Security(require_settings_admin),
):
    """Remove item from infrastructure watchlist."""
    from app.database import get_db

    if not item_id.startswith("wl-") or len(item_id) != 13 or not item_id[3:].isalnum():
        raise HTTPException(status_code=422, detail="Invalid watchlist item identifier")

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
                    data["parsed_raw"] = json.loads(data["raw_json"])
                except Exception:
                    data["parsed_raw"] = data["raw_json"]
            sources = await (await conn.execute(
                """SELECT source_name, source_record_id, incident_type, victim_name,
                          group_name, domain, discovered, description, reference_url,
                          first_seen, last_seen
                   FROM exposure_incident_sources WHERE incident_id=?
                   ORDER BY last_seen DESC, source_name""",
                (identifier,),
            )).fetchall()
            data["source_observations"] = [dict(source) for source in sources]
            return {"type": "ransomware", "identifier": identifier, "data": data}

        elif artifact_type == "news":
            cur = await conn.execute("SELECT * FROM cti_news WHERE id = ?;", (identifier,))
            row = await cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"News item {identifier} not found")
            data = dict(row)
            return {"type": "news", "identifier": identifier, "data": data}

        elif artifact_type == "ioc":
            cur = await conn.execute("SELECT * FROM normalized_iocs WHERE id = ?;", (identifier,))
            row = await cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"IOC {identifier} not found")
            data = dict(row)
            cur = await conn.execute(
                """SELECT source_name, source_id, first_seen, last_seen, confidence,
                          expires_at, active, raw_metadata
                   FROM ioc_sources WHERE ioc_id=?
                   ORDER BY active DESC, confidence DESC, source_name;""",
                (identifier,),
            )
            data["source_observations"] = [dict(item) for item in await cur.fetchall()]
            if data.get("raw_metadata"):
                try:
                    data["parsed_raw"] = json.loads(data["raw_metadata"])
                except (TypeError, json.JSONDecodeError):
                    data["parsed_raw"] = data["raw_metadata"]
            return {"type": "ioc", "identifier": identifier, "data": data}

        elif artifact_type == "attack":
            cur = await conn.execute("SELECT * FROM attack_knowledge WHERE id = ?;", (identifier,))
            row = await cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"ATT&CK object {identifier} not found")
            data = dict(row)
            for key in ("aliases", "platforms", "tactics", "raw_json"):
                if data.get(key):
                    try:
                        data[f"parsed_{key}"] = json.loads(data[key])
                    except (TypeError, json.JSONDecodeError):
                        data[f"parsed_{key}"] = data[key]
            return {"type": "attack", "identifier": identifier, "data": data}

        elif artifact_type == "advisory":
            cur = await conn.execute("SELECT * FROM vendor_advisories WHERE id = ?;", (identifier,))
            row = await cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"Vendor advisory {identifier} not found")
            data = dict(row)
            if data.get("raw_json"):
                try:
                    data["parsed_raw"] = json.loads(data["raw_json"])
                except (TypeError, json.JSONDecodeError):
                    data["parsed_raw"] = data["raw_json"]
            return {"type": "advisory", "identifier": identifier, "data": data}

        else:
            raise HTTPException(status_code=400, detail=f"Unknown artifact type: {artifact_type}")
