import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, Query, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import HOST, PORT, BASE_DIR
from app.database import (
    init_db,
    get_db,
    get_dashboard_stats,
    get_all_feed_statuses
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
    logger.info("Initializing ThreatRadar database...")
    await init_db()
    start_scheduler()
    logger.info("Triggering initial background ingestion...")
    asyncio.create_task(scheduled_sync_task())
    yield
    # Shutdown
    shutdown_scheduler()
    logger.info("ThreatRadar shutdown complete.")

app = FastAPI(
    title="ThreatRadar CTI Engine",
    description="Autonomous Standalone Cyber Threat Intelligence Hub & SOC Radar",
    version="1.0.0",
    lifespan=lifespan
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))

# ==================== PAGE ROUTES ====================

@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    stats = await get_dashboard_stats()
    feed_statuses = await get_all_feed_statuses()
    sync_state = get_sync_state()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "stats": stats,
            "feed_statuses": feed_statuses,
            "sync_state": sync_state
        }
    )

# ==================== API ENDPOINTS ====================

@app.get("/api/stats")
async def api_stats():
    stats = await get_dashboard_stats()
    feed_statuses = await get_all_feed_statuses()
    sync_state = get_sync_state()
    return {
        "stats": stats,
        "feeds": feed_statuses,
        "sync": sync_state
    }

@app.post("/api/sync")
async def api_trigger_sync(background_tasks: BackgroundTasks):
    result = await trigger_manual_sync(background_tasks)
    return result

@app.get("/api/status")
async def api_status():
    feed_statuses = await get_all_feed_statuses()
    sync_state = get_sync_state()
    return {
        "feeds": feed_statuses,
        "sync": sync_state
    }

@app.get("/api/cves")
async def api_cves(
    q: Optional[str] = Query(None, description="Search keyword"),
    source: Optional[str] = Query(None, description="cisa_kev or nvd"),
    ransomware: Optional[str] = Query(None, description="Known or Unknown"),
    min_cvss: Optional[float] = Query(None, description="Minimum CVSS score"),
    severity: Optional[str] = Query(None, description="CRITICAL, HIGH, etc."),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
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

        # Sort order: prioritize KEV date or high CVSS
        query += " ORDER BY CASE WHEN cvss_score IS NOT NULL THEN cvss_score ELSE 0 END DESC, date_added DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cur = await conn.execute(query, params)
        rows = await cur.fetchall()
        items = [dict(r) for r in rows]

    return {"total": total, "limit": limit, "offset": offset, "items": items}

@app.get("/api/malware")
async def api_malware(
    q: Optional[str] = Query(None, description="Search hash, signature, filename"),
    file_type: Optional[str] = Query(None, description="File type filter"),
    signature: Optional[str] = Query(None, description="Signature filter"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
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

@app.get("/api/dshield")
async def api_dshield():
    async with get_db() as conn:
        cur = await conn.execute("SELECT status, updated_at, raw_json FROM dshield_infocon WHERE id = 1;")
        infocon_row = await cur.fetchone()
        infocon = dict(infocon_row) if infocon_row else {"status": "unknown", "updated_at": None}

        cur = await conn.execute("SELECT * FROM dshield_sources ORDER BY attacks DESC LIMIT 50;")
        sources = [dict(r) for r in await cur.fetchall()]

        cur = await conn.execute("SELECT * FROM dshield_ports ORDER BY records DESC LIMIT 50;")
        ports = [dict(r) for r in await cur.fetchall()]

    return {
        "infocon": infocon,
        "sources": sources,
        "ports": ports
    }

@app.get("/api/news")
async def api_news(
    q: Optional[str] = Query(None, description="Search title or snippet"),
    source: Optional[str] = Query(None, description="Source filter"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
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

@app.get("/api/artifact/{artifact_type}/{identifier:path}")
async def api_artifact(artifact_type: str, identifier: str):
    async with get_db() as conn:
        if artifact_type == "cve":
            cur = await conn.execute("SELECT * FROM cve_records WHERE cve_id = ?;", (identifier,))
            row = await cur.fetchone()
            if not row:
                return JSONResponse(status_code=404, content={"error": f"CVE {identifier} not found"})
            data = dict(row)
            if data.get("raw_json"):
                try:
                    data["parsed_raw"] = json.loads(data["raw_json"])
                except Exception:
                    data["parsed_raw"] = data["raw_json"]
            return {"type": "cve", "identifier": identifier, "data": data}

        elif artifact_type == "malware":
            cur = await conn.execute("SELECT * FROM malware_samples WHERE sha256_hash = ? OR md5_hash = ?;", (identifier, identifier))
            row = await cur.fetchone()
            if not row:
                return JSONResponse(status_code=404, content={"error": f"Malware sample {identifier} not found"})
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
                return JSONResponse(status_code=404, content={"error": f"Source IP {identifier} not found"})
            data = dict(row)
            return {"type": "ip", "identifier": identifier, "data": data}

        elif artifact_type == "port":
            try:
                port_num = int(identifier)
            except ValueError:
                return JSONResponse(status_code=400, content={"error": "Invalid port number"})
            cur = await conn.execute("SELECT * FROM dshield_ports WHERE port = ?;", (port_num,))
            row = await cur.fetchone()
            if not row:
                return JSONResponse(status_code=404, content={"error": f"Port {identifier} not found"})
            data = dict(row)
            return {"type": "port", "identifier": identifier, "data": data}

        elif artifact_type == "news":
            cur = await conn.execute("SELECT * FROM cti_news WHERE id = ?;", (identifier,))
            row = await cur.fetchone()
            if not row:
                return JSONResponse(status_code=404, content={"error": f"News item {identifier} not found"})
            data = dict(row)
            return {"type": "news", "identifier": identifier, "data": data}

        else:
            return JSONResponse(status_code=400, content={"error": f"Unknown artifact type: {artifact_type}"})
