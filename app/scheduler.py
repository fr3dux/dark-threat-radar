import asyncio
import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from app.ingestion import run_all_ingestions
from app.config import SYNC_INTERVAL_SECONDS

logger = logging.getLogger("scheduler")

scheduler = AsyncIOScheduler()
_sync_lock = asyncio.Lock()
_is_syncing = False

async def scheduled_sync_task():
    global _is_syncing
    if _sync_lock.locked():
        logger.warning("Sync task already in progress, skipping scheduled run.")
        return
    async with _sync_lock:
        _is_syncing = True
        try:
            await run_all_ingestions()
        finally:
            _is_syncing = False

async def trigger_manual_sync(background_tasks=None):
    global _is_syncing
    if _is_syncing:
        return {"status": "already_running", "message": "Ingestion pipeline is already executing"}
    
    # Run in background
    asyncio.create_task(scheduled_sync_task())
    return {"status": "started", "message": "Manual sync initiated in background"}

def get_sync_state():
    return {
        "is_syncing": _is_syncing,
        "scheduler_running": scheduler.running
    }

def start_scheduler():
    if not scheduler.running:
        scheduler.add_job(
            scheduled_sync_task,
            "interval",
            seconds=SYNC_INTERVAL_SECONDS,
            id="cti_sync_job",
            replace_existing=True
        )
        scheduler.start()
        logger.info(f"CTI Scheduler started with interval of {SYNC_INTERVAL_SECONDS}s")

def shutdown_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("CTI Scheduler shut down.")
