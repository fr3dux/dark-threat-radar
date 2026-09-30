import asyncio
import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from app.ingestion import (
    run_all_ingestions,
    run_core_ingestions,
    run_fast_ioc_ingestions,
    run_hourly_ingestions,
    run_slow_ingestions,
)
from app.config import (
    SYNC_INTERVAL_SECONDS,
    CTI_FAST_INTERVAL_SECONDS,
    CTI_HOURLY_INTERVAL_SECONDS,
    CTI_SLOW_INTERVAL_SECONDS,
)

logger = logging.getLogger("scheduler")

scheduler = AsyncIOScheduler()
_sync_lock = asyncio.Lock()
_group_locks = {
    "core": asyncio.Lock(),
    "fast": asyncio.Lock(),
    "hourly": asyncio.Lock(),
    "slow": asyncio.Lock(),
}
_scheduled_group_lock = asyncio.Lock()
_is_syncing = False


async def _run_group_locked(name, callback):
    lock = _group_locks[name]
    if lock.locked():
        logger.warning("Connector group %s is already running; skipping", name)
        return
    if _scheduled_group_lock.locked():
        logger.warning("Another connector group is writing; skipping %s", name)
        return
    async with _scheduled_group_lock:
        async with lock:
            await callback()

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
            _run_group_locked,
            "interval",
            seconds=SYNC_INTERVAL_SECONDS,
            args=["core", run_core_ingestions],
            id="cti_core_sync",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
            jitter=20,
        )
        scheduler.add_job(
            _run_group_locked,
            "interval",
            seconds=CTI_FAST_INTERVAL_SECONDS,
            args=["fast", run_fast_ioc_ingestions],
            id="cti_fast_ioc_sync",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
            jitter=45,
        )
        scheduler.add_job(
            _run_group_locked,
            "interval",
            seconds=CTI_HOURLY_INTERVAL_SECONDS,
            args=["hourly", run_hourly_ingestions],
            id="cti_hourly_sync",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
            jitter=120,
        )
        scheduler.add_job(
            _run_group_locked,
            "interval",
            seconds=CTI_SLOW_INTERVAL_SECONDS,
            args=["slow", run_slow_ingestions],
            id="cti_slow_sync",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
            jitter=300,
        )
        scheduler.start()
        logger.info(
            "CTI scheduler started: core=%ss fast=%ss hourly=%ss slow=%ss",
            SYNC_INTERVAL_SECONDS,
            CTI_FAST_INTERVAL_SECONDS,
            CTI_HOURLY_INTERVAL_SECONDS,
            CTI_SLOW_INTERVAL_SECONDS,
        )

def shutdown_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("CTI Scheduler shut down.")
