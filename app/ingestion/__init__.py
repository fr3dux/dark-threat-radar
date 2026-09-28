import asyncio
import logging
from app.ingestion.cisa_kev import ingest_cisa_kev
from app.ingestion.nvd_cve import ingest_nvd_cve
from app.ingestion.dshield import ingest_dshield
from app.ingestion.malware_bazaar import ingest_malware_bazaar
from app.ingestion.news_feed import ingest_news_feed

logger = logging.getLogger("ingestion")

async def run_all_ingestions():
    logger.info("Triggering comprehensive ingestion pipeline...")
    # Run in parallel with error handling per task
    results = await asyncio.gather(
        ingest_cisa_kev(),
        ingest_nvd_cve(),
        ingest_dshield(),
        ingest_malware_bazaar(),
        ingest_news_feed(),
        return_exceptions=True
    )
    for i, res in enumerate(results):
        if isinstance(res, Exception):
            logger.error(f"Task {i} failed: {res}")
        else:
            logger.info(f"Task {i} returned {res} items")
    return results
