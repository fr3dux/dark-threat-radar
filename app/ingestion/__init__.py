import asyncio
import logging
from app.ingestion.cisa_kev import ingest_cisa_kev
from app.ingestion.nvd_cve import ingest_nvd_cve
from app.ingestion.dshield import ingest_dshield
from app.ingestion.malware_bazaar import ingest_malware_bazaar
from app.ingestion.news_feed import ingest_news_feed
from app.ingestion.ransomware_live import ingest_ransomware_live
from app.ingestion.epss import ingest_epss

logger = logging.getLogger("ingestion")

async def run_all_ingestions():
    logger.info("Triggering comprehensive ingestion pipeline (v1.2.0)...")
    # Run core feeds in parallel
    results = await asyncio.gather(
        ingest_cisa_kev(),
        ingest_nvd_cve(),
        ingest_dshield(),
        ingest_malware_bazaar(),
        ingest_news_feed(),
        ingest_ransomware_live(),
        return_exceptions=True
    )
    for i, res in enumerate(results):
        if isinstance(res, Exception):
            logger.error(f"Core ingestion task {i} failed: {res}")
        else:
            logger.info(f"Core ingestion task {i} returned {res} items")

    # Run EPSS enrichment after CVEs are updated
    try:
        epss_res = await ingest_epss()
        logger.info(f"EPSS enrichment updated {epss_res} records")
    except Exception as e:
        logger.error(f"EPSS enrichment failed: {e}")

    return results
