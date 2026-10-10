import asyncio
import logging
from collections.abc import Awaitable, Callable

from app.credential_store import openphish_is_enabled
from app.ingestion.cisa_kev import ingest_cisa_kev
from app.ingestion.dshield import ingest_dshield
from app.ingestion.epss import ingest_epss
from app.ingestion.feodo_tracker import ingest_feodo_tracker
from app.ingestion.github_advisories import ingest_github_advisories
from app.ingestion.malware_bazaar import ingest_malware_bazaar
from app.ingestion.news_feed import ingest_news_feed
from app.ingestion.nvd_cve import ingest_nvd_cve
from app.ingestion.openphish import ingest_openphish
from app.ingestion.osv import ingest_osv
from app.ingestion.ransomware_live import ingest_ransomware_live
from app.ingestion.spamhaus_drop import ingest_spamhaus_drop
from app.ingestion.sslbl import ingest_sslbl
from app.ingestion.threatfox import ingest_threatfox
from app.ingestion.urlhaus import ingest_urlhaus
from app.ingestion.abuseipdb import ingest_abuseipdb
from app.ingestion.alienvault_otx import ingest_alienvault_otx
from app.ingestion.blocklist_de import ingest_blocklist_de
from app.ingestion.circl_misp import ingest_circl_misp
from app.ingestion.common import expire_stale_iocs
from app.ingestion.mitre_attack import ingest_mitre_attack
from app.ingestion.msrc_csaf import ingest_msrc_csaf
from app.ingestion.phishtank import ingest_phishtank
from app.ingestion.redhat_security import ingest_redhat_security
from app.ingestion.ransomfeed import ingest_ransomfeed
from app.ingestion.ransomlook import ingest_ransomlook
from app.ingestion.databreaches_net import ingest_databreaches_net
from app.ingestion.threatcluster import ingest_threatcluster

logger = logging.getLogger("ingestion")
Connector = Callable[[], Awaitable[int]]


async def _run_group(name: str, connectors: list[Connector]) -> list[object]:
    """Run independent connectors without allowing one failure to stop others."""
    logger.info("Starting CTI connector group %s (%d connectors)", name, len(connectors))
    results = await asyncio.gather(
        *(connector() for connector in connectors),
        return_exceptions=True,
    )
    for connector, result in zip(connectors, results):
        if isinstance(result, Exception):
            logger.error(
                "Connector %s failed outside its error boundary: %s",
                connector.__name__,
                result,
            )
        else:
            logger.info("Connector %s processed %s records", connector.__name__, result)
    return results


async def run_core_ingestions() -> list[object]:
    results = await _run_group("core", [
        ingest_cisa_kev,
        ingest_nvd_cve,
        ingest_dshield,
        ingest_malware_bazaar,
        ingest_news_feed,
        ingest_ransomware_live,
    ])
    try:
        await ingest_epss()
    except Exception:
        logger.exception("EPSS enrichment failed")
    return results


async def run_fast_ioc_ingestions() -> list[object]:
    results = await _run_group("fast-authenticated", [
        ingest_threatfox,
        ingest_urlhaus,
    ])
    # These feeds can update thousands of rows. Keep their write transactions
    # sequential so SQLite does not report a provider failure due to lock time.
    results.extend(await _run_group("fast-feodo", [ingest_feodo_tracker]))
    results.extend(await _run_group("fast-sslbl", [ingest_sslbl]))
    return results


async def run_hourly_ingestions() -> list[object]:
    results = await _run_group("hourly-github", [ingest_github_advisories])
    results.extend(await _run_group("hourly-spamhaus", [ingest_spamhaus_drop]))
    for name, connector in (
        ("hourly-otx", ingest_alienvault_otx),
        ("hourly-phishtank", ingest_phishtank),
        ("hourly-blocklist", ingest_blocklist_de),
        ("hourly-msrc", ingest_msrc_csaf),
        ("hourly-redhat", ingest_redhat_security),
        ("hourly-ransomfeed", ingest_ransomfeed),
        ("hourly-ransomlook", ingest_ransomlook),
        ("hourly-databreaches", ingest_databreaches_net),
        ("hourly-threatcluster", ingest_threatcluster),
    ):
        results.extend(await _run_group(name, [connector]))
    return results


async def run_abuseipdb_ingestion() -> list[object]:
    """Run the quota-sensitive AbuseIPDB blacklist connector independently."""
    return await _run_group("daily-abuseipdb", [ingest_abuseipdb])


async def run_slow_ingestions() -> list[object]:
    connectors: list[Connector] = [ingest_osv]
    if openphish_is_enabled():
        connectors.append(ingest_openphish)
    results = await _run_group("slow", connectors)
    results.extend(await _run_group("slow-circl", [ingest_circl_misp]))
    results.extend(await _run_group("slow-mitre", [ingest_mitre_attack]))
    await expire_stale_iocs()
    return results


async def run_all_ingestions() -> list[object]:
    """Manual full synchronization, grouped to preserve failure isolation."""
    groups = []
    for runner in (
        run_core_ingestions,
        run_fast_ioc_ingestions,
        run_hourly_ingestions,
        run_abuseipdb_ingestion,
        run_slow_ingestions,
    ):
        try:
            groups.append(await runner())
        except Exception as exc:
            logger.exception("Connector group failed outside its error boundary")
            groups.append(exc)
    return groups
