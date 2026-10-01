"""Microsoft Security Response Center machine-readable advisories."""

import json
import logging
import time
from datetime import datetime, timezone

import httpx

from app.database import get_db, update_connector_health
from app.ingestion.normalization import normalize_cve

logger = logging.getLogger("ingestion.msrc_csaf")
UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
DOCUMENT_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{release_id}"


def _note(vulnerability: dict) -> str:
    for note in vulnerability.get("Notes") or []:
        if str(note.get("Type") or "").lower() in {"description", "summary"}:
            return str(note.get("Value") or "")
    return "Microsoft security vulnerability"


def _score(value: object) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


async def ingest_msrc_csaf() -> int:
    started = time.time()
    created = updated = received = 0
    try:
        headers = {"User-Agent": "DarkThreatRadar/1.10", "Accept": "application/json"}
        async with httpx.AsyncClient(timeout=45, follow_redirects=True) as client:
            index_response = await client.get(UPDATES_URL, headers=headers)
            index_response.raise_for_status()
            releases = index_response.json().get("value") or []
            releases = sorted(
                releases, key=lambda item: str(item.get("CurrentReleaseDate") or item.get("InitialReleaseDate") or ""),
                reverse=True,
            )[:2]
            documents = []
            for release in releases:
                release_id = str(release.get("ID") or "")
                if not release_id:
                    continue
                response = await client.get(DOCUMENT_URL.format(release_id=release_id), headers=headers)
                if response.status_code == 200:
                    documents.append((release_id, release, response.json()))

        now = datetime.now(timezone.utc).isoformat()
        async with get_db() as conn:
            for release_id, release, document in documents:
                for vulnerability in document.get("Vulnerability") or []:
                    cve = normalize_cve(vulnerability.get("CVE"))
                    if not cve:
                        continue
                    received += 1
                    scores = vulnerability.get("CVSSScoreSets") or []
                    score = _score(scores[0].get("BaseScore")) if scores else None
                    severity = "CRITICAL" if score is not None and score >= 9 else "HIGH" if score is not None and score >= 7 else "MEDIUM"
                    title = _note(vulnerability)[:500]
                    remediation = vulnerability.get("Remediations") or []
                    fixed = [str(item.get("Description") or "") for item in remediation[:20] if item.get("Description")]
                    advisory_id = f"{release_id}:{cve}"
                    cursor = await conn.execute("SELECT id FROM vendor_advisories WHERE id=?", (f"msrc:{advisory_id}",))
                    exists = await cursor.fetchone()
                    await conn.execute(
                        """INSERT INTO vendor_advisories (
                           id, vendor, product, advisory_id, title, severity, cve_ids,
                           affected_versions, fixed_versions, workaround, reference_url,
                           published_date, updated_at, raw_json
                        ) VALUES (?, 'Microsoft', 'Microsoft Products', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET title=excluded.title,
                           severity=excluded.severity, fixed_versions=excluded.fixed_versions,
                           updated_at=excluded.updated_at, raw_json=excluded.raw_json""",
                        (f"msrc:{advisory_id}", advisory_id, title, severity, cve,
                         json.dumps(vulnerability.get("ProductStatuses") or {}, separators=(",", ":")),
                         json.dumps(fixed, ensure_ascii=False), "",
                         f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}",
                         str(release.get("InitialReleaseDate") or "")[:10], now,
                         json.dumps(vulnerability, ensure_ascii=False, separators=(",", ":"))[:50000]),
                    )
                    created += 0 if exists else 1
                    updated += 1 if exists else 0
            await conn.commit()

        await update_connector_health(
            "msrc_csaf", "Vulnerabilities", "healthy",
            duration_seconds=round(time.time() - started, 2), items_received=received,
            items_created=created, items_updated=updated, http_code=index_response.status_code,
        )
        return created + updated
    except Exception as exc:
        logger.exception("MSRC ingestion failed")
        await update_connector_health(
            "msrc_csaf", "Vulnerabilities", "failed",
            duration_seconds=round(time.time() - started, 2),
            last_error=f"{type(exc).__name__}: MSRC ingestion failed",
        )
        return 0
