"""Persistent exposure monitoring for organization-oriented Watchlist entries."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from datetime import datetime, timezone
from urllib.parse import urlsplit

from app.database import get_db


EXPOSURE_TYPES = {"company", "brand", "domain", "keyword"}


def normalize_text(value: str | None) -> str:
    normalized = unicodedata.normalize("NFKC", value or "").casefold()
    return " ".join(normalized.split())


def normalize_domain(value: str | None) -> str:
    candidate = normalize_text(value).strip(". ")
    if not candidate:
        return ""
    if "://" not in candidate:
        candidate = f"//{candidate}"
    parsed = urlsplit(candidate)
    host = (parsed.hostname or "").strip(".")
    if host.startswith("www."):
        host = host[4:]
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    if len(host) > 253 or not re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
        host,
    ):
        return ""
    return host


def text_matches(needle: str, *values: str | None) -> bool:
    target = normalize_text(needle)
    if not target:
        return False
    haystack = normalize_text(" ".join(value or "" for value in values))
    start = 0
    while True:
        index = haystack.find(target, start)
        if index < 0:
            return False
        before = haystack[index - 1] if index else ""
        end = index + len(target)
        after = haystack[end] if end < len(haystack) else ""
        left_ok = not (target[0].isalnum() and before.isalnum())
        right_ok = not (target[-1].isalnum() and after.isalnum())
        if left_ok and right_ok:
            return True
        start = index + 1


def domain_matches(watched: str, candidate: str | None) -> bool:
    target = normalize_domain(watched)
    host = normalize_domain(candidate)
    return bool(target and host and (host == target or host.endswith(f".{target}")))


def _alert_id(watchlist_id: str, source_type: str, artifact_id: str) -> str:
    material = f"{watchlist_id}\0{source_type}\0{artifact_id}".encode("utf-8")
    return f"wla-{hashlib.sha256(material).hexdigest()[:24]}"


def _truncate(value: str | None, limit: int = 500) -> str:
    text = " ".join((value or "").split())
    return text[:limit]


async def refresh_watchlist_alerts(watchlist_id: str | None = None) -> int:
    """Cross-reference exposure targets with locally ingested public CTI."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    created = 0

    async with get_db() as conn:
        query = "SELECT * FROM watchlist WHERE item_type IN ('company','brand','domain','keyword')"
        params: tuple[str, ...] = ()
        if watchlist_id:
            query += " AND id = ?"
            params = (watchlist_id,)
        targets = [dict(row) for row in await (await conn.execute(query, params)).fetchall()]
        if not targets:
            return 0

        ransomware = [dict(row) for row in await (await conn.execute(
            """SELECT id, victim_name, group_name, country, activity, domain,
                      description, url, claim_url, discovered, updated_at
               FROM ransomware_victims"""
        )).fetchall()]
        news = [dict(row) for row in await (await conn.execute(
            """SELECT id, title, source, link, snippet, published_date,
                      published_at, updated_at FROM cti_news"""
        )).fetchall()]
        advisories = [dict(row) for row in await (await conn.execute(
            """SELECT id, vendor, product, advisory_id, title, cve_ids,
                      reference_url, published_date, updated_at
               FROM vendor_advisories"""
        )).fetchall()]

        for target in targets:
            target_id = target["id"]
            target_type = target["item_type"]
            watched = target["value"]
            matches: list[dict[str, str | None]] = []

            for row in ransomware:
                matched_field = None
                if target_type == "domain" and domain_matches(watched, row.get("domain")):
                    matched_field = "domain"
                elif target_type != "domain" and text_matches(
                    watched, row.get("victim_name"), row.get("domain"),
                    row.get("activity"), row.get("description"),
                ):
                    matched_field = "victim disclosure"
                if matched_field:
                    evidence = row.get("description") or row.get("domain") or row.get("victim_name")
                    matches.append({
                        "source_type": "ransomware", "source_name": "Ransomware.live",
                        "artifact_id": row["id"], "title": row.get("victim_name") or watched,
                        "matched_field": matched_field, "severity": "CRITICAL",
                        "evidence": evidence, "reference_url": row.get("url") or row.get("claim_url"),
                        "source_date": row.get("discovered") or row.get("updated_at"),
                    })

            for row in news:
                fields = (row.get("title"), row.get("snippet"), row.get("link"))
                matched = (
                    text_matches(watched, row.get("title"), row.get("snippet"))
                    or domain_matches(watched, row.get("link"))
                    if target_type == "domain"
                    else text_matches(watched, *fields)
                )
                if matched:
                    matches.append({
                        "source_type": "news", "source_name": row.get("source") or "CTI News",
                        "artifact_id": row["id"], "title": row.get("title") or watched,
                        "matched_field": "title / summary", "severity": "HIGH",
                        "evidence": row.get("snippet") or row.get("title"),
                        "reference_url": row.get("link"),
                        "source_date": row.get("published_at") or row.get("published_date") or row.get("updated_at"),
                    })

            for row in advisories:
                fields = (row.get("vendor"), row.get("product"), row.get("title"), row.get("cve_ids"))
                matched = target_type != "domain" and text_matches(watched, *fields)
                if matched:
                    matches.append({
                        "source_type": "advisory", "source_name": row.get("vendor") or "Vendor Advisory",
                        "artifact_id": row["id"], "title": row.get("title") or watched,
                        "matched_field": "vendor advisory", "severity": "HIGH",
                        "evidence": " ".join(filter(None, fields)),
                        "reference_url": row.get("reference_url"),
                        "source_date": row.get("published_date") or row.get("updated_at"),
                    })

            if target_type == "domain":
                normalized = normalize_domain(watched)
                if normalized:
                    cursor = await conn.execute(
                        """SELECT id, indicator_type, indicator_value, normalized_value,
                                  threat_type, confidence, severity, source_name,
                                  reference_url, source_url, first_seen, last_seen, updated_at
                           FROM normalized_iocs
                           WHERE active=1 AND revoked=0
                             AND indicator_type IN ('domain','hostname','url')
                             AND (
                               (indicator_type IN ('domain','hostname')
                                AND (LOWER(normalized_value)=? OR LOWER(normalized_value) LIKE ?))
                               OR (indicator_type='url' AND LOWER(normalized_value) LIKE ?)
                             )""",
                        (normalized, f"%.{normalized}", f"%{normalized}%"),
                    )
                    for row_obj in await cursor.fetchall():
                        row = dict(row_obj)
                        candidate = row.get("normalized_value") or row.get("indicator_value")
                        if not domain_matches(normalized, candidate):
                            continue
                        matches.append({
                            "source_type": "ioc", "source_name": row.get("source_name") or "Public IOC",
                            "artifact_id": row["id"], "title": row.get("indicator_value") or normalized,
                            "matched_field": row.get("indicator_type") or "domain IOC",
                            "severity": row.get("severity") or "HIGH",
                            "evidence": f"{row.get('threat_type') or 'Malicious infrastructure'}; confidence {row.get('confidence') or 0}%",
                            "reference_url": row.get("reference_url") or row.get("source_url"),
                            "source_date": row.get("last_seen") or row.get("first_seen") or row.get("updated_at"),
                        })
            elif target_type in {"company", "brand", "keyword"}:
                normalized = normalize_text(watched)
                cursor = await conn.execute(
                    """SELECT id, indicator_type, indicator_value, normalized_value,
                              threat_type, confidence, severity, source_name,
                              reference_url, source_url, first_seen, last_seen, updated_at
                       FROM normalized_iocs
                       WHERE active=1 AND revoked=0
                         AND indicator_type IN ('domain','hostname','url')
                         AND LOWER(normalized_value) LIKE ?
                       LIMIT 250""",
                    (f"%{normalized}%",),
                )
                for row_obj in await cursor.fetchall():
                    row = dict(row_obj)
                    candidate = row.get("normalized_value") or row.get("indicator_value")
                    if not text_matches(watched, candidate):
                        continue
                    matches.append({
                        "source_type": "ioc", "source_name": row.get("source_name") or "Public IOC",
                        "artifact_id": row["id"], "title": row.get("indicator_value") or watched,
                        "matched_field": row.get("indicator_type") or "malicious IOC",
                        "severity": row.get("severity") or "HIGH",
                        "evidence": f"{row.get('threat_type') or 'Malicious infrastructure'}; confidence {row.get('confidence') or 0}%",
                        "reference_url": row.get("reference_url") or row.get("source_url"),
                        "source_date": row.get("last_seen") or row.get("first_seen") or row.get("updated_at"),
                    })

            for match in matches:
                alert_id = _alert_id(target_id, str(match["source_type"]), str(match["artifact_id"]))
                cursor = await conn.execute("SELECT 1 FROM watchlist_alerts WHERE id = ?", (alert_id,))
                existed = await cursor.fetchone()
                await conn.execute(
                    """INSERT INTO watchlist_alerts (
                           id, watchlist_id, source_type, source_name, artifact_id,
                           title, matched_value, matched_field, severity, evidence,
                           reference_url, source_date, detected_at, last_seen
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(id) DO UPDATE SET
                           source_name=excluded.source_name, title=excluded.title,
                           matched_field=excluded.matched_field, severity=excluded.severity,
                           evidence=excluded.evidence, reference_url=excluded.reference_url,
                           source_date=excluded.source_date, last_seen=excluded.last_seen""",
                    (
                        alert_id, target_id, match["source_type"], match["source_name"],
                        match["artifact_id"], _truncate(match["title"], 300), watched,
                        match["matched_field"], str(match["severity"]).upper(),
                        _truncate(match["evidence"]), match["reference_url"],
                        match["source_date"], now, now,
                    ),
                )
                if not existed:
                    created += 1

        await conn.commit()
    return created
