"""Canonical multi-source ransomware and public data-breach incidents."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlsplit

from app.database import get_db


SOURCE_BASE_CONFIDENCE = {
    "Ransomware.live": 72,
    "RansomFeed": 70,
    "RansomLook": 72,
    "DataBreaches.net": 58,
    "ThreatCluster": 78,
}
SOURCE_PRIORITY = {
    "ThreatCluster": 5,
    "Ransomware.live": 4,
    "RansomLook": 3,
    "RansomFeed": 2,
    "DataBreaches.net": 1,
}
GROUP_ALIASES = {
    "lockbit30": "lockbit",
    "lockbit3": "lockbit",
    "lockbit": "lockbit",
    "alphvblackcat": "alphv",
    "blackcatalphv": "alphv",
    "qilinagenda": "qilin",
}
UNKNOWN_GROUPS = {"", "unknown", "na", "unattributed", "databreach"}


@dataclass(slots=True)
class ExposureRecord:
    source_record_id: str
    victim_name: str
    group_name: str = "unknown"
    incident_type: str = "ransomware_extortion"
    country: str = ""
    activity: str = ""
    domain: str = ""
    discovered: str = ""
    attackdate: str = ""
    description: str = ""
    claim_url: str = ""
    screenshot: str = ""
    reference_url: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


def _clean(value: Any, limit: int) -> str:
    text = " ".join(str(value or "").replace("\x00", "").split())
    return text[:limit]


def normalize_domain(value: str | None) -> str:
    candidate = _clean(value, 500).casefold().strip(". ")
    if not candidate:
        return ""
    if "://" not in candidate:
        candidate = f"//{candidate}"
    host = (urlsplit(candidate).hostname or "").strip(".")
    if host.startswith("www."):
        host = host[4:]
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    if not re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
        host,
    ):
        return ""
    return host


def normalize_organization(value: str | None) -> str:
    text = unicodedata.normalize("NFKD", value or "").casefold()
    text = "".join(char for char in text if not unicodedata.combining(char))
    text = re.sub(r"https?://|www\.", " ", text)
    text = re.sub(r"[^a-z0-9]+", " ", text)
    suffixes = {
        "inc", "incorporated", "llc", "ltd", "limited", "corp", "corporation",
        "company", "co", "gmbh", "plc", "sa", "spa", "bv", "ag", "group",
    }
    tokens = [token for token in text.split() if token not in suffixes]
    return " ".join(tokens)[:300]


def normalize_group(value: str | None) -> str:
    compact = re.sub(r"[^a-z0-9]+", "", (value or "").casefold())
    return GROUP_ALIASES.get(compact, compact)


def parse_datetime(value: str | None) -> datetime | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        parsed = parsedate_to_datetime(text)
    except (TypeError, ValueError, OverflowError):
        parsed = None
    if parsed is None:
        candidate = text.replace("Z", "+00:00").replace(" UTC", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d/%m/%Y"):
                try:
                    parsed = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalized_timestamp(value: str | None) -> str:
    parsed = parse_datetime(value)
    return parsed.isoformat().replace("+00:00", "Z") if parsed else ""


def _dates_close(left: str | None, right: str | None, days: int = 21) -> bool:
    left_date = parse_datetime(left)
    right_date = parse_datetime(right)
    if not left_date or not right_date:
        return True
    return abs((left_date - right_date).total_seconds()) <= days * 86400


def _organization_related(left: str, right: str) -> bool:
    if not left or not right:
        return False
    if left == right:
        return True
    shorter, longer = sorted((left, right), key=len)
    return len(shorter) >= 5 and re.search(rf"(?:^| ){re.escape(shorter)}(?: |$)", longer) is not None


def _canonical_id(record: ExposureRecord) -> str:
    domain = normalize_domain(record.domain)
    organization = normalize_organization(record.victim_name)
    group = normalize_group(record.group_name)
    day = (normalized_timestamp(record.discovered or record.attackdate) or "unknown")[:10]
    material = f"{domain or organization}\0{group}\0{day}".encode("utf-8")
    return f"exp-{hashlib.sha256(material).hexdigest()[:24]}"


def _source_observation_id(source_name: str, source_record_id: str) -> str:
    material = f"{source_name}\0{source_record_id}".encode("utf-8")
    return f"src-{hashlib.sha256(material).hexdigest()[:28]}"


def _canonical_key(record: ExposureRecord) -> str:
    return ":".join(filter(None, (
        normalize_domain(record.domain),
        normalize_organization(record.victim_name),
        normalize_group(record.group_name),
    )))[:700]


def _matching_score(record: ExposureRecord, candidate: dict[str, Any]) -> int:
    record_domain = normalize_domain(record.domain)
    candidate_domain = normalize_domain(candidate.get("domain"))
    record_org = normalize_organization(record.victim_name)
    candidate_org = normalize_organization(candidate.get("victim_name"))
    if not _dates_close(
        record.discovered or record.attackdate,
        candidate.get("discovered") or candidate.get("attackdate"),
    ):
        return 0
    group_left = normalize_group(record.group_name)
    group_right = normalize_group(candidate.get("group_name"))
    compatible_group = (
        group_left in UNKNOWN_GROUPS or group_right in UNKNOWN_GROUPS or group_left == group_right
    )
    if record_domain and candidate_domain and record_domain == candidate_domain:
        return 100 if compatible_group else 88
    if record_org and candidate_org and record_org == candidate_org:
        return 94 if compatible_group else 82
    if _organization_related(record_org, candidate_org):
        return 80 if compatible_group else 0
    return 0


async def _find_incident(conn, record: ExposureRecord) -> str | None:
    existing = await (await conn.execute(
        """SELECT incident_id FROM exposure_incident_sources
           WHERE source_name=? AND source_record_id=?""",
        (record.raw.get("_source_name"), record.source_record_id),
    )).fetchone()
    if existing:
        return existing["incident_id"]
    rows = await (await conn.execute(
        """SELECT id, victim_name, group_name, domain, discovered, attackdate
           FROM ransomware_victims ORDER BY COALESCE(last_seen, updated_at) DESC LIMIT 5000"""
    )).fetchall()
    scored = [(_matching_score(record, dict(row)), row["id"]) for row in rows]
    score, incident_id = max(scored, default=(0, None))
    return incident_id if score >= 80 else None


async def _recompute_incident(conn, incident_id: str, now: str) -> None:
    rows = [dict(row) for row in await (await conn.execute(
        """SELECT * FROM exposure_incident_sources WHERE incident_id=?
           ORDER BY last_seen DESC""",
        (incident_id,),
    )).fetchall()]
    if not rows:
        return
    ranked = sorted(rows, key=lambda row: (
        SOURCE_PRIORITY.get(row["source_name"], 0),
        bool(row.get("domain")),
        len(row.get("description") or ""),
    ), reverse=True)
    primary = ranked[0]
    source_names = sorted({row["source_name"] for row in rows})
    source_count = len(source_names)
    base = max(SOURCE_BASE_CONFIDENCE.get(name, 55) for name in source_names)
    confidence = min(98, base + (15 if source_count >= 2 else 0) + (8 if source_count >= 3 else 0) + (3 if source_count >= 4 else 0))
    first_seen = min(filter(None, (row.get("first_seen") for row in rows)), default=now)
    last_seen = max(filter(None, (row.get("last_seen") for row in rows)), default=now)
    best_description = max((row.get("description") or "" for row in rows), key=len, default="")
    best_domain = next((normalize_domain(row.get("domain")) for row in ranked if normalize_domain(row.get("domain"))), "")
    best_group = next((row.get("group_name") for row in ranked if normalize_group(row.get("group_name")) not in UNKNOWN_GROUPS), "unknown")
    incident_type = "ransomware_extortion" if any(row["incident_type"] == "ransomware_extortion" for row in rows) else "data_breach"
    discovered_values = [normalized_timestamp(row.get("discovered") or row.get("attackdate")) for row in rows]
    discovered = min(filter(None, discovered_values), default=primary.get("discovered") or "")
    await conn.execute(
        """UPDATE ransomware_victims SET
             victim_name=?, group_name=?, country=?, activity=?, domain=?, discovered=?,
             attackdate=?, description=?, claim_url=?, screenshot=?, url=?, raw_json=?,
             updated_at=?, incident_type=?, canonical_key=?, first_seen=?, last_seen=?,
             confidence_score=?, source_count=?, source_names=? WHERE id=?""",
        (
            primary["victim_name"], best_group, primary.get("country") or "",
            primary.get("activity") or "", best_domain, discovered,
            primary.get("attackdate") or "", best_description,
            primary.get("claim_url") or "", primary.get("screenshot") or "",
            primary.get("reference_url") or "", primary.get("raw_json") or "{}",
            now, incident_type,
            ":".join(filter(None, (best_domain, normalize_organization(primary["victim_name"]), normalize_group(best_group))))[:700],
            first_seen, last_seen, confidence, source_count,
            json.dumps(source_names, ensure_ascii=False, separators=(",", ":")), incident_id,
        ),
    )


async def upsert_exposure_records(source_name: str, records: list[ExposureRecord]) -> dict[str, int]:
    """Correlate provider records into incidents while preserving every observation."""
    stats = {"received": len(records), "created": 0, "updated": 0, "dropped": 0, "duplicated": 0}
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    async with get_db() as conn:
        for record in records:
            record.source_record_id = _clean(record.source_record_id, 500)
            record.victim_name = _clean(record.victim_name, 500)
            if not record.source_record_id or len(normalize_organization(record.victim_name)) < 2:
                stats["dropped"] += 1
                continue
            record.group_name = _clean(record.group_name, 200) or "unknown"
            record.country = _clean(record.country, 100)
            record.activity = _clean(record.activity, 300)
            record.domain = normalize_domain(record.domain)
            record.description = _clean(record.description, 8000)
            record.claim_url = _clean(record.claim_url, 2000)
            record.screenshot = _clean(record.screenshot, 2000)
            record.reference_url = _clean(record.reference_url, 2000)
            record.discovered = normalized_timestamp(record.discovered) or _clean(record.discovered, 100)
            record.attackdate = normalized_timestamp(record.attackdate) or _clean(record.attackdate, 100)
            record.raw["_source_name"] = source_name
            source_id = _source_observation_id(source_name, record.source_record_id)
            existing_source = await (await conn.execute(
                "SELECT incident_id FROM exposure_incident_sources WHERE id=?", (source_id,)
            )).fetchone()
            incident_id = existing_source["incident_id"] if existing_source else await _find_incident(conn, record)
            if not incident_id:
                incident_id = _canonical_id(record)
                collision = await (await conn.execute(
                    "SELECT 1 FROM ransomware_victims WHERE id=?", (incident_id,)
                )).fetchone()
                if collision:
                    incident_id = f"{incident_id}-{hashlib.sha256(source_id.encode()).hexdigest()[:6]}"
                await conn.execute(
                    """INSERT INTO ransomware_victims (
                         id, victim_name, group_name, country, activity, domain, discovered,
                         attackdate, description, claim_url, screenshot, url, raw_json,
                         updated_at, incident_type, canonical_key, first_seen, last_seen,
                         confidence_score, source_count, source_names
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)""",
                    (
                        incident_id, record.victim_name, record.group_name, record.country,
                        record.activity, record.domain, record.discovered, record.attackdate,
                        record.description, record.claim_url, record.screenshot,
                        record.reference_url,
                        json.dumps(record.raw, ensure_ascii=False, separators=(",", ":"), default=str)[:32000],
                        now, record.incident_type, _canonical_key(record), now, now,
                        SOURCE_BASE_CONFIDENCE.get(source_name, 55),
                        json.dumps([source_name], separators=(",", ":")),
                    ),
                )
                stats["created"] += 1
            elif existing_source:
                stats["duplicated"] += 1
            else:
                stats["updated"] += 1
            raw_json = json.dumps(record.raw, ensure_ascii=False, separators=(",", ":"), default=str)[:32000]
            await conn.execute(
                """INSERT INTO exposure_incident_sources (
                     id, incident_id, source_name, source_record_id, incident_type,
                     victim_name, group_name, country, activity, domain, discovered,
                     attackdate, description, claim_url, screenshot, reference_url,
                     raw_json, first_seen, last_seen
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(source_name, source_record_id) DO UPDATE SET
                     victim_name=excluded.victim_name, group_name=excluded.group_name,
                     country=excluded.country, activity=excluded.activity,
                     domain=excluded.domain, discovered=excluded.discovered,
                     attackdate=excluded.attackdate, description=excluded.description,
                     claim_url=excluded.claim_url, screenshot=excluded.screenshot,
                     reference_url=excluded.reference_url, raw_json=excluded.raw_json,
                     last_seen=excluded.last_seen""",
                (
                    source_id, incident_id, source_name, record.source_record_id,
                    record.incident_type, record.victim_name, record.group_name,
                    record.country, record.activity, record.domain, record.discovered,
                    record.attackdate, record.description, record.claim_url,
                    record.screenshot, record.reference_url, raw_json,
                    existing_source and now or (record.discovered or now), now,
                ),
            )
            await _recompute_incident(conn, incident_id, now)
        await conn.commit()
    return stats
