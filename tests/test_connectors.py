"""Offline tests for connector contracts and schema migration."""

import asyncio
import stat
from datetime import datetime, timedelta, timezone

import aiosqlite

from app import database
from app import credential_store
from app.ingestion import _run_group
from app import ingestion
from app.ingestion import abuseipdb, threatfox, urlhaus
from app.ingestion.spamhaus_drop import parse_ndjson
from app.ingestion.sslbl import _recent
from app.ingestion.urlhaus import parse_recent_csv
from app.ingestion.common import IOCRecord, expire_stale_iocs, upsert_ioc_records
from app.ingestion.normalization import TYPE_IPV4
from app.news_dates import normalize_news_date
from app.ingestion.exposure_incidents import ExposureRecord, upsert_exposure_records
from app.ingestion.ransomfeed import parse_ransomfeed
from app.ingestion.ransomlook import parse_ransomlook
from app.ingestion.databreaches_net import parse_databreaches_feed
from app.ingestion.threatcluster import parse_threatcluster


def test_spamhaus_ndjson_parser():
    payload = '# comment\n{"cidr":"192.0.2.0/24","asn":64500}\n{"cidr":"2001:db8::/32"}\n'
    rows = parse_ndjson(payload)
    assert rows[0]["cidr"] == "192.0.2.0/24"
    assert len(rows) == 2


def test_spamhaus_invalid_ndjson_fails_closed():
    try:
        parse_ndjson('{"cidr":')
    except ValueError as exc:
        assert "line 1" in str(exc)
    else:
        raise AssertionError("invalid feed must not be reported healthy")


def test_urlhaus_recent_csv_parser():
    payload = (
        '# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n'
        '123,"2026-09-30 00:00:00",http://bad.test/a,online,2026-09-30,malware_download,"elf,botnet",https://urlhaus.test/123,tester\n'
    )
    rows = parse_recent_csv(payload)
    assert rows[0]["id"] == "123"
    assert rows[0]["tags"] == ["elf", "botnet"]


def test_sslbl_ja3_recency():
    assert _recent("2019-01-01 00:00:00") is False


def test_connector_group_isolates_failures():
    async def good():
        return 7

    async def bad():
        raise RuntimeError("provider unavailable")

    result = asyncio.run(_run_group("test", [bad, good]))
    assert isinstance(result[0], RuntimeError)
    assert result[1] == 7


def test_migration_is_idempotent_and_openphish_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test.db")

    async def verify():
        await database.init_db()
        await database.init_db()
        connectors = await database.get_all_connector_health()
        versions = await database.get_schema_migrations()
        async with database.get_db() as conn:
            cve_columns = {
                row[1] for row in await (await conn.execute("PRAGMA table_info(cve_records)")).fetchall()
            }
            exposure_columns = {
                row[1] for row in await (await conn.execute("PRAGMA table_info(ransomware_victims)")).fetchall()
            }
            settings = {
                row["setting_key"]: row["setting_value"]
                for row in await (await conn.execute(
                    "SELECT setting_key, setting_value FROM app_settings"
                )).fetchall()
            }
        return connectors, versions, cve_columns, exposure_columns, settings

    connectors, versions, cve_columns, exposure_columns, settings = asyncio.run(verify())
    assert len(connectors) == 27
    assert next(c for c in connectors if c["source_name"] == "openphish")["state"] == "disabled"
    assert "incident_type" not in cve_columns
    assert {"incident_type", "confidence_score", "source_count", "source_names"} <= exposure_columns
    assert settings == {"timezone": "UTC", "locale": "en"}
    assert sum(v["version"] == "1.8.1" for v in versions) == 1


def test_news_dates_sort_chronologically_across_weekdays():
    wednesday = normalize_news_date("Wed, 30 Sep 2026 23:43:51 +0000")
    thursday = normalize_news_date("Thu, 08 Oct 2026 09:00:00 +0000")
    local_date = normalize_news_date("2026-10-07 09:00")
    assert wednesday == "2026-09-30T23:43:51Z"
    assert thursday == "2026-10-08T09:00:00Z"
    assert local_date == "2026-10-07T09:00:00Z"
    assert wednesday < local_date < thursday
    assert normalize_news_date("provider-date-unavailable") is None


def test_news_date_migration_backfills_legacy_rows(tmp_path, monkeypatch):
    database_path = tmp_path / "legacy-news.db"
    monkeypatch.setattr(database, "DB_PATH", database_path)

    async def verify():
        async with aiosqlite.connect(database_path) as conn:
            await conn.execute("""
                CREATE TABLE cti_news (
                    id TEXT PRIMARY KEY, title TEXT NOT NULL, link TEXT NOT NULL,
                    source TEXT NOT NULL, published_date TEXT, snippet TEXT, updated_at TEXT
                )
            """)
            await conn.executemany(
                "INSERT INTO cti_news VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    ("older", "Older", "https://example.test/older", "Test",
                     "Wed, 30 Sep 2026 23:43:51 +0000", "", "2026-10-01 00:00:00 UTC"),
                    ("newer", "Newer", "https://example.test/newer", "Test",
                     "Thu, 08 Oct 2026 09:00:00 +0000", "", "2026-10-08 09:01:00 UTC"),
                ],
            )
            await conn.commit()

        await database.init_db()
        async with database.get_db() as conn:
            columns = [row[1] for row in await (await conn.execute(
                "PRAGMA table_info(cti_news)"
            )).fetchall()]
            rows = await (await conn.execute(
                "SELECT id, published_at FROM cti_news "
                "ORDER BY COALESCE(published_at, updated_at) DESC"
            )).fetchall()
            migrations = await (await conn.execute(
                "SELECT version FROM schema_migrations WHERE version='1.11.7'"
            )).fetchall()
        return columns, [(row["id"], row["published_at"]) for row in rows], migrations

    columns, rows, migrations = asyncio.run(verify())
    assert "published_at" in columns
    assert [row[0] for row in rows] == ["newer", "older"]
    assert rows[0][1] == "2026-10-08T09:00:00Z"
    assert len(migrations) == 1


def test_runtime_credentials_are_owner_only_and_never_require_restart(tmp_path, monkeypatch):
    secret_path = tmp_path / ".runtime-secrets.json"
    monkeypatch.setattr(credential_store, "RUNTIME_SECRETS_PATH", secret_path)
    monkeypatch.delenv("THREATFOX_AUTH_KEY", raising=False)

    credential_store.save_provider_secret("threatfox", "test-secret-value")
    assert credential_store.get_provider_secret("threatfox") == "test-secret-value"
    assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600

    credential_store.delete_provider_secret("threatfox")
    assert credential_store.get_provider_secret("threatfox") == ""


def test_new_provider_credentials_share_protected_runtime_store(tmp_path, monkeypatch):
    secret_path = tmp_path / ".runtime-secrets.json"
    monkeypatch.setattr(credential_store, "RUNTIME_SECRETS_PATH", secret_path)
    for provider in ("alienvault_otx", "phishtank", "abuseipdb", "threatcluster"):
        monkeypatch.delenv(credential_store.PROVIDER_ENV_VARS[provider], raising=False)
        credential_store.save_provider_secret(provider, f"{provider}-test-key")
        assert credential_store.provider_secret_is_configured(provider) is True
    assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600


def test_exposure_provider_parsers():
    ransomfeed = parse_ransomfeed([{
        "id": 10, "hash": "rf-10", "victim": "Example Corp", "gang": "Qilin",
        "website": "www.example.com/path", "date": "2026-10-09 10:00:00",
    }])
    assert ransomfeed[0].domain == "www.example.com/path"
    ransomlook = parse_ransomlook([{
        "id": "rl-10", "post_title": "Example Corp", "group_name": "qilin",
        "discovered": "2026-10-09T11:00:00Z",
    }])
    assert ransomlook[0].victim_name == "Example Corp"
    rss = b"""<?xml version='1.0'?><rss version='2.0'><channel><title>DataBreaches</title>
      <item><guid>db-10</guid><title>Example Corp reports data exposure</title>
      <link>https://databreaches.net/example</link><pubDate>Fri, 09 Oct 2026 12:00:00 +0000</pubDate>
      <description><![CDATA[<p>Customer records were exposed.</p>]]></description></item>
      </channel></rss>"""
    breach = parse_databreaches_feed(rss)
    assert breach[0].incident_type == "data_breach"
    assert "Customer records" in breach[0].description
    threatcluster = parse_threatcluster({"results": [{
        "id": "tc-10", "victim_name": "Example Corp", "group_name": "Qilin",
        "domain": "example.com", "discovered_at": "2026-10-09T12:00:00Z",
    }]})
    assert threatcluster[0].source_record_id == "tc-10"


def test_multi_source_exposure_correlation_and_provenance(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "exposure.db")

    async def scenario():
        await database.init_db()
        first = await upsert_exposure_records("Ransomware.live", [ExposureRecord(
            source_record_id="live-1", victim_name="Example Corp", group_name="Qilin",
            domain="example.com", discovered="2026-10-08T10:00:00Z",
        )])
        second = await upsert_exposure_records("RansomFeed", [ExposureRecord(
            source_record_id="feed-1", victim_name="Example Corporation", group_name="qilin",
            domain="www.example.com", discovered="2026-10-09T10:00:00Z",
        )])
        third = await upsert_exposure_records("DataBreaches.net", [ExposureRecord(
            source_record_id="news-1", victim_name="Example Corp reports data exposure",
            group_name="data breach", incident_type="data_breach",
            discovered="Fri, 09 Oct 2026 12:00:00 +0000",
        )])
        duplicate = await upsert_exposure_records("RansomFeed", [ExposureRecord(
            source_record_id="feed-1", victim_name="Example Corporation", group_name="qilin",
            domain="example.com", discovered="2026-10-09T10:00:00Z",
        )])
        # Re-running startup migrations must not fabricate a Ransomware.live
        # observation for incidents that already have real source provenance.
        await database.init_db()
        async with database.get_db() as conn:
            incidents = [dict(row) for row in await (await conn.execute(
                "SELECT * FROM ransomware_victims"
            )).fetchall()]
            sources = [dict(row) for row in await (await conn.execute(
                "SELECT * FROM exposure_incident_sources"
            )).fetchall()]
        return first, second, third, duplicate, incidents, sources

    first, second, third, duplicate, incidents, sources = asyncio.run(scenario())
    assert first["created"] == 1
    assert second["updated"] == 1
    assert third["updated"] == 1
    assert duplicate["duplicated"] == 1
    assert len(incidents) == 1
    assert incidents[0]["source_count"] == 3
    assert incidents[0]["confidence_score"] > 72
    assert set(__import__("json").loads(incidents[0]["source_names"])) == {
        "Ransomware.live", "RansomFeed", "DataBreaches.net",
    }
    assert len(sources) == 3


def test_source_aware_expiry_keeps_correlated_ioc_active(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "expiry.db")
    now = datetime.now(timezone.utc)

    async def verify():
        await database.init_db()
        await upsert_ioc_records("blocklist_de", [IOCRecord(
            TYPE_IPV4, "203.0.113.10", "scanner",
            expires_at=(now - timedelta(minutes=1)).isoformat(),
        )])
        await upsert_ioc_records("abuseipdb", [IOCRecord(
            TYPE_IPV4, "203.0.113.10", "abusive_host",
            expires_at=(now + timedelta(days=1)).isoformat(),
        )])
        await expire_stale_iocs()
        async with database.get_db() as conn:
            row = await (await conn.execute(
                "SELECT active FROM normalized_iocs WHERE normalized_value='203.0.113.10'"
            )).fetchone()
            sources = await (await conn.execute(
                "SELECT source_name, active FROM ioc_sources ORDER BY source_name"
            )).fetchall()
        return row["active"], [(item["source_name"], item["active"]) for item in sources]

    active, sources = asyncio.run(verify())
    assert active == 1
    assert sources == [("abuseipdb", 1), ("blocklist_de", 0)]


def test_openphish_runtime_opt_in_is_persistent(tmp_path, monkeypatch):
    secret_path = tmp_path / ".runtime-secrets.json"
    monkeypatch.setattr(credential_store, "RUNTIME_SECRETS_PATH", secret_path)
    monkeypatch.delenv("ENABLE_OPENPHISH", raising=False)

    assert credential_store.openphish_is_enabled() is False
    credential_store.save_openphish_settings(
        enabled=True,
        terms_accepted=True,
    )

    assert credential_store.openphish_is_enabled() is True
    assert credential_store.openphish_terms_accepted() is True
    assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600


def test_openphish_cannot_be_enabled_without_terms_confirmation(tmp_path, monkeypatch):
    monkeypatch.setattr(credential_store, "RUNTIME_SECRETS_PATH", tmp_path / "secrets.json")
    try:
        credential_store.save_openphish_settings(enabled=True, terms_accepted=False)
    except ValueError as exc:
        assert "terms" in str(exc).lower()
    else:
        raise AssertionError("OpenPhish must remain opt-in")


def test_slow_group_reads_live_openphish_setting(monkeypatch):
    calls = []

    async def fake_osv():
        calls.append("osv")
        return 1

    async def fake_openphish():
        calls.append("openphish")
        return 1

    async def fake_circl():
        calls.append("circl")
        return 1

    async def fake_mitre():
        calls.append("mitre")
        return 1

    async def fake_expire():
        calls.append("expire")
        return 0

    monkeypatch.setattr(ingestion, "ingest_osv", fake_osv)
    monkeypatch.setattr(ingestion, "ingest_openphish", fake_openphish)
    monkeypatch.setattr(ingestion, "ingest_circl_misp", fake_circl)
    monkeypatch.setattr(ingestion, "ingest_mitre_attack", fake_mitre)
    monkeypatch.setattr(ingestion, "expire_stale_iocs", fake_expire)
    monkeypatch.setattr(ingestion, "openphish_is_enabled", lambda: True)

    asyncio.run(ingestion.run_slow_ingestions())
    assert calls == ["osv", "openphish", "circl", "mitre", "expire"]


def test_rejected_threatfox_key_is_error_not_auth_required(monkeypatch):
    states = []

    class RejectedResponse:
        status_code = 401

    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *_args): return None
        async def post(self, *_args, **_kwargs): return RejectedResponse()

    async def capture_state(_source, _category, state, **_kwargs):
        states.append(state)

    monkeypatch.setattr(threatfox, "get_provider_secret", lambda _provider: "rejected-key")
    monkeypatch.setattr(threatfox.httpx, "AsyncClient", lambda **_kwargs: FakeClient())
    monkeypatch.setattr(threatfox, "update_connector_health", capture_state)

    asyncio.run(threatfox.ingest_threatfox())
    assert states == ["failed"]


def test_rejected_urlhaus_key_is_error_not_auth_required(monkeypatch):
    states = []

    class RejectedResponse:
        status_code = 403

    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *_args): return None
        async def get(self, *_args, **_kwargs): return RejectedResponse()

    async def capture_state(_source, _category, state, **_kwargs):
        states.append(state)

    monkeypatch.setattr(urlhaus, "get_provider_secret", lambda _provider: "rejected-key")
    monkeypatch.setattr(urlhaus.httpx, "AsyncClient", lambda **_kwargs: FakeClient())
    monkeypatch.setattr(urlhaus, "update_connector_health", capture_state)

    asyncio.run(urlhaus.ingest_urlhaus())
    assert states == ["failed"]


def test_abuseipdb_persistent_quota_guard():
    now = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
    recent_success = {
        "state": "healthy",
        "http_code": 200,
        "last_attempt": "2026-10-02 11:00:00 UTC",
        "rate_limit_info": "remaining=4; limit=5; reset=1790985600",
    }
    assert abuseipdb.request_is_due(recent_success, now) is False

    old_success = dict(recent_success, last_attempt="2026-10-01 11:00:00 UTC")
    assert abuseipdb.request_is_due(old_success, now) is True

    limited = {
        "state": "rate_limited",
        "http_code": 429,
        "last_attempt": "2026-10-02 10:00:00 UTC",
        "rate_limit_info": f"remaining=0; limit=5; reset={int((now + timedelta(hours=2)).timestamp())}",
    }
    assert abuseipdb.request_is_due(limited, now) is False
    limited["rate_limit_info"] = (
        f"remaining=0; limit=5; reset={int((now - timedelta(minutes=1)).timestamp())}"
    )
    assert abuseipdb.request_is_due(limited, now) is True


def test_abuseipdb_429_preserves_provider_reset(monkeypatch):
    captured = {}

    class LimitedResponse:
        status_code = 429
        headers = {
            "x-ratelimit-remaining": "0",
            "x-ratelimit-limit": "5",
            "x-ratelimit-reset": "1790985600",
            "retry-after": "3600",
        }

    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *_args): return None
        async def get(self, *_args, **_kwargs): return LimitedResponse()

    async def no_previous_health(_source):
        return None

    async def capture_state(_source, _category, state, **kwargs):
        captured.update(state=state, **kwargs)

    monkeypatch.setattr(abuseipdb, "get_provider_secret", lambda _provider: "test-key")
    monkeypatch.setattr(abuseipdb, "get_connector_health", no_previous_health)
    monkeypatch.setattr(abuseipdb.httpx, "AsyncClient", lambda **_kwargs: FakeClient())
    monkeypatch.setattr(abuseipdb, "update_connector_health", capture_state)

    asyncio.run(abuseipdb.ingest_abuseipdb())
    assert captured["state"] == "rate_limited"
    assert captured["http_code"] == 429
    assert captured["rate_limit_info"] == (
        "remaining=0; limit=5; reset=1790985600; retry_after=3600"
    )
