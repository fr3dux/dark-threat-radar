"""Offline tests for connector contracts and schema migration."""

import asyncio

from app import database
from app.ingestion import _run_group
from app.ingestion.spamhaus_drop import parse_ndjson
from app.ingestion.sslbl import _recent
from app.ingestion.urlhaus import parse_recent_csv


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
        return connectors, versions

    connectors, versions = asyncio.run(verify())
    assert len(connectors) == 15
    assert next(c for c in connectors if c["source_name"] == "openphish")["state"] == "disabled"
    assert sum(v["version"] == "1.8.1" for v in versions) == 1
