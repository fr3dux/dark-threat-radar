"""Offline tests for connector contracts and schema migration."""

import asyncio
import stat

from app import database
from app import credential_store
from app.ingestion import _run_group
from app.ingestion import threatfox, urlhaus
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


def test_runtime_credentials_are_owner_only_and_never_require_restart(tmp_path, monkeypatch):
    secret_path = tmp_path / ".runtime-secrets.json"
    monkeypatch.setattr(credential_store, "RUNTIME_SECRETS_PATH", secret_path)
    monkeypatch.delenv("THREATFOX_AUTH_KEY", raising=False)

    credential_store.save_provider_secret("threatfox", "test-secret-value")
    assert credential_store.get_provider_secret("threatfox") == "test-secret-value"
    assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600

    credential_store.delete_provider_secret("threatfox")
    assert credential_store.get_provider_secret("threatfox") == ""


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
