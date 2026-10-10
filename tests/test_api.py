"""Automated Test Suite for ThreatRadar API & Core Architecture
Validates endpoints, schema consistency, versioning, migrations, and error handling.
"""

import asyncio
from contextlib import asynccontextmanager

import aiosqlite
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import main as main_module
from app import credential_store
from app.version import __version__, __app_name__
from app.database import init_db, get_schema_migrations
from app.security import rate_limiter


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Ensure database schema is initialized and migrations are applied before tests run."""
    asyncio.run(init_db())


@pytest.fixture(scope="module")
def client():
    """Provide a TestClient instance for API requests."""
    with TestClient(app) as test_client:
        yield test_client


def test_api_version(client):
    """Test /api/version returns semantic versioning metadata."""
    response = client.get("/api/version")
    assert response.status_code == 200
    data = response.json()
    assert data["version"] == __version__
    assert data["app_name"] == __app_name__
    assert "release_date" in data
    assert "description" in data
    assert "author" in data
    assert "license" in data


def test_update_status_endpoint(client, monkeypatch):
    async def fake_status(force=False):
        return {
            "current_version": "1.9.0",
            "latest_version": "1.9.1",
            "latest_tag": "v1.9.1",
            "update_available": True,
            "updater_enabled": True,
        }

    monkeypatch.setattr(main_module, "get_update_status", fake_status)
    response = client.get("/api/update/status")
    assert response.status_code == 200
    assert response.json()["update_available"] is True


def test_update_install_requires_admin_and_queues(client, monkeypatch):
    monkeypatch.setattr(main_module, "SETTINGS_ADMIN_TOKEN", "update-admin-code")

    async def fake_queue():
        return {"status": "queued", "target_version": "1.9.1"}

    monkeypatch.setattr(main_module, "queue_latest_update", fake_queue)
    assert client.post("/api/admin/update").status_code == 401
    response = client.post(
        "/api/admin/update",
        headers={"X-Admin-Token": "update-admin-code"},
    )
    assert response.status_code == 202
    assert response.json() == {"status": "queued", "target_version": "1.9.1"}


def test_openphish_admin_opt_in_requires_terms_and_reports_unauthenticated_feed(client, tmp_path, monkeypatch):
    secret_path = tmp_path / ".runtime-secrets.json"
    sync_calls = []

    async def fake_sync(provider):
        sync_calls.append(provider)

    monkeypatch.setattr(main_module, "SETTINGS_ADMIN_TOKEN", "openphish-admin-code")
    monkeypatch.setattr(credential_store, "RUNTIME_SECRETS_PATH", secret_path)
    monkeypatch.setattr(main_module, "sync_managed_integration", fake_sync)
    headers = {"X-Admin-Token": "openphish-admin-code"}

    rejected = client.put(
        "/api/admin/integrations/openphish/settings",
        headers=headers,
        json={"enabled": True, "terms_accepted": False},
    )
    assert rejected.status_code == 422

    enabled = client.put(
        "/api/admin/integrations/openphish/settings",
        headers=headers,
        json={"enabled": True, "terms_accepted": True},
    )
    assert enabled.status_code == 200
    assert enabled.json()["validation"] == "started"
    assert sync_calls == ["openphish"]

    settings = client.get("/api/admin/integrations", headers=headers)
    openphish = next(item for item in settings.json()["items"] if item["provider"] == "openphish")
    assert openphish["enabled"] is True
    assert openphish["terms_accepted"] is True
    assert openphish["configured"] is False

    disabled = client.put(
        "/api/admin/integrations/openphish/settings",
        headers=headers,
        json={"enabled": False, "terms_accepted": False},
    )
    assert disabled.status_code == 200
    assert disabled.json()["state"] == "disabled"


def test_api_status(client):
    """Test /api/status returns live feed states, sync lock, and version."""
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["version"] == __version__
    assert "feeds" in data
    assert isinstance(data["feeds"], list)
    assert "sync" in data
    assert "is_syncing" in data["sync"]


def test_api_stats(client):
    """Test /api/stats returns complete dashboard metrics."""
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert data["version"] == __version__
    assert "stats" in data
    assert "total_cves" in data["stats"]
    assert "cvss_distribution" in data["stats"]
    assert "infocon" in data["stats"]
    assert "total_active_iocs" in data["stats"]
    assert "total_correlated_iocs" in data["stats"]
    assert "total_vendor_advisories" in data["stats"]
    assert "total_attack_objects" in data["stats"]
    assert "feeds" in data
    assert "sync" in data


def test_api_cves(client):
    """Test /api/cves returns paginated CVE records."""
    response = client.get("/api/cves?limit=10&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert data["limit"] == 10
    assert data["offset"] == 0
    assert isinstance(data["items"], list)


def test_api_malware(client):
    """Test /api/malware returns paginated malware samples."""
    response = client.get("/api/malware?limit=10&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert data["limit"] == 10
    assert isinstance(data["items"], list)


def test_public_intelligence_explorer_endpoints(client):
    for endpoint in (
        "/api/iocs?limit=10&active=true",
        "/api/attack-knowledge?limit=10",
        "/api/vendor-advisories?limit=10",
    ):
        response = client.get(endpoint)
        assert response.status_code == 200
        assert {"total", "limit", "offset", "items"} <= set(response.json())


def test_api_dshield(client):
    """Test /api/dshield returns Infocon, sources, and port telemetry."""
    response = client.get("/api/dshield")
    assert response.status_code == 200
    data = response.json()
    assert "infocon" in data
    assert "sources" in data
    assert "ports" in data
    assert isinstance(data["sources"], list)
    assert isinstance(data["ports"], list)


def test_api_news(client):
    """Test /api/news returns paginated CTI news stream."""
    response = client.get("/api/news?limit=10&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert data["limit"] == 10
    assert isinstance(data["items"], list)


def test_artifact_cve_not_found(client):
    """Test non-existent CVE artifact returns standardized 404 JSON."""
    response = client.get("/api/artifact/cve/CVE-9999-99999")
    assert response.status_code == 404
    data = response.json()
    assert "error" in data
    assert "CVE-9999-99999 not found" in data["error"]
    assert data["status_code"] == 404


def test_artifact_invalid_type(client):
    """Test invalid artifact type returns standardized 400 JSON."""
    response = client.get("/api/artifact/invalid_type/test1234")
    assert response.status_code == 400
    data = response.json()
    assert "error" in data
    assert data["status_code"] == 400


def test_artifact_invalid_port(client):
    """Test non-numeric port artifact returns standardized 400 JSON."""
    response = client.get("/api/artifact/port/invalid_port")
    assert response.status_code == 400
    data = response.json()
    assert "error" in data
    assert "Invalid port number" in data["error"]
    assert data["status_code"] == 400


def test_artifact_ransomware_returns_record_and_parsed_payload(client, monkeypatch):
    """Ransomware inspection must return a complete artifact instead of HTTP 500."""

    @asynccontextmanager
    async def ransomware_test_db():
        conn = await aiosqlite.connect(":memory:")
        conn.row_factory = aiosqlite.Row
        await conn.execute(
            """
            CREATE TABLE ransomware_victims (
                id TEXT PRIMARY KEY,
                victim_name TEXT NOT NULL,
                group_name TEXT NOT NULL,
                country TEXT,
                raw_json TEXT
            )
            """
        )
        await conn.execute(
            """CREATE TABLE exposure_incident_sources (
                   id TEXT PRIMARY KEY, incident_id TEXT, source_name TEXT,
                   source_record_id TEXT, incident_type TEXT, victim_name TEXT,
                   group_name TEXT, domain TEXT, discovered TEXT, description TEXT,
                   reference_url TEXT, first_seen TEXT, last_seen TEXT
               )"""
        )
        await conn.execute(
            """INSERT INTO exposure_incident_sources VALUES
               (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("src-test", "victim-test-id", "Ransomware.live", "provider-1",
             "ransomware_extortion", "Example Corp", "example-group", "example.test",
             "2026-10-08", "Evidence", "https://example.test/record",
             "2026-10-08", "2026-10-09"),
        )
        await conn.execute(
            """INSERT INTO ransomware_victims
               (id, victim_name, group_name, country, raw_json)
               VALUES (?, ?, ?, ?, ?)""",
            ("victim-test-id", "Example Corp", "example-group", "BR", '{"source":"ransomware.live"}'),
        )
        await conn.commit()
        try:
            yield conn
        finally:
            await conn.close()

    monkeypatch.setattr(main_module, "get_db", ransomware_test_db)
    response = client.get("/api/artifact/ransomware/victim-test-id")

    assert response.status_code == 200
    payload = response.json()
    assert payload["type"] == "ransomware"
    assert payload["identifier"] == "victim-test-id"
    assert payload["data"]["victim_name"] == "Example Corp"
    assert payload["data"]["parsed_raw"] == {"source": "ransomware.live"}
    assert isinstance(payload["data"]["raw_json"], str)
    assert payload["data"]["source_observations"][0]["source_name"] == "Ransomware.live"


def test_index_page_version_injection(client):
    """Test web index page contains header version badge and footer text."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    # Header badge
    assert f"v{__version__}" in html
    assert 'class="brand-name">DARK THREAT RADAR</span>' in html
    assert 'class="version-badge"' in html
    assert 'id="update-available-pill"' in html
    assert 'id="infocon-badge"' not in html
    assert 'id="infocon-val"' in html
    assert 'id="panel-intel"' in html
    assert '<h2>WATCHLIST</h2>' in html
    assert 'INTELLIGENCE FOR YOU' in html
    assert 'MY THREAT RADAR' not in html
    assert "HIGH-CONFIDENCE IOC ACTIVITY" in html
    assert html.index("GLOBAL INTERNET ACTIVITY") < html.index("CTI INTEL SPOTLIGHT: LATEST ADVISORIES")
    assert html.index("CTI INTEL SPOTLIGHT: LATEST ADVISORIES") < html.index("RECENT PUBLIC EXPOSURES")
    assert html.index("RECENT PUBLIC EXPOSURES") < html.index("VENDORS W/ CRITICAL CVES")
    assert html.index("VENDORS W/ CRITICAL CVES") < html.index("KEV SPOTLIGHT: RECENT EXPLOITS IN THE WILD")
    assert html.index("KEV SPOTLIGHT: RECENT EXPLOITS IN THE WILD") < html.index("CVSS SEVERITY DISTRIBUTION")
    assert html.index("CVSS SEVERITY DISTRIBUTION") < html.index("HIGH-CONFIDENCE IOC ACTIVITY")
    assert html.index("HIGH-CONFIDENCE IOC ACTIVITY") < html.index('id="panel-intel"')
    # Footer
    assert f"Dark Threat Radar v{__version__} // SOC Engine //" in html
    assert 'class="app-footer"' in html
    assert '<a href="/docs"' in html


def test_source_health_summary_uses_red_only_for_real_failures(client, monkeypatch):
    def connector(source_name, state):
        return {
            "source_name": source_name,
            "category": "Test Sources",
            "state": state,
            "last_error": None,
            "last_success": None,
        }

    async def attention_connectors():
        return [
            connector("healthy_feed", "healthy"),
            connector("abuseipdb", "rate_limited"),
            connector("phishtank", "auth_required"),
        ]

    monkeypatch.setattr(main_module, "get_all_connector_health", attention_connectors)
    attention_html = client.get("/").text
    assert 'id="feed-summary-btn" data-health="attention"' in attention_html
    assert '<span class="health-count attention">1 attention</span>' in attention_html
    assert '<span class="health-count failed">' not in attention_html

    async def failed_connectors():
        return [
            connector("healthy_feed", "healthy"),
            connector("broken_feed", "failed"),
        ]

    monkeypatch.setattr(main_module, "get_all_connector_health", failed_connectors)
    failed_html = client.get("/").text
    assert 'id="feed-summary-btn" data-health="failed"' in failed_html
    assert '<span class="health-count failed">1 error</span>' in failed_html


def test_index_uses_dynamic_public_cti_port_ranking(client):
    """Map port ranking must mirror public DShield data, not fixed demo totals."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    assert 'id="map-top-targeted-ports"' in html
    assert "TOP TARGETED PORTS" in html
    assert "PUBLIC CTI" in html
    assert "561k probes" not in html
    assert "472k probes" not in html
    assert "374k probes" not in html


def test_admin_integration_keys_are_protected_and_never_returned(client, tmp_path, monkeypatch):
    secret_path = tmp_path / ".runtime-secrets.json"
    monkeypatch.setattr(main_module, "SETTINGS_ADMIN_TOKEN", "test-admin-code")
    monkeypatch.setattr(credential_store, "RUNTIME_SECRETS_PATH", secret_path)
    monkeypatch.delenv("THREATFOX_AUTH_KEY", raising=False)

    async def fake_sync(_provider):
        return None

    monkeypatch.setattr(main_module, "sync_managed_integration", fake_sync)

    unauthorized = client.get("/api/admin/integrations")
    assert unauthorized.status_code == 401

    headers = {"X-Admin-Token": "test-admin-code"}
    saved = client.put(
        "/api/admin/integrations/threatfox",
        headers=headers,
        json={"api_key": "private-test-key"},
    )
    assert saved.status_code == 200

    status = client.get("/api/admin/integrations", headers=headers)
    assert status.status_code == 200
    assert status.json()["items"][0]["configured"] is True
    assert "private-test-key" not in status.text

    removed = client.delete("/api/admin/integrations/threatfox", headers=headers)
    assert removed.status_code == 200
    assert removed.json()["state"] == "auth_required"


def test_database_schema_migrations():
    """Verify schema migrations table exists and tracks migrations."""
    migrations = asyncio.run(get_schema_migrations())
    assert len(migrations) >= 2
    versions = [m["version"] for m in migrations]
    assert "1.0.0" in versions
    assert "1.3.0" in versions


def test_api_ransomware(client):
    """Test /api/ransomware returns victim list and metadata."""
    response = client.get("/api/ransomware?limit=10&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "brazil_total" in data
    assert "items" in data
    assert isinstance(data["items"], list)


def test_schema_migration_120(client):
    """Test database schema contains 1.2.0 migration record."""
    import asyncio
    async def check():
        migrations = await get_schema_migrations()
        versions = [m["version"] for m in migrations]
        assert "1.2.0" in versions
    asyncio.run(check())


def test_schema_migration_130(client):
    """Test database schema contains 1.5.1 migration record."""
    import asyncio
    async def check():
        migrations = await get_schema_migrations()
        versions = [m["version"] for m in migrations]
        assert "1.3.0" in versions
    asyncio.run(check())


def test_recent_critical_vendors_in_stats(client):
    """Test /api/stats includes recent_critical_vendors and recent_ransomware_victims."""
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert "recent_critical_vendors" in data["stats"]
    assert "recent_ransomware_victims" in data["stats"]


def test_api_attacks_live(client):
    """Test /api/attacks/live returns real-time attack trajectories."""
    response = client.get("/api/attacks/live")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "attacks" in data
    assert isinstance(data["attacks"], list)
    if data["attacks"]:
        atk = data["attacks"][0]
        assert "src_country" in atk
        assert "dst_country" in atk
        assert "port" in atk
        assert "service" in atk


def test_schema_migration_150(client):
    """Test database schema contains 1.5.1 migration record."""
    import asyncio
    async def check():
        migrations = await get_schema_migrations()
        versions = [m["version"] for m in migrations]
        assert "1.5.0" in versions
    asyncio.run(check())


def test_leak_check_password(client):
    """Test /api/leak-check/password with known leaked password."""
    response = client.post(
        "/api/leak-check/password",
        json={
            "sha1_prefix": "CBFDA",
            "sha1_suffix": "C6008F9CAB4083784CBD1874F76618D2A97",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["exposed"] is True
    assert data["count"] > 1000
    assert "Have I Been Pwned" in data["source"]

    plaintext = client.post("/api/leak-check/password", json={"password": "password123"})
    assert plaintext.status_code == 422


def test_leak_check_email(client):
    """Test /api/leak-check/email endpoint."""
    response = client.post("/api/leak-check/email", json={"email": "test@example.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "exposed" in data
    assert "source" in data


def test_schema_migration_160(client):
    """Test database schema contains 1.6.1 migration record."""
    import asyncio
    async def check():
        migrations = await get_schema_migrations()
        versions = [m["version"] for m in migrations]
        assert "1.6.0" in versions
    asyncio.run(check())


def test_api_watchlist_crud(client):
    """Test watchlist CRUD endpoints."""
    main_module.SETTINGS_ADMIN_TOKEN = "watchlist-admin-code"
    headers = {"X-Admin-Token": "watchlist-admin-code"}
    assert client.post(
        "/api/watchlist",
        json={"item_type": "vendor", "value": "Citrix"},
    ).status_code == 401

    # 1. Add item
    add_res = client.post(
        "/api/watchlist",
        headers=headers,
        json={"item_type": "vendor", "value": "Citrix", "notes": "Edge Gateway"},
    )
    assert add_res.status_code == 200
    item_id = add_res.json()["id"]

    # 2. Get list and verify matching
    get_res = client.get("/api/watchlist")
    assert get_res.status_code == 200
    data = get_res.json()
    assert data["total_items"] >= 1
    assert any(w["value"] == "Citrix" for w in data["watchlist"])
    assert "exposure_alerts" in data
    assert "total_exposure_alerts" in data
    assert "total_vulnerability_alerts" in data

    # 3. Delete item
    del_res = client.delete(f"/api/watchlist/{item_id}", headers=headers)
    assert del_res.status_code == 200


def test_watchlist_correlated_alert_acknowledgement(client):
    """One source incident matched by company and domain has one alert lifecycle."""
    main_module.SETTINGS_ADMIN_TOKEN = "watchlist-ack-code"
    headers = {"X-Admin-Token": "watchlist-ack-code"}

    async def seed_correlated_incident():
        async with main_module.get_db() as conn:
            for item_id, item_type, value in (
                ("wl-ack-company", "company", "Ack Example Corp"),
                ("wl-ack-domain", "domain", "ack-example.invalid"),
            ):
                await conn.execute(
                    """INSERT OR REPLACE INTO watchlist
                       (id, item_type, value, notes, created_at) VALUES (?, ?, ?, ?, ?)""",
                    (item_id, item_type, value, "Acknowledgement test", "2026-10-08T12:00:00+00:00"),
                )
                await conn.execute(
                    """INSERT OR REPLACE INTO watchlist_alerts
                       (id, watchlist_id, source_type, source_name, artifact_id, title,
                        matched_value, matched_field, severity, evidence, source_date,
                        detected_at, last_seen, acknowledged_at)
                       VALUES (?, ?, 'ransomware', 'Ransomware.live', 'ack-artifact-1',
                               'Ack Example Corp', ?, 'victim disclosure', 'CRITICAL',
                               'Correlated acknowledgement test', '2026-10-08',
                               '2026-10-08 12:00:00 UTC', '2026-10-08 12:00:00 UTC', NULL)""",
                    (f"wla-ack-{item_type}", item_id, value),
                )
            await conn.commit()

    async def cleanup():
        async with main_module.get_db() as conn:
            await conn.execute("DELETE FROM watchlist WHERE id IN ('wl-ack-company','wl-ack-domain')")
            await conn.commit()

    asyncio.run(seed_correlated_incident())
    try:
        before = client.get("/api/watchlist").json()
        incident = next(
            item for item in before["exposure_alerts"]
            if item["artifact_id"] == "ack-artifact-1"
        )
        assert incident["acknowledged"] == 0
        assert set(incident["matched_values"].split(",")) == {
            "Ack Example Corp", "ack-example.invalid"
        }

        unauthenticated = client.post(
            "/api/watchlist/alerts/acknowledge",
            json={"source_type": "ransomware", "artifact_id": "ack-artifact-1"},
        )
        assert unauthenticated.status_code == 401

        acknowledged = client.post(
            "/api/watchlist/alerts/acknowledge",
            headers=headers,
            json={"source_type": "ransomware", "artifact_id": "ack-artifact-1"},
        )
        assert acknowledged.status_code == 200
        assert acknowledged.json()["status"] == "acknowledged"

        after = client.get("/api/watchlist").json()
        incident = next(
            item for item in after["exposure_alerts"]
            if item["artifact_id"] == "ack-artifact-1"
        )
        assert incident["acknowledged"] == 1
        assert incident["acknowledged_at"]
    finally:
        asyncio.run(cleanup())


def test_schema_migration_1122(client):
    async def check():
        migrations = await get_schema_migrations()
        versions = [migration["version"] for migration in migrations]
        assert "1.12.2" in versions
        async with main_module.get_db() as conn:
            columns = await (await conn.execute("PRAGMA table_info(watchlist_alerts)")).fetchall()
            assert "acknowledged_at" in {column[1] for column in columns}

    asyncio.run(check())


def test_watchlist_validation_and_stored_xss_is_rendered_inert(client):
    main_module.SETTINGS_ADMIN_TOKEN = "watchlist-xss-code"
    headers = {"X-Admin-Token": "watchlist-xss-code"}
    payload = '<img src=x onerror="document.title=\'XSS\'">'
    added = client.post(
        "/api/watchlist",
        headers=headers,
        json={"item_type": "vendor", "value": payload, "notes": payload},
    )
    assert added.status_code == 200
    item_id = added.json()["id"]

    page = client.get("/")
    assert page.status_code == 200
    assert payload not in page.text
    assert "X-Content-Type-Options" in page.headers
    assert page.headers["X-Frame-Options"] == "DENY"

    invalid = client.post(
        "/api/watchlist",
        headers=headers,
        json={"item_type": "invalid", "value": "test"},
    )
    assert invalid.status_code == 422
    assert client.delete(f"/api/watchlist/{item_id}", headers=headers).status_code == 200


def test_manual_sync_requires_admin(client, monkeypatch):
    main_module.SETTINGS_ADMIN_TOKEN = "sync-admin-code"

    async def fake_sync(_background_tasks):
        return {"status": "started"}

    monkeypatch.setattr(main_module, "trigger_manual_sync", fake_sync)
    assert client.post("/api/sync").status_code == 401
    allowed = client.post("/api/sync", headers={"X-Admin-Token": "sync-admin-code"})
    assert allowed.status_code == 200


def test_admin_rate_limit_and_request_size_limit(client):
    rate_limiter.clear()
    main_module.SETTINGS_ADMIN_TOKEN = "rate-limit-code"
    for _ in range(20):
        response = client.get("/api/admin/integrations", headers={"X-Admin-Token": "wrong"})
        assert response.status_code == 401
    limited = client.get("/api/admin/integrations", headers={"X-Admin-Token": "wrong"})
    assert limited.status_code == 429
    assert "Retry-After" in limited.headers
    rate_limiter.clear()

    oversized = client.post(
        "/api/leak-check/email",
        content=b"x" * (65 * 1024),
        headers={"Content-Type": "application/json"},
    )
    assert oversized.status_code == 413

def test_schema_migration_170(client):
    """Test database schema contains 1.7.10 migration record."""
    import asyncio
    async def check():
        migrations = await get_schema_migrations()
        versions = [m["version"] for m in migrations]
        assert "1.7.0" in versions
    asyncio.run(check())
