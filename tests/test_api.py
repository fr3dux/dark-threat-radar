"""Automated Test Suite for ThreatRadar API & Core Architecture
Validates endpoints, schema consistency, versioning, migrations, and error handling.
"""

import asyncio
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.version import __version__, __app_name__
from app.database import init_db, get_schema_migrations


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


def test_index_page_version_injection(client):
    """Test web index page contains header version badge and footer text."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    # Header badge
    assert f"v{__version__}" in html
    assert 'class="version-badge"' in html
    # Footer
    assert f"ThreatRadar v{__version__} // SOC Engine //" in html
    assert 'class="app-footer"' in html
    assert '<a href="/docs"' in html


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
    """Test database schema contains 1.3.0 migration record."""
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
