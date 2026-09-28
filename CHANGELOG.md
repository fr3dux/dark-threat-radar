# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-09-28

### Added
- **Automated 5-Minute Ingestion Scheduler**: Configured continuous background feed synchronization cycle every 5 minutes (`SYNC_INTERVAL_SECONDS = 300`), removing manual sync friction.
- **Enterprise Header & Navigation System**: Redesigned top navigation into a sleek, unified enterprise SOC header with integrated live auto-sync beacon, SANS Infocon indicator, refined tab pills, and active status telemetry.

### Removed
- **Manual SYNC FEEDS Button**: Retired manual sync button in favor of fully autonomous, zero-touch continuous background ingestion.

## [1.3.1] - 2026-09-28

### Changed
- **Dashboard Layout Priority**: Reordered Row 1 to place 'Critical Vendor Threats (Citrix, SharePoint, etc.)' and 'Recent Ransomware Extortions' at the very top of the grid, prioritizing real-time active exploitation over cumulative historical volume.

## [1.3.0] - 2026-09-28

### Added
- **Critical Vendor Threats Spotlight**: Added dedicated dashboard widget tracking vendors with actively exploited, critical CVEs from recent weeks (highlighting Citrix NetScaler, Microsoft SharePoint, MikroTik RouterOS, Adobe, F5 BIG-IP).
- **Ransomware Spotlight Widget**: Paired the critical vendor widget with live recent ransomware extortion disclosures from Ransomware.live v2, maintaining clean 2-column symmetry.
- **Database Schema Migration 1.3.0**: Registered migration ('1.3.0', 'Add critical vendor threats query and recent ransomware spotlight') in app/database.py.
- **Enriched Stats Endpoint**: Updated /api/stats and get_dashboard_stats() to deliver recent_critical_vendors and recent_ransomware_victims.

## [1.2.0] - 2026-09-28

### Added
- **Ransomware.live v2 CTI Integration**: Implemented collector `app/ingestion/ransomware_live.py` ingesting recent victims (`/v2/recentvictims`) and Brazil-specific telemetry (`/v2/country/brazil`) with robust SQLite upsert logic.
- **EPSS Scoring & Exploitation Probability**: Implemented collector `app/ingestion/epss.py` consuming FIRST.org EPSS API (`https://api.first.org/data/v1/epss`) to dynamically enrich CVE records with exploit probability scores and percentiles.
- **Database Schema Migration 1.2.0**: Added migration `('1.2.0', 'Add ransomware_victims table, Brazil telemetry, and EPSS scoring columns')` in `app/database.py`. Created `ransomware_victims` table with indices on `group_name`, `country`, and `discovered`. Added `epss_score` and `epss_percentile` columns to `cve_records`.
- **Ransomware API & Schema Architecture**: Added `RansomwareVictim` and `RansomwareListResponse` Pydantic models in `app/schemas.py`. Exposed `/api/ransomware` endpoint with pagination and multi-vector filtering (`q`, `group`, `country`).
- **Dashboard Telemetry Aggregations**: Added metrics `total_ransomware_victims`, `total_brazil_victims`, and `top_ransomware_groups` to `/api/stats` and `get_dashboard_stats()`.
- **Ransomware Tracker Web UI**: Created dedicated 'RANSOMWARE TRACKER' navigation tab with live victim counter, country and threat group filtering, and priority highlighting for Brazil (`BR`).
- **EPSS Visual Badges & Inspection**: Added EPSS probability column to the CVE Explorer table alongside CVSS and integrated EPSS score/percentile badges into the lateral artifact inspection drawer.
- **Automated Test Suite Expansion**: Added test coverage in `tests/test_api.py` for `/api/ransomware`, EPSS data fields, and schema migration 1.2.0 verification.

## [1.1.0] - 2026-09-28

### Added
- **Centralized Semantic Versioning**: Added `app/version.py` defining single-source-of-truth metadata (`__version__ = '1.1.0'`, `__app_name__`, `release_date`, and helper functions).
- **Version Endpoints & Telemetry**: Exposed `/api/version` and enriched `/api/status` & `/api/stats` with version payloads.
- **UI Versioning Indicators**: Injected dynamic version badges in web navigation header (`v1.1.0`) and unified application footer linking to `/docs`.
- **Pydantic v2 Architecture**: Added `app/schemas.py` with strict Pydantic v2 schemas for all API payloads, query pagination, dashboard statistics, telemetry, and error models.
- **Database Schema Migrations**: Introduced `schema_migrations` tracking table in `app/database.py` with transactional migration registration to preserve schema continuity and prevent breaking changes.
- **Standardized Error Handling**: Configured FastAPI exception handlers for `HTTPException` and `RequestValidationError` with structured JSON payloads (`error`, `status_code`, `detail`).
- **Automated Test Suite**: Created `tests/test_api.py` utilizing `pytest` and `fastapi.testclient.TestClient` covering system health, versioning, CVE queries, telemetry, artifacts, error handling, and migrations.
- **CI/CD Pipeline**: Configured GitHub Actions workflow (`.github/workflows/ci.yml`) for automated linting and test execution across Python 3.11 and 3.12.

### Changed
- Standardized artifact deep inspection endpoints to throw unified `HTTPException` with 400/404 HTTP statuses.
- Upgraded project dependencies in `requirements.txt` to include test runners (`pytest`).

## [1.0.0] - 2026-09-25

### Added
- **Autonomous CTI Engine**: Standalone threat intelligence aggregation platform for SOC analysts.
- **Multi-Feed Ingestion**:
  - CISA Known Exploited Vulnerabilities (KEV).
  - NVD CVE 2.0 API with CVSS scoring.
  - SANS ISC DShield Infocon, attacking sources, and port targeting telemetry.
  - MalwareBazaar real-time malware sample stream.
  - Curated CTI news and vulnerability advisories.
- **Analyst Web Dashboard**: Responsive dark SOC interface with real-time counters, search filters, and lateral deep inspection drawer.
- **Background Scheduler**: Async ingestion worker using APScheduler with non-blocking concurrency and manual sync triggers.
- **Local Persistence**: Embedded SQLite storage with Write-Ahead Logging (WAL) and index optimization.
