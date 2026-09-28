# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
