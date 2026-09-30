# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.1] - 2026-09-29

### Changed
- **Compact Navigation Bar**: Streamlined all menu tab titles to concise, single-word labels (, , , , , , , ), eliminating horizontal overflow and scrollbars.

## [1.7.0] - 2026-09-29

### Added
- **Infrastructure Watchlist & Remediation Radar**: Added dedicated  module allowing security teams to monitor specific vendors, operating systems, products, or CVEs.
- **Automated Mitigation Directives**: Cross-references monitored assets against active CISA KEV and NIST NVD feeds to deliver official required remediation actions, mitigation deadlines (due dates), and severity ratings.
- **Standardized Navigation Icons**: Unified all menu tab icons to consistent monochrome SOC symbols, including  and .
- **Database Schema Migration 1.7.0**: Registered migration .

## [1.6.2] - 2026-09-29

### Changed
- **Localization Standardization**: Standardized 100% of UI labels, buttons, notes, and messages to English across all dashboard views, leak check forms, and API responses, eliminating mixed language discrepancies.
- **Widget Renaming**: Renamed hero radar card from `GLOBAL LIVE CYBERATTACK MAP` to **`GLOBAL INTERNET ACTIVITY`**.
- **Stream Sidebar Renaming**: Renamed live telemetry sidebar from `LIVE ATTACK STREAM` to **`LIVE TRAFFIC TELEMETRY`**.

## [1.6.1] - 2026-09-29

### Changed
- **Project Rebranding**: Renamed project and system to **Dark Threat Radar** across UI headers, footer, metadata, API service descriptions, and documentation, ensuring brand uniqueness while retaining GitHub repository path `fr3dux/threat-radar`.
- **Documentation Alignment**: Updated `README.md` to reflect Dark Threat Radar branding, architecture headers, and telemetry specifications.

## [1.6.0] - 2026-09-28

### Added
- **Credential & Data Breach Leak Check**: Added dedicated `🔍 LEAK CHECK` module allowing security teams to validate exposed emails and passwords against global threat databases.
- **K-Anonymity Password Exposure Scanner**: Integrated Cloudflare / Have I Been Pwned K-Anonymity SHA-1 range query protocol (`POST /api/leak-check/password`), ensuring passwords never leave client/server memory in cleartext while checking against 850M+ leaked passwords.
- **Email Breach Exposure Scanner**: Integrated XposedOrNot Community Breach Intelligence API (`POST /api/leak-check/email`) detecting compromised services, breach years, and exposed data types.
- **Source Transparency**: Added explicit attribution badges and explanations identifying data sources and privacy models for each check.
- **Database Schema Migration 1.6.0**: Registered migration `('1.6.0', 'Add credential leak check validation and breach lookup endpoints')`.

## [1.5.5] - 2026-09-28

### Security & Hygiene
- **Repository Security Audit**: Verified zero leaked secrets, API keys, credentials, or private keys across git history. Confirmed repository privacy (`isPrivate: true`).
- **Hygiene & Artifact Verification**: Verified strict `.gitignore` protection over SQLite databases, virtual environments, bytecode caches, and logs. Confirmed zero junk files tracked.

### Documentation
- **Comprehensive README.md Overhaul**: Completely updated documentation with all 7 synchronized threat feeds (including Ransomware.live v2 and FIRST.org EPSS), the 60 FPS cartographic Live Attack Map, updated REST API endpoints (`/api/attacks/live`, `/api/ransomware`), and automated test instructions.

## [1.5.4] - 2026-09-28

### Changed
- **Dashboard Principal Hero Integration**: Elevated the perfected, bounded 60 FPS cartographic Live Attack Map directly into the Dashboard Principal as the central hero radar widget, removing the separate navigation tab and unifying the executive view.

## [1.5.3] - 2026-09-28

### Added
- **Cartographic World Basemap**: Integrated real-world geospatial polygons (`app/static/data/world_polygons.json`, 287 geographic features) accurately rendering all global coastlines, continents, and nation borders (including Brazil, Americas, Europe, Asia, Africa, and Oceania).
- **Proportional Aspect Ratio Engine**: Configured geographic projection with guaranteed 2:1 equirectangular ratio enforcement, preventing vertical stretching or distortion across different monitor aspect ratios.

### Fixed
- **Container Height Lock & Stream Overflow**: Fixed CSS layout bug where prepending live stream attack items caused the sidebar and canvas to expand unbounded vertically. Bounded map stage and attack stream list to fixed height (`540px`) with scrollable viewport (`overflow-y: auto`).

## [1.5.2] - 2026-09-28

### Changed
- **Navigation Architecture**: Restored the Live Cyberattack Map into its own dedicated full-screen menu tab (`🌐 LIVE ATTACK MAP`), restoring the clean, compact 4-pair layout of the Dashboard Principal without visual crowding.
- **Dynamic Canvas Sizing**: Configured automatic viewport resizing upon switching to the attack map view panel to ensure sharp 60 FPS graphics and instant streaming.

## [1.5.1] - 2026-09-28

### Changed
- **Dashboard Principal Integration**: Embedded the Live Cyberattack Map directly into the Dashboard Principal as an executive hero section, eliminating the separate tab.
- **Attack Map Engine Implementation**: Fixed engine initialization bug by properly wiring HTML5 Canvas 60 FPS animation loop, automatic canvas scaling, equirectangular world continent projection, and real-time streaming feed updates on page load.

## [1.5.0] - 2026-09-28

### Added
- **Global Live Cyberattack Map**: Implemented 60 FPS HTML5 Canvas real-time cyberattack map (styled after SonicWall / Check Point / Fortinet Threat Maps) featuring ballistic attack trajectories, particle arcs, impact ripple pulses, and live stream telemetry.
- **Live Attack Telemetry Endpoint**: Added `GET /api/attacks/live` providing continuous streaming feeds connecting SANS ISC DShield global scanner IPs and targeted ports to geographic attack coordinates.
- **Dedicated Attack Map Tab**: Added `🌐 LIVE ATTACK MAP` in the navigation header with real-time attack frequency indicators, top attacking countries ranking, and live ticker stream.
- **Database Schema Migration 1.5.0**: Registered migration `('1.5.0', 'Add Live Attack Map real-time telemetry streaming and geo coordinates')` in `app/database.py`.

## [1.4.1] - 2026-09-28

### Restored
- **Synchronized Feeds Ribbon**: Restored the complete real-time status ribbon of connected CTI feeds (CISA KEV, NIST NVD, SANS DShield, MalwareBazaar, Ransomware.live, CTI News, EPSS) in the top header, maintaining full visibility into data source synchronization states and counts.

### Changed
- **Header Layout Refinement**: Preserved the approved brand and version placement (`THREAT-RADAR v1.4.1`), maintained automated 5-minute sync indicator (`AUTO-SYNC 5M`), and permanently removed the manual sync button while keeping dedicated navigation tabs.

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
