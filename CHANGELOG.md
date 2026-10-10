# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.14.5] - 2026-10-10

### Fixed
- **Wide Executive Dashboard**: Restores the dashboard's wide workspace so the global map, live telemetry, KPI rail, and paired intelligence cards retain their intended proportions.
- **Focused Operational Pages**: Keeps the centered 1180px workspace introduced in v1.14.4 for explorers, Watchlist, Leak Check, and Settings.

## [1.14.4] - 2026-10-10

### Changed
- **Unified Page Workspace**: Applies the centered 1180px Settings workspace to Dashboard, CVEs, IOCs, Malware, Telemetry, Ransomware, Advisories, Watchlist, and Leak Check.
- **Aligned Page Controls**: Centers explorer filters and the dashboard KPI rail on the same content axis while retaining responsive table scrolling and mobile edge spacing.

## [1.14.3] - 2026-10-10

### Fixed
- **Resilient Update Discovery**: Uses the GitHub latest-release redirect when the unauthenticated REST quota is exhausted, halves normal release-check API usage, and preserves the last verified state during temporary provider failures.
- **Accurate Update Status**: Replaces the alarming unknown state with a degraded warning only when no verified status exists; cached verified status remains visible with a clear non-fatal warning.
- **Ransomware.live Partial Availability**: Keeps the primary global victim feed healthy when the optional Brazil enrichment endpoint fails temporarily.

## [1.14.2] - 2026-10-10

### Fixed
- **Centered Settings Workspace**: Constrains and centers the Settings page instead of stretching the administration surface across ultrawide displays.
- **Mobile Settings Layout**: Adds dedicated phone breakpoints for the header, administrative unlock, provider controls, cards, and touch-friendly full-width actions.

## [1.14.1] - 2026-10-10

### Fixed
- **Compact Settings Authentication**: Constrains the administrative unlock form to a focused card instead of stretching the credential field across the full workspace.
- **Settings Action Hierarchy**: Replaces the oversized full-card save button with a compact action area and tighter responsive spacing.

## [1.14.0] - 2026-10-10

### Added
- **Central Settings Workspace**: Adds a dedicated Settings tab for global presentation preferences and protected feed administration.
- **Configurable IANA Timezone**: Stores threat data in UTC while consistently converting dashboard, explorer, Watchlist, artifact, and connector timestamps to the selected display timezone with an explicit zone label.
- **Localization Foundation**: Adds persisted locale preferences for English, Portuguese (Brazil), and Spanish, with locale-aware dates and a message-catalog-ready UI architecture.

### Changed
- **Integrated Feed Administration**: Moves API-key and OpenPhish controls from the former modal into Settings, retaining owner-only secret storage and live connector validation.
- **Normalized News Dates**: Exposes the canonical UTC publication timestamp to the browser instead of mixing raw provider date formats.

### Security
- **Protected Preference Changes**: Timezone and locale changes require the existing administrative access code; only non-secret presentation preferences are publicly readable.

## [1.13.1] - 2026-10-10

### Fixed
- **Immediate Update Discovery**: A full page refresh now explicitly bypasses the server-side release cache, so newly published stable versions appear immediately while background polling remains rate-limited.

## [1.13.0] - 2026-10-10

### Added
- **Multi-Source Exposure Intelligence**: Adds RansomFeed, RansomLook, and DataBreaches.net alongside Ransomware.live, plus an optional authenticated ThreatCluster connector.
- **Canonical Incident Correlation**: Correlates observations by normalized organization, domain, threat group, and time proximity so one event appears once with an `N SOURCES` indicator.
- **Complete Provenance**: Preserves provider record identifiers, first seen, last update, evidence links, raw metadata, and per-source observations for every canonical incident.
- **Confidence Escalation**: A single provider is sufficient to create an incident and Watchlist alert; independent confirmations automatically raise its confidence score.
- **Managed ThreatCluster Key**: Adds owner-only runtime key storage, web configuration, live validation, and `AUTH REQUIRED` behavior when no key is configured.

### Changed
- **Public Exposure View**: Expands the former single-provider ransomware list into a public exposure stream covering ransomware extortion and non-ransomware breach/exfiltration reporting.
- **Watchlist Attribution**: Uses canonical incident identifiers and all contributing source names, preventing duplicate company/domain alerts while retaining every matching interest.
- **Provider-Aware Scheduling**: Runs the new exposure connectors hourly and sequentially to respect public services and SQLite write isolation.

### Security
- **Bounded Untrusted Feeds**: Limits provider records and response sizes, strips RSS HTML, normalizes domains and timestamps, truncates stored fields, and continues escaped rendering with safe HTTP/HTTPS pivots.

## [1.12.2] - 2026-10-08

### Added
- **Operational Watchlist Alerts**: Adds a persistent high-visibility banner, unread navigation counter, detection timestamp, and explicit `NEW ALERT` state for public-exposure incidents.
- **Analyst Acknowledgement**: Analysts can acknowledge a correlated incident with the administrative access code, clearing its active warning while preserving the incident and evidence in Exposure history.

### Changed
- **Incident-Level Lifecycle**: A company and domain that match the same source artifact continue to produce one correlated incident, and one acknowledgement resolves that entire incident instead of requiring duplicate actions.
- **Priority Queue**: The Priority view now contains only unacknowledged exposure incidents plus high-priority vulnerability intelligence; acknowledged exposure remains available in the Exposure view.

## [1.12.1] - 2026-10-08

### Changed
- **Watchlist Workspace Redesign**: Replaces the large administration form and dense technical tables with a compact Watchlist overview, grouped monitored interests, and one curated intelligence stream.
- **Interest-Centric Navigation**: Groups companies, brands, domains, and keywords separately from vendors, products, and CVEs; selecting any interest immediately filters its relevant intelligence.
- **Priority-First View**: Shows public exposure, CISA KEV, and critical CVEs first while keeping dedicated Exposure and Vulnerabilities views for deeper analysis.
- **Progressive Administration**: Keeps the add-interest form collapsed until requested so daily analyst work remains the primary visual focus.

### Fixed
- **Duplicate Incident Presentation**: Consolidates one public incident matched by multiple Watchlist values, such as a company name and its domain, into a single alert with all matching interests identified.
- **Responsive Signal Cards**: Replaces horizontally scrolling alert tables with readable cards that retain source, evidence, relevance, remediation, and inspection actions.

## [1.12.0] - 2026-10-08

### Added
- **Organization Exposure Watchlist**: Adds Company, Brand, Domain, and Keyword targets alongside the existing Vendor, Product, and CVE monitoring.
- **Cross-Source Exposure Correlation**: Detects monitored identities in ransomware disclosures, CTI news, official vendor advisories, and active normalized public IOCs.
- **Persistent Alert Evidence**: Stores a stable alert with source, severity, matched field, evidence excerpt, source date, detection time, and original artifact reference.
- **Live Watchlist Signaling**: Highlights the Watchlist tab and checks once per minute for new exposure findings, showing an in-dashboard notification when the alert count increases.

### Changed
- **Separated Analyst Workflows**: Splits organization-exposure alerts from vulnerability and remediation matches so public mentions are not confused with technical asset risk.

### Security
- **Boundary-Aware Matching**: Applies normalized word boundaries for organization terms and exact/subdomain boundaries for domains to reduce misleading partial matches.
- **Protected Target Administration**: New Watchlist target types retain the existing administrative authentication, input validation, rate limiting, and escaped rendering controls.

## [1.11.7] - 2026-10-08

### Fixed
- **Chronological CTI News**: Normalizes RSS and local-news publication dates to UTC before sorting, preventing weekday text such as `Wed` from appearing newer than later `Thu` entries.
- **Non-Destructive News Migration**: Preserves the original publication text for display while automatically backfilling a dedicated sortable timestamp for existing installations.
- **Safe Date Fallback**: Keeps malformed or missing provider dates ingestible without allowing one feed entry to interrupt the news pipeline.

## [1.11.6] - 2026-10-02

### Fixed
- **Stable Source Health Severity**: Keeps `AUTH REQUIRED`, `RATE LIMITED`, and `DEGRADED` connector states in the amber attention tier during live polling, matching the initial server-rendered header.
- **True Failure Signaling**: Reserves the red source-health indicator and error counter exclusively for connectors in the `FAILED` state.
- **Consistent Health Counts**: Uses the same healthy, attention, authentication, disabled, and failure grouping before and after automatic dashboard refreshes.

## [1.11.5] - 2026-10-02

### Fixed
- **AbuseIPDB Daily Quota**: Moves the blacklist connector out of the hourly group and defaults it to one request per day, within the Standard plan's five-request allowance.
- **Persistent Quota Guard**: Prevents application restarts and manual synchronization from repeating calls before the configured interval, while honoring AbuseIPDB's `X-RateLimit-Reset` response header after HTTP 429.
- **Operational Visibility**: Preserves remaining, limit, reset, and retry metadata in connector health so rate-limited state remains explicit instead of appearing as a generic failure.

## [1.11.4] - 2026-10-01

### Changed
- **Stronger Product Identity**: Increases the prominence, contrast, weight, and tracking of the Dark Threat Radar name in the fixed header, with a restrained cyan identity accent while keeping engine and version badges secondary.

## [1.11.3] - 2026-10-01

### Changed
- **Priority Threat Row**: Pairs the latest CTI advisories with recent ransomware extortions immediately below the global activity map.
- **Vulnerability Context Row**: Pairs vendors with recent critical CVEs alongside the CISA KEV spotlight, while preserving every subsequent dashboard row unchanged.

## [1.11.2] - 2026-10-01

### Changed
- **News-First Dashboard**: Moves CTI Intel Spotlight directly below the global activity map and places it first in the spotlight row, keeping the latest cybersecurity news among the dashboard's highest-priority surfaces.
- **Operational Context**: Keeps the CISA KEV spotlight beside current news so analysts can immediately connect reporting with vulnerabilities actively exploited in the wild.

## [1.11.1] - 2026-10-01

### Changed
- **Dashboard Visual Hierarchy**: Moves High-Confidence IOC Activity and Public Intelligence Coverage to the end of the dashboard so the primary operational panels remain directly below the global activity map.

## [1.11.0] - 2026-10-01

### Added
- **Analyst IOC Explorer**: Adds a searchable, paginated interface for normalized IPs, domains, URLs, hashes, CVEs, CIDRs, and ASNs with provider, type, confidence, lifecycle, and source-correlation context.
- **MITRE ATT&CK Browser**: Adds a second intelligence view for techniques, groups, malware, tools, campaigns, tactics, aliases, and platforms.
- **Official Vendor Advisory API**: Exposes Microsoft MSRC and Red Hat Security advisories through `/api/vendor-advisories` and includes their matches in Watchlist remediation results.
- **Deep Intelligence Inspection**: Adds lateral inspection for IOCs, ATT&CK objects, and official vendor advisories with safe public pivots.

### Changed
- **Actionable Dashboard Metrics**: Replaces legacy single-provider counters with Active IOCs, Correlated IOCs, Malicious IPs, Vendor Advisories, and ATT&CK Objects.
- **Visible Feed Value**: Adds compact High-Confidence IOC Activity and Public Intelligence Coverage widgets directly below the global activity map.
- **Live Source Attribution**: IOC results now identify every currently active contributing source instead of exposing only the first provider.

### Security
- **Bounded Intelligence Queries**: New public explorer filters enforce length and pagination limits and continue to use parameterized database queries and escaped rendering.

## [1.10.0] - 2026-10-01

### Added
- **Eight New Public CTI Sources**: Adds AlienVault OTX, PhishTank, AbuseIPDB, blocklist.de, Microsoft MSRC, Red Hat Security Data, CIRCL MISP OSINT, and MITRE ATT&CK, bringing the engine to 23 connectors.
- **Managed Community Credentials**: OTX, PhishTank, and AbuseIPDB keys can be stored and validated through the existing authenticated Feed Settings panel without restarting the service.
- **ATT&CK Knowledge API**: Stores MITRE techniques, groups, malware, tools, and campaigns locally and exposes them through `GET /api/attack-knowledge`.
- **Source-Aware IOC Lifecycle**: Tracks expiration independently for each contributing source so stale short-lived observations expire without hiding an indicator still confirmed elsewhere.

### Changed
- **Provider-Aware Scheduling**: Runs the new public feeds at hourly or six-hour intervals appropriate to provider limits and dataset size.
- **CIRCL Feed Efficiency**: Fetches a bounded set of recent public MISP events concurrently with response-size safeguards.

### Security
- **Protected Secret Handling**: New provider keys use the owner-only runtime secret store and are never returned by the API or included in connector logs.

## [1.9.4] - 2026-10-01

### Changed
- **Persistent Update Status**: Replaces the redundant header INFOCON badge with a permanent system update indicator that shows `SYSTEM UPDATED`, an available version, update progress, or a release-check error.
- **Single INFOCON Surface**: Keeps the public SANS INFOCON state in the map HUD and updates it live with the rest of the telemetry.

## [1.9.3] - 2026-10-01

### Security
- **Stored-XSS Remediation**: Escapes untrusted Watchlist, breach, telemetry, ransomware, news, and error values; validates external URLs; and replaces dynamic inline handlers with inert data attributes.
- **Authenticated State Changes**: Manual feed synchronization and Watchlist creation/deletion now require the per-installation administrator code and are described by an OpenAPI API-key security scheme.
- **Private Password Lookup**: SHA-1 is calculated locally in the browser, so plaintext passwords never reach the Dark Threat Radar backend. The API accepts only strictly validated K-Anonymity components.
- **Abuse and Input Controls**: Adds bounded Pydantic request models, a 64 KiB mutation-body ceiling, per-client rate limits, and browser security headers.
- **Reduced Fingerprinting**: Native and Docker launchers no longer advertise the Uvicorn server header.
- **Container Hardening**: Runs with a read-only application filesystem, all Linux capabilities dropped, `no-new-privileges`, bounded memory/CPU/PIDs, and a restricted temporary filesystem.
- **Reproducible Dependencies**: Pins the complete production dependency graph in `requirements-prod.txt`, separates test/updater tooling, upgrades the base OS during image builds, and removes unnecessary build packages.
- **Updater Workspace Validation**: Automatic updates now reject untracked files as well as tracked modifications before activation.

### Changed
- **Watchlist Administration**: The dashboard now requests the administrator code before adding or deleting monitored assets while keeping Watchlist intelligence readable to all users.

## [1.9.2] - 2026-10-01

### Added
- **OpenPhish Feed Settings**: Administrators can explicitly enable or disable the OpenPhish Community connector, acknowledge provider terms, and launch a live validation without restarting the service.
- **Live Connector State**: OpenPhish now transitions from `DISABLED` to validation and then `HEALTHY` or `ERROR` using the same source-health model as the other CTI connectors.

### Changed
- **Official Community Endpoint**: OpenPhish ingestion now uses the provider's current official public-feed repository. The Community feed is correctly represented as unauthenticated instead of exposing a non-functional API-key field.
- **Docker Configuration**: Compose now forwards the initial `ENABLE_OPENPHISH` opt-in while runtime changes remain persisted in the existing protected data volume.

### Security
- **Explicit Terms Boundary**: Public deployments cannot enable OpenPhish from the web interface until an authenticated administrator confirms review of the provider terms.

## [1.9.1] - 2026-10-01

### Security
- **Safe Docker Build Context**: Excludes local secrets, databases, virtual environments, logs, and development artifacts so they cannot be embedded in an image built after local configuration.

### Fixed
- **Relocatable Update Environment**: Repairs Python console launchers and activation helpers after the updater atomically activates its validated virtual environment.

## [1.9.0] - 2026-10-01

### Added
- **Dashboard Update Notifications**: Checks the fixed official GitHub stable channel and displays a compact `UPDATE AVAILABLE` action only when a higher semantic version exists.
- **Authenticated Update Center**: Shows installed/available versions, release notes, operational state, and progress; installation requires the existing administrative access code.
- **Privilege-Separated Native Updater**: Added an opt-in, root-owned systemd path worker outside the application environment that validates the official origin and annotated tag, builds an isolated environment, runs tests, backs up SQLite, activates the release, health-checks it, and rolls back automatically on failure.
- **Container-Safe Behavior**: Docker deployments receive update notifications without exposing the host Docker socket or attempting to self-modify the running container.

### Security
- **Fixed Trust Boundary**: The browser cannot supply repositories, URLs, commands, branches, or arbitrary versions to the root-owned update worker.
- **Forward-Only Releases**: Automatic installation requires a clean `main` branch and a stable official tag whose commit is both forward from the installed commit and contained in `origin/main`.

## [1.8.8] - 2026-10-01

### Fixed
- **Ransomware Artifact Inspector**: Restored the missing API response for ransomware victim records, eliminating the HTTP 500 error when opening a recent extortion disclosure.
- **Ransomware Detail Rendering**: Added victim, threat actor, country, domain, dates, description, safe public pivots, and resilient raw-payload rendering to the lateral inspector.
- **Regression Coverage**: Added a dedicated API test that verifies ransomware artifacts and parsed source payloads are returned successfully.

## [1.8.7] - 2026-10-01

### Added
- **Per-Installation Admin Onboarding**: Added a setup command that generates a unique cryptographically random administrative access code for every clone and stores it only in the local, Git-ignored `.env` file.

### Fixed
- **Native Environment Loading**: The standalone launcher now loads `.env` and stops with a clear setup instruction when administrative access has not been initialized.
- **Docker Secret Persistence**: Docker Compose now passes the administrator and abuse.ch credentials explicitly and persists web-managed ThreatFox and URLhaus keys in the application data volume.

## [1.8.6] - 2026-10-01

### Added
- **Web API Key Administration**: Added an authenticated panel for configuring ThreatFox and URLhaus Auth-Keys without editing server files.
- **Server-Only Secret Store**: Runtime credentials are excluded from Git, written atomically with owner-only permissions, and are never returned to the browser.
- **Immediate Connector Validation**: Saving a key runs its connector immediately; missing keys remain `AUTH REQUIRED`, rejected keys show `ERROR`, and accepted keys become `HEALTHY`.

## [1.8.5] - 2026-09-30

### Fixed
- **Synchronized Targeted Ports**: Replaced the hardcoded sidebar values with a compact mirror of the public DShield `Top Targeted Ports Under Attack` widget, including records, attacker IPs, and targets.
- **Public CTI Attribution**: Both map-side streams now clearly identify their public telemetry context instead of implying monitoring of the hosting environment.
- **DShield-Weighted Stream**: Live service selection now follows the current SANS ISC DShield record distribution instead of choosing targeted ports uniformly.

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
