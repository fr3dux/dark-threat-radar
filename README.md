# Dark Threat Radar

[![Version](https://img.shields.io/badge/version-1.9.1-blue.svg)](app/version.py)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Threat Intelligence](https://img.shields.io/badge/CTI-Autonomous%20Engine-red.svg)](https://github.com/fr3dux/dark-threat-radar)
[![Tests Passing](https://img.shields.io/badge/tests-48%2F48%20passed-brightgreen.svg)](tests/)
[![Docker Ready](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)](docker-compose.yml)

Dark Threat Radar is an autonomous, lightweight, standalone Cyber Threat Intelligence (CTI) aggregator, SOC radar, and search engine. Built on top of FastAPI and asynchronous SQLite (`aiosqlite`), it continuously ingests, correlates, and normalizes high-fidelity vulnerability intelligence, active malware telemetry, global attack traffic, ransomware extortion disclosures, credential leak checks, and asset-specific remediation guidance into a single pane of glass and high-speed REST API.

---

## Table of Contents

- [Key Features](#key-features)
- [Architecture and Data Pipeline](#architecture-and-data-pipeline)
- [Integrated Threat Intelligence Sources](#integrated-threat-intelligence-sources)
- [Global Internet Activity (Live Map)](#global-internet-activity-live-map)
- [Watchlist and Remediation Radar](#watchlist-and-remediation-radar)
- [Leak Check Credential Scanner](#leak-check-credential-scanner)
- [Quickstart with Docker Compose](#quickstart-with-docker-compose)
- [Native Linux Installation](#native-linux-installation)
- [Configuration and Environment Variables](#configuration-and-environment-variables)
- [Secure Updates](#secure-updates)
- [REST API Reference](#rest-api-reference)
- [Automated Testing Suite](#automated-testing-suite)
- [Security and Hygiene Architecture](#security-and-hygiene-architecture)
- [Resumo em Portugues](#resumo-em-portugues)
- [License](#license)

---

## Key Features

- **Provider-Aware Autonomous Ingestion:** `APScheduler` runs isolated connector groups at provider-appropriate intervals: core intelligence every 5 minutes, fast IOC feeds every 15 minutes, hourly feeds every hour, and slower enrichment every 6 hours.
- **Normalized IOC Correlation:** IPs, CIDRs, ASNs, domains, URLs, hashes, TLS certificates, JA3 fingerprints, CVEs, GHSAs, and packages are normalized, deduplicated, confidence-scored, and correlated across their contributing sources.
- **Global Internet Activity Map:** 60 FPS HTML5 Canvas vector radar featuring real cartographic coastlines (287 country polygons) with ballistic laser trajectories connecting real SANS ISC DShield scanner IPs to targeted global ports.
- **Critical Vendor Threat Spotlight:** Current visibility into high-impact vulnerabilities and actively exploited CISA KEV entries published or updated in recent weeks.
- **Asset Watchlist and Official Remediation:** Register internal vendors, operating systems, or specific CVEs to cross-reference against CISA KEV and NVD feeds, automatically delivering required mitigation directives and official patch due dates.
- **Ransomware Extortion Tracker:** Dedicated monitoring of active ransomware gang victim disclosures (LockBit, Akira, Qilin, MedusaLocker) with specialized country filtering and immediate highlighting for Brazilian targets.
- **Leak Check Credential Scanner:** Interactive validation of compromised email addresses (XposedOrNot Community DB) and passwords via the NIST SP 800-63B compliant K-Anonymity SHA-1 protocol (Have I Been Pwned / Cloudflare).
- **EPSS Scoring Correlation:** Enriches all vulnerability records with FIRST.org Exploit Prediction Scoring System (EPSS) probabilities and percentiles alongside CVSS scores.
- **Industrial SOC Aesthetic:** Sober, dense, high-contrast analyst-grade interface with side-by-side symmetrical card pairs, lateral drawer inspection, compact single-row menu, and dark theme.
- **Enterprise-Grade Versioning:** Strict Semantic Versioning (SemVer), schema migration tracking (`schema_migrations`), and an automated `pytest` validation suite.
- **Secure Update Channel:** Detects new stable GitHub releases in the dashboard. Native installations can opt into authenticated one-click updates through a privilege-separated systemd worker with backup, isolated testing, health checks, and rollback.

---

## Architecture and Data Pipeline

```
┌────────────────────────────────────────────────────────────────────────┐
│                    15 Public CTI Connectors                            │
├────────────────────────────────────────────────────────────────────────┤
│ CORE / 5m: CISA KEV, NVD, EPSS, DShield, MalwareBazaar,                │
│            ransomware.live, CTI News                                   │
│ FAST / 15m: ThreatFox, URLhaus, Feodo Tracker, SSLBL                   │
│ HOURLY: GitHub Advisories, Spamhaus DROP                               │
│ SLOW / 6h: OSV.dev, OpenPhish (optional; disabled by default)           │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ isolated connector groups
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 Normalization & Correlation Layer                      │
│ type/value normalization │ deterministic IDs │ confidence scoring     │
│ deduplication            │ multi-source links │ connector health       │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ transactional UPSERT
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                SQLite Async Storage & Migrations (WAL)                 │
│ CVEs │ malware │ DShield │ ransomware │ news │ watchlist              │
│ normalized_iocs │ ioc_sources │ connector_health │ vendor_advisories   │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ async queries
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         FastAPI Backend                                │
│ REST /api/* │ OpenAPI /docs │ Jinja2 dashboard │ admin key management │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      CTI Dashboard & Explorer                          │
│ Internet activity │ CVEs + EPSS │ IOC search │ malware │ ransomware   │
│ source health │ watchlist + remediation │ news │ credential leak check│
└────────────────────────────────────────────────────────────────────────┘
```

---

## Integrated Threat Intelligence Sources

Dark Threat Radar tracks 15 public CTI connectors. Fourteen are enabled by default; OpenPhish remains disabled until the operator explicitly accepts the provider terms for the intended deployment. ThreatFox and URLhaus report `AUTH REQUIRED` until their keys are configured.

| Feed | Source / API | Description | Ingestion Frequency |
| :--- | :--- | :--- | :--- |
| **CISA KEV** | CISA | Official Known Exploited Vulnerabilities catalog, including ransomware campaign associations. | Core: 5 min |
| **NIST NVD 2.0** | NIST | Recently published or updated CVEs with CVSS, severity, and CWE data. | Core: 5 min |
| **FIRST.org EPSS** | FIRST | Exploitation probability and percentile enrichment for stored CVEs. | After each core cycle |
| **SANS ISC DShield** | SANS Internet Storm Center | INFOCON state, global scanning sources, attacked ports, records, and target counts. | Core: 5 min |
| **MalwareBazaar** | abuse.ch | Recent malware samples, hashes, file types, signatures, and families. | Core: 5 min |
| **Ransomware.live v2** | Ransomware.live | Recent extortion disclosures with group, victim, domain, country, and discovery data. | Core: 5 min |
| **CTI News & OSINT** | Curated RSS + optional local cache | The Hacker News, BleepingComputer, SecurityWeek, CISO Advisor, and CERT.br bulletins. | Core: 5 min |
| **ThreatFox** | abuse.ch | Authenticated IOC feed for malicious IPs, domains, URLs, hashes, JA3 fingerprints, and malware families. | Fast: 15 min; key required |
| **URLhaus** | abuse.ch | Authenticated feed of recent malware-distribution URLs and their online status. | Fast: 15 min; key required |
| **Feodo Tracker** | abuse.ch | Active botnet command-and-control IPs, ports, status, and malware families. | Fast: 15 min |
| **SSLBL** | abuse.ch | Malicious TLS certificates, C2 IPs, and contextual JA3 fingerprints from recommended lists. | Fast: 15 min |
| **GitHub Advisory Database** | GitHub REST API | Global security advisories across open-source ecosystems, including GHSA and CVE aliases. | Hourly |
| **Spamhaus DROP** | Spamhaus | IPv4, IPv6, and ASN DROP intelligence normalized as CIDR and ASN indicators. | Hourly |
| **OSV.dev** | OSV API | Targeted vulnerability enrichment for packages registered in the Watchlist. | Slow: 6 hours |
| **OpenPhish** | OpenPhish | Active phishing URLs. Disabled until explicitly enabled after terms review. | Disabled by default; 6 hours when enabled |

Operational attribution, authentication, and usage notes are maintained in [SOURCES_LICENSES.md](SOURCES_LICENSES.md).

---

## Global Internet Activity (Live Map)

Dark Threat Radar includes a hardware-accelerated 60 FPS HTML5 Canvas Cyberattack Map:
- **Authentic Cartography:** Driven by `app/static/data/world_polygons.json` containing 287 real-world geographic features, accurately rendering all global coastlines and borders (Brazil, South America, North America, Europe, Asia, Africa, and Oceania).
- **Proportional Aspect Ratio:** Enforces a locked 2:1 equirectangular projection centered within the viewport, preventing distortion or stretching across any screen resolution.
- **Ballistic Laser Trajectories:** Renders quadratic bezier attack arcs with glowing particle heads and expanding ripple rings upon target impact.
- **Live Traffic Telemetry Feed:** Dedicated scrolling telemetry feed displaying source country, attacker IP, target country, destination port, and service identification.

---

## Watchlist and Remediation Radar

The Watchlist module allows SOC analysts and engineers to monitor internal technologies and appliances:
- **Target Types:** Register targets by Vendor (e.g., Citrix, Palo Alto), Product/OS (e.g., PAN-OS, NetScaler, Linux Kernel), or Specific CVE (e.g., CVE-2026-88772).
- **Automated Correlation:** Real-time cross-referencing against ingested CISA KEV and NVD records.
- **Remediation Directives:** Surfaces official required actions (ACTION REQUIRED), mitigation deadlines (DUE DATE), severity classifications, and direct links to patch advisories.

---

## Leak Check Credential Scanner

Dark Threat Radar incorporates an interactive verification module (`/api/leak-check/*`):
- **Email Breach Scanner:** Checks target emails against the XposedOrNot Community Breach Intelligence database, returning compromised services, breach years, and compromised data classes.
- **K-Anonymity Password Scanner:** Implements the Troy Hunt / Cloudflare K-Anonymity protocol. Only the first 5 characters of the password's SHA-1 hash are queried against the 850M+ compromised passwords dataset. The password itself never leaves local memory.

---

## Quickstart with Docker Compose

Ensure Docker and Docker Compose are installed:

```bash
# Clone the repository
git clone https://github.com/fr3dux/dark-threat-radar.git
cd dark-threat-radar

# Generate this installation's unique admin access code
python3 scripts/setup_admin.py

# Build and launch in detached mode
docker compose up -d

# Verify logs
docker compose logs -f
```

Open your browser at `http://localhost:9220` (or your server's IP).

---

## Native Linux Installation

### 1. Requirements and Setup
```bash
sudo apt update && sudo apt install -y python3 python3-venv git

git clone https://github.com/fr3dux/dark-threat-radar.git
cd dark-threat-radar

python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

# Generate this installation's unique admin access code
./venv/bin/python scripts/setup_admin.py
```

### 2. Run Standalone
```bash
./run.sh
```

### 3. Production Systemd Service
The following is an example unit for `/etc/systemd/system/threat-radar.service`; adjust the user and installation path for your server:

```ini
[Unit]
Description=Dark Threat Radar CTI Engine & Analyst Dashboard
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/dark-threat-radar
EnvironmentFile=-/opt/dark-threat-radar/.env
ExecStart=/opt/dark-threat-radar/run.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now threat-radar.service
sudo systemctl status threat-radar.service
```

### 4. Optional One-Click Updater

After the native service is working, install the root-owned update worker once:

```bash
sudo /opt/dark-threat-radar/venv/bin/python /opt/dark-threat-radar/scripts/install_systemd_updater.py \
  --project-root /opt/dark-threat-radar \
  --service threat-radar.service
```

The installer copies the worker to a root-owned system location and runs it with the system Python interpreter, outside the application environment. The web application never receives permission to execute arbitrary commands; it can only create a validated request for the fixed external updater. Adjust `/opt/dark-threat-radar` if the repository is installed elsewhere.

---

## Configuration and Environment Variables

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `HOST` | `0.0.0.0` | Network binding interface. |
| `PORT` | `9220` | Listening HTTP port. |
| `SYNC_INTERVAL_SECONDS` | `300` | Core connector interval: CISA, NVD, EPSS, DShield, MalwareBazaar, ransomware.live, and news. |
| `CTI_FAST_INTERVAL_SECONDS` | `900` (minimum 900) | ThreatFox, URLhaus, Feodo Tracker, and SSLBL interval. |
| `CTI_HOURLY_INTERVAL_SECONDS` | `3600` (minimum 3600) | GitHub Advisories and Spamhaus DROP interval. |
| `CTI_SLOW_INTERVAL_SECONDS` | `21600` (minimum 21600) | OSV.dev and, when enabled, OpenPhish interval. |
| `BASE_DIR` | `/opt/dark-threat-radar` (or repo root) | Absolute root directory of the application. |
| `DB_PATH` | `./threat_radar.db` | Path to the SQLite database file. |
| `LOCAL_NEWS_FILE` | `./news_history.json` | Path to optional local OSINT/news JSON cache. |
| `MB_API_KEY` | `""` | Optional Abuse.ch MalwareBazaar Auth Key. |
| `NVD_API_KEY` | `""` | Optional NIST NVD 2.0 API Key for higher rate limits. |
| `THREATFOX_AUTH_KEY` | `""` | Initial ThreatFox Auth-Key; can also be managed securely from the web panel. |
| `URLHAUS_AUTH_KEY` | `""` | Initial URLhaus Auth-Key; can also be managed securely from the web panel. |
| `SETTINGS_ADMIN_TOKEN` | Generated during setup | Unique per-installation administrative access code for web-based secret management. |
| `UPDATE_REPOSITORY` | `fr3dux/dark-threat-radar` | Fixed GitHub repository used for stable release discovery. |
| `UPDATE_CHECK_INTERVAL_SECONDS` | `21600` (minimum 300) | Cached interval for checking the stable release channel. |
| `ENABLE_WEB_UPDATES` | `false` | Enabled by the native updater installer after its root-owned worker is ready. |
| `UPDATE_REQUEST_PATH` | `/var/lib/dark-threat-radar/update.request.json` | Privilege-separated update request watched by systemd. |
| `UPDATE_STATUS_PATH` | `/var/lib/dark-threat-radar/update-status.json` | Non-secret update progress and result file. |
| `GITHUB_TOKEN` | `""` | Optional token that raises GitHub Advisory API rate limits. |
| `ENABLE_OPENPHISH` | `false` | Enables OpenPhish only after the operator confirms applicable provider terms. |
| `OPENPHISH_API_KEY` | `""` | Optional OpenPhish plan credential. |
| `RUNTIME_SECRETS_PATH` | `./.runtime-secrets.json` | Owner-only runtime credential store, excluded from Git. |

### Administrative access code

Run `python3 scripts/setup_admin.py` once after cloning. The command creates `.env` with owner-only permissions, generates a cryptographically random code, and displays it once so it can be saved in a password manager. Neither `.env` nor the runtime API key store is committed to Git, so every clone receives a different code.

If the code is lost, the server owner can replace `SETTINGS_ADMIN_TOKEN` in `.env` with a new long random value and restart the application. Existing ThreatFox and URLhaus keys remain in the local runtime secret store. Docker installations persist that store in the `threat-radar-data` volume.

---

## Secure Updates

The dashboard checks the official stable release channel every six hours and displays `UPDATE AVAILABLE` only when a higher semantic version exists. Release discovery is read-only and works for native and Docker installations.

On native systemd installations where the optional updater is installed, the administrator can review the version and release notes, enter the administrative access code, and select `INSTALL UPDATE`. The external worker then:

1. Validates the fixed Git origin, stable annotated tag, clean `main` branch, and forward-only commit ancestry.
2. Creates an isolated Git worktree and fresh Python environment.
3. Runs the complete test suite and JavaScript syntax validation before downtime.
4. Creates an online SQLite backup and a local rollback branch.
5. Activates the release, restarts the service, and verifies `/api/version`.
6. Restores the previous commit, environment, and database automatically if the health check fails.

Docker installations intentionally receive update notifications only. A container must not control the host Docker daemon; update it from the host with `git pull` followed by `docker compose up -d --build`. Persistent data remains in the `threat-radar-data` volume.

---

## REST API Reference

Interactive documentation with live OpenAPI testing is available at `/docs` (Swagger UI) and `/redoc`.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/version` | Returns centralized SemVer version and system metadata. |
| `GET` | `/api/update/status` | Checks the official stable channel and returns sanitized update state. |
| `GET` | `/api/status` | Ingestion health, per-feed synchronization timestamps, and counts. |
| `GET` | `/api/connectors` | Operational state and counters for all 15 configured connectors. |
| `GET` | `/api/stats` | Aggregated dashboard statistics (CVSS distribution, vendors, malware, ransomware). |
| `GET` | `/api/iocs` | Search normalized IOCs by value, type, source, and active state. |
| `GET` | `/api/cves` | Query CVEs with filters (`q`, `severity`, `source`, `has_ransomware`, `limit`, `offset`). |
| `GET` | `/api/malware` | Query malware samples (`q`, `file_type`, `signature`, `limit`, `offset`). |
| `GET` | `/api/dshield` | SANS DShield telemetry (INFOCON, top attacking IPs, top scanned ports). |
| `GET` | `/api/ransomware` | Ransomware victim disclosures (`q`, `group`, `country`, `limit`, `offset`). |
| `GET` | `/api/attacks/live` | Real-time cyberattack trajectories with geographic coordinates for map rendering. |
| `GET` | `/api/watchlist` | Retrieve registered watchlist targets and cross-referenced KEV/NVD alerts. |
| `POST`| `/api/watchlist` | Add a new target (`vendor`, `product`, or `cve`) to the infrastructure watchlist. |
| `DELETE`| `/api/watchlist/{id}` | Remove a target from the infrastructure watchlist. |
| `POST`| `/api/leak-check/email` | Validate email exposure in known global data breaches (XposedOrNot). |
| `POST`| `/api/leak-check/password` | Validate password exposure via K-Anonymity SHA-1 range (Have I Been Pwned). |
| `GET` | `/api/news` | Security bulletins and news feeds with search and pagination. |
| `GET` | `/api/artifact/{type}/{id}` | Deep inspection details for CVE, malware hash, port, IP, or ransomware claim. |
| `POST`| `/api/sync` | Manually triggers immediate synchronization of all background feeds. |
| `GET` | `/api/admin/integrations` | Returns ThreatFox/URLhaus configuration and validation state; requires `X-Admin-Token`. |
| `PUT` | `/api/admin/integrations/{provider}` | Stores and validates a ThreatFox or URLhaus key without returning the secret. |
| `DELETE` | `/api/admin/integrations/{provider}` | Removes a managed key and returns the connector to `AUTH REQUIRED`. |
| `POST` | `/api/admin/update` | Authenticates and queues the latest validated stable release for the external updater. |

---

## Automated Testing Suite

Dark Threat Radar includes a `pytest` regression suite for critical API endpoints, migrations, connector parsing, IOC normalization, secret administration, and installation onboarding:

```bash
# Execute test suite
./venv/bin/pytest -v tests/
```

Test coverage includes:
- Semantic version injection verification (`test_api_version`, `test_index_page_version_injection`)
- All primary API query endpoints (`/api/stats`, `/api/cves`, `/api/malware`, `/api/dshield`, `/api/ransomware`, `/api/attacks/live`)
- Connector status, normalized IOC search, and ThreatFox/URLhaus administrative flows
- Provider parsers and failure isolation for the expanded connector set
- IOC normalization, deterministic IDs, confidence scoring, and multi-source correlation
- Watchlist CRUD & correlation logic (`test_api_watchlist_crud`)
- Leak check endpoints (`test_leak_check_password`, `test_leak_check_email`)
- Input validation and 404/400 exception boundaries (`test_artifact_cve_not_found`, `test_artifact_invalid_type`)
- Schema migration registration through the normalized IOC and connector-health schema (`1.8.1`)
- Per-installation administrator code generation and file-permission checks
- Stable release discovery, authenticated update requests, and semantic-version validation

---

## Security and Hygiene Architecture

- **Zero Secrets Tracked:** Git history contains no API tokens, private keys, or passwords.
- **Database & Cache Isolation:** Database (`*.db`, `*.db-wal`), virtual environments (`venv/`), bytecode caches (`__pycache__/`), and logs are strictly ignored by `.gitignore`.
- **Per-Installation Administration:** The setup utility generates a unique administrator code locally; no shared or default administrator credential exists in the repository.
- **Restricted Secret Files:** `.env` and the runtime API key store use owner-only permissions and are excluded from Git.
- **Non-Root Docker Execution:** Docker container runs under an unprivileged `threatradar` user (UID 10001).

---

## Resumo em Portugues

O Dark Threat Radar é uma plataforma autônoma e leve de inteligência de ameaças cibernéticas (CTI) e apoio a SOC. Desenvolvido em FastAPI com SQLite assíncrono, o sistema acompanha 15 conectores públicos em quatro grupos de agendamento:

1. **Núcleo de vulnerabilidades e telemetria (5 min):** CISA KEV, NIST NVD, FIRST EPSS, SANS ISC DShield, MalwareBazaar, ransomware.live e notícias CTI.
2. **IOCs rápidos (15 min):** ThreatFox, URLhaus, Feodo Tracker e SSLBL. ThreatFox e URLhaus exigem Auth-Key e podem ser configurados pelo painel administrativo.
3. **Inteligência horária:** GitHub Advisory Database e Spamhaus DROP.
4. **Enriquecimento lento (6 h):** OSV.dev e OpenPhish, sendo que o OpenPhish permanece desativado por padrão.

Os indicadores são normalizados, deduplicados, pontuados por confiança e correlacionados entre fontes. O painel oferece mapa de atividade global, pesquisa de CVEs e IOCs, telemetria DShield, malware, ransomware, notícias, Watchlist com remediação e verificação de credenciais expostas.

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.
