# Dark Threat Radar

[![Version](https://img.shields.io/badge/version-1.8.3-blue.svg)](app/version.py)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Threat Intelligence](https://img.shields.io/badge/CTI-Autonomous%20Engine-red.svg)](https://github.com/fr3dux/dark-threat-radar)
[![Tests Passing](https://img.shields.io/badge/tests-23%2F23%20passed-brightgreen.svg)](tests/)
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
- [REST API Reference](#rest-api-reference)
- [Automated Testing Suite](#automated-testing-suite)
- [Security and Hygiene Architecture](#security-and-hygiene-architecture)
- [Resumo em Portugues](#resumo-em-portugues)
- [License](#license)

---

## Key Features

- **Autonomous 5-Minute Ingestion:** Background scheduler (`APScheduler`) continuously synchronizes feeds every 5 minutes (`SYNC_INTERVAL_SECONDS = 300`) without blocking the main event loop or requiring manual user interaction.
- **Global Internet Activity Map:** 60 FPS HTML5 Canvas vector radar featuring real cartographic coastlines (287 country polygons) with ballistic laser trajectories connecting real SANS ISC DShield scanner IPs to targeted global ports.
- **Critical Vendor Threat Spotlight:** Real-time visibility into high-impact zero-days and active KEV exploits published in recent weeks (e.g., Citrix NetScaler `CVE-2026-88771`/`CVE-2026-88772`, Microsoft SharePoint `CVE-2026-65660`, MikroTik RouterOS `CVE-2026-67279`, Apple Multiple Products `CVE-2026-86950`).
- **Asset Watchlist and Official Remediation:** Register internal vendors, operating systems, or specific CVEs to cross-reference against CISA KEV and NVD feeds, automatically delivering required mitigation directives and official patch due dates.
- **Ransomware Extortion Tracker:** Dedicated monitoring of active ransomware gang victim disclosures (LockBit, Akira, Qilin, MedusaLocker) with specialized country filtering and immediate highlighting for Brazilian targets.
- **Leak Check Credential Scanner:** Interactive validation of compromised email addresses (XposedOrNot Community DB) and passwords via the NIST SP 800-63B compliant K-Anonymity SHA-1 protocol (Have I Been Pwned / Cloudflare).
- **EPSS Scoring Correlation:** Enriches all vulnerability records with FIRST.org Exploit Prediction Scoring System (EPSS) probabilities and percentiles alongside CVSS scores.
- **Industrial SOC Aesthetic:** Sober, dense, high-contrast analyst-grade interface with side-by-side symmetrical card pairs, lateral drawer inspection, compact single-row menu, and dark theme.
- **Enterprise-Grade Versioning:** Strict Semantic Versioning (SemVer), schema migration tracking (`schema_migrations`), and automated `pytest` validation suite (23/23 tests passing).

---

## Architecture and Data Pipeline

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Threat Intelligence Sources (Every 5m)               │
├───────────────┬───────────────┬────────────────┬───────────────────────┤
│ CISA KEV      │ NIST NVD 2.0  │ FIRST.org EPSS │ SANS ISC DShield      │
│ MalwareBazaar │ Ransomware.live│ CTI RSS Feeds  │ Local News / OSINT    │
└───────┬───────┴───────┬───────┴────────┬───────┴───────────┬───────────┘
        │               │                │                   │
        └───────────────┼────────────────┼───────────────────┘
                        ▼                ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     Autonomous Ingestion Workers                       │
│  - cisa_kev.py       - nvd_cve.py       - epss.py                      │
│  - dshield.py        - malware_bazaar.py- ransomware_live.py           │
│  - news_feed.py      - scheduler.py                                    │
└───────────────────────┬────────────────────────────────────────────────┘
                        │ Normalized UPSERT
                        ▼
┌────────────────────────────────────────────────────────────────────────┐
│               Embedded Asynchronous Storage & Migrations               │
│                   threat_radar.db (aiosqlite / WAL)                    │
│   cve_records │ malware_samples │ dshield_* │ ransomware_victims       │
│   cti_news    │ watchlist       │ ingestion_status│ schema_migrations  │
└───────────────────────┬────────────────────────────────────────────────┘
                        │ Fast Async Queries
                        ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      FastAPI Application Backend                       │
│    REST API (/api/*)  │  Swagger/OpenAPI (/docs)  │  Jinja2 Templates │
└───────────────────────┬────────────────────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     Analyst Dashboard & Explorer                       │
│  - 60 FPS Internet Activity - Critical Vendor Zero-Day Spotlight       │
│  - CVE Explorer & EPSS      - Ransomware Tracker (BR Filter)           │
│  - Malware Hash Feed        - SANS DShield Network Telemetry           │
│  - Watchlist & Remediation  - Leak Check Scanner                       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Integrated Threat Intelligence Sources

Dark Threat Radar ingests and cross-references data from 7 primary intelligence feeds:

| Feed | Source / API | Description | Ingestion Frequency |
| :--- | :--- | :--- | :--- |
| **CISA KEV** | Cybersecurity & Infrastructure Security Agency | Official catalog of Known Exploited Vulnerabilities in the wild, including ransomware campaign associations. | Every 5 minutes |
| **NIST NVD 2.0** | National Vulnerability Database | Vulnerabilities published or updated in the last 7 days with CVSS v3.1/v2 scores, severity ratings, and CWE mappings. | Every 5 minutes |
| **FIRST.org EPSS** | Exploit Prediction Scoring System | Machine-learning probability score (0.0% to 100%) and global percentile for likelihood of exploitation within 30 days. | Continuous batching |
| **SANS ISC DShield** | Internet Storm Center Distributed Sensors | Global honeypot telemetry tracking top scanning IP addresses, attacked ports, target counts, and INFOCON threat level. | Every 5 minutes |
| **MalwareBazaar** | abuse.ch | Freshly analyzed malware samples, SHA256/MD5 hashes, delivery file types, and signature classifications (Mirai, Vidar, etc.). | Every 5 minutes |
| **Ransomware.live v2** | Ransomware.live API | Real-time disclosures of corporate ransomware victims, threat actor attribution (Akira, Qilin, LockBit), domains, and country tags. | Every 5 minutes |
| **CTI News & OSINT** | RSS Feeds & Local Scrapers | Security bulletins from The Hacker News, BleepingComputer, Dark Reading, CERT.br, CSIRT-DF, and DarkWebInformer. | Every 5 minutes |

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

# Copy environment variables template
cp .env.example .env

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
```

### 2. Run Standalone
```bash
./run.sh
```

### 3. Production Systemd Service
The repository includes a production unit configured at `/etc/systemd/system/threat-radar.service`:

```ini
[Unit]
Description=Dark Threat Radar CTI Engine & Analyst Dashboard
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/dark-threat-radar
ExecStart=/opt/dark-threat-radar/run.sh
Restart=always
RestartSec=5
Environment=PORT=9220
Environment=HOST=0.0.0.0
Environment=SYNC_INTERVAL_SECONDS=300

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now threat-radar.service
sudo systemctl status threat-radar.service
```

---

## Configuration and Environment Variables

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `HOST` | `0.0.0.0` | Network binding interface. |
| `PORT` | `9220` | Listening HTTP port. |
| `SYNC_INTERVAL_SECONDS` | `300` | Background ingestion interval in seconds (default: 5 minutes). |
| `BASE_DIR` | `/opt/dark-threat-radar` (or repo root) | Absolute root directory of the application. |
| `DB_PATH` | `./threat_radar.db` | Path to the SQLite database file. |
| `LOCAL_NEWS_FILE` | `./news_history.json` | Path to optional local OSINT/news JSON cache. |
| `MB_API_KEY` | `""` | Optional Abuse.ch MalwareBazaar Auth Key. |
| `NVD_API_KEY` | `""` | Optional NIST NVD 2.0 API Key for higher rate limits. |

---

## REST API Reference

Interactive documentation with live OpenAPI testing is available at `/docs` (Swagger UI) and `/redoc`.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/version` | Returns centralized SemVer version and system metadata. |
| `GET` | `/api/status` | Ingestion health, per-feed synchronization timestamps, and counts. |
| `GET` | `/api/stats` | Aggregated dashboard statistics (CVSS distribution, vendors, malware, ransomware). |
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

---

## Automated Testing Suite

Dark Threat Radar enforces 100% test coverage over critical API endpoints, schema migrations, and rendering contracts using `pytest`:

```bash
# Execute test suite
./venv/bin/pytest -v tests/
```

Test coverage includes:
- Semantic version injection verification (`test_api_version`, `test_index_page_version_injection`)
- All primary API query endpoints (`/api/stats`, `/api/cves`, `/api/malware`, `/api/dshield`, `/api/ransomware`, `/api/attacks/live`)
- Watchlist CRUD & correlation logic (`test_api_watchlist_crud`)
- Leak check endpoints (`test_leak_check_password`, `test_leak_check_email`)
- Input validation and 404/400 exception boundaries (`test_artifact_cve_not_found`, `test_artifact_invalid_type`)
- Schema migration idempotency across versions 1.0.0 through 1.7.0 (`test_database_schema_migrations`)

---

## Security and Hygiene Architecture

- **Zero Secrets Tracked:** Git history contains no API tokens, private keys, or passwords.
- **Database & Cache Isolation:** Database (`*.db`, `*.db-wal`), virtual environments (`venv/`), bytecode caches (`__pycache__/`), and logs are strictly ignored by `.gitignore`.
- **Non-Root Docker Execution:** Docker container runs under an unprivileged `appuser` (UID 10001).

---

## Resumo em Portugues

O Dark Threat Radar e uma plataforma autonoma e leve de inteligencia contra ameacas ciberneticas (CTI) e radar para SOC. Desenvolvido em Python (FastAPI) com banco de dados embutido SQLite assincrono, ele agrega e correlaciona continuamente:
1. **CISA KEV:** Vulnerabilidades exploradas ativamente no mundo real e campanhas de ransomware.
2. **NIST NVD 2.0:** Ultimas CVEs dos ultimos 7 dias e todas as falhas com severidade Critica.
3. **EPSS (FIRST.org):** Probabilidade matematica de exploracao ativa em 30 dias para cada CVE.
4. **SANS DShield:** Sensores globais, IPs atacantes, portas mais visadas e status INFOCON.
5. **MalwareBazaar:** Amostras de malware recentes, familias ativas e hashes SHA256/MD5.
6. **Ransomware.live:** Vitimas recentes de extorsao por ransomware com filtro e destaque especial para alvos no Brasil.
7. **Global Internet Activity (60 FPS):** Mapa-mundi cartografico real com feixes luminosos balisticos e telemetria de tráfego ao vivo.
8. **Watchlist & Remediacao:** Monitoramento de ativos especificos da infraestrutura com diretivas oficiais de correcao e prazos do CISA KEV.
9. **Leak Check:** Verificacao de credenciais vazadas (e-mails via XposedOrNot e senhas via Have I Been Pwned com modelo seguro K-Anonymity).

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.
