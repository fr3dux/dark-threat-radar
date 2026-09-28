# 🛡️ ThreatRadar

[![Version](https://img.shields.io/badge/version-1.5.5-blue.svg)](app/version.py)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Threat Intelligence](https://img.shields.io/badge/CTI-Autonomous%20Engine-red.svg)](https://github.com/fr3dux/threat-radar)
[![Tests Passing](https://img.shields.io/badge/tests-18%2F18%20passed-brightgreen.svg)](tests/)
[![Docker Ready](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)](docker-compose.yml)

**ThreatRadar** is an autonomous, lightweight, standalone Cyber Threat Intelligence (CTI) aggregator, SOC radar, and search engine. Built on top of FastAPI and asynchronous SQLite (`aiosqlite`), it continuously ingests, correlates, and normalizes high-fidelity vulnerability intelligence, active malware telemetry, global attack traffic, ransomware extortion disclosures, and security advisories into a single pane of glass and high-speed REST API.

---

## 📑 Table of Contents

- [Key Features](#-key-features)
- [Architecture and Data Pipeline](#-architecture-and-data-pipeline)
- [Integrated Threat Intelligence Sources](#-integrated-threat-intelligence-sources)
- [Global Live Cyberattack Map](#-global-live-cyberattack-map)
- [Quickstart with Docker Compose](#-quickstart-with-docker-compose)
- [Native Linux Installation](#-native-linux-installation)
- [Configuration and Environment Variables](#-configuration-and-environment-variables)
- [REST API Reference](#-rest-api-reference)
- [Automated Testing Suite](#-automated-testing-suite)
- [Security and Hygiene Architecture](#-security-and-hygiene-architecture)
- [Resumo em Portugues](#-resumo-em-portugues)
- [License](#-license)

---

## 🚀 Key Features

- **Autonomous 5-Minute Ingestion:** Background scheduler (`APScheduler`) continuously synchronizes feeds every 5 minutes (`SYNC_INTERVAL_SECONDS = 300`) without blocking the main event loop or requiring manual user interaction.
- **Global Live Cyberattack Map:** 60 FPS HTML5 Canvas vector radar featuring real cartographic coastlines (287 country polygons) with ballistic laser trajectories connecting real SANS ISC DShield scanner IPs to targeted global ports.
- **Critical Vendor Threat Spotlight:** Real-time visibility into high-impact zero-days and active KEV exploits published in recent weeks (e.g., Citrix NetScaler `CVE-2026-88771`/`CVE-2026-88772`, Microsoft SharePoint `CVE-2026-65660`, MikroTik RouterOS `CVE-2026-67279`).
- **Ransomware Extortion Tracker:** Dedicated monitoring of active ransomware gang victim disclosures (LockBit, Akira, Qilin, MedusaLocker) with specialized country filtering and immediate highlighting for Brazilian targets.
- **EPSS Scoring Correlation:** Enriches all vulnerability records with FIRST.org Exploit Prediction Scoring System (EPSS) probabilities and percentiles alongside CVSS scores.
- **Industrial SOC Aesthetic:** Sober, dense, high-contrast analyst-grade interface with side-by-side symmetrical card pairs, lateral drawer inspection, and dark theme.
- **Enterprise-Grade Versioning:** Strict Semantic Versioning (SemVer), schema migration tracking (`schema_migrations`), and automated `pytest` validation suite.

---

## 🏛️ Architecture and Data Pipeline

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
│   cti_news    │ ingestion_status│ schema_migrations                    │
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
│  - 60 FPS Live Attack Map   - Critical Vendor Zero-Day Spotlight       │
│  - CVE Explorer & EPSS      - Ransomware Tracker (BR Filter)           │
│  - Malware Hash Feed        - SANS DShield Network Telemetry           │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🌐 Integrated Threat Intelligence Sources

ThreatRadar ingests and cross-references data from **7 primary intelligence feeds**:

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

## 🗺️ Global Live Cyberattack Map

ThreatRadar includes a hardware-accelerated **60 FPS HTML5 Canvas Cyberattack Map**:
- **Authentic Cartography:** Driven by `app/static/data/world_polygons.json` containing **287 real-world geographic features**, accurately rendering all global coastlines and borders (Brazil, South America, North America, Europe, Asia, Africa, and Oceania).
- **Proportional Aspect Ratio:** Enforces a locked 2:1 equirectangular projection centered within the viewport, preventing distortion or stretching across any screen resolution.
- **Ballistic Laser Trajectories:** Renders quadratic bezier attack arcs with glowing particle heads and expanding ripple rings upon target impact.
- **Real-Time Attack Stream:** Dedicated scrolling telemetry feed displaying source country, attacker IP, target country, destination port, and service identification.

---

## ⚡ Quickstart with Docker Compose

Ensure Docker and Docker Compose are installed:

```bash
# Clone the repository
git clone https://github.com/fr3dux/threat-radar.git
cd threat-radar

# Copy environment variables template
cp .env.example .env

# Build and launch in detached mode
docker compose up -d

# Verify logs
docker compose logs -f
```

Open your browser at **`http://localhost:9220`** (or your server's IP).

---

## 🐧 Native Linux Installation

### 1. Requirements and Setup
```bash
sudo apt update && sudo apt install -y python3 python3-venv git

git clone https://github.com/fr3dux/threat-radar.git /root/threat-radar
cd /root/threat-radar

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
Description=ThreatRadar CTI Engine & Analyst Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/threat-radar
ExecStart=/root/threat-radar/run.sh
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

## ⚙️ Configuration and Environment Variables

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `HOST` | `0.0.0.0` | Network binding interface. |
| `PORT` | `9220` | Listening HTTP port. |
| `SYNC_INTERVAL_SECONDS` | `300` | Background ingestion interval in seconds (default: 5 minutes). |
| `BASE_DIR` | `/root/threat-radar` | Absolute root directory of the application. |
| `DB_PATH` | `/root/threat-radar/threat_radar.db` | Path to the SQLite database file. |
| `LOCAL_NEWS_FILE` | `/root/news_history.json` | Path to optional local OSINT/news JSON cache. |
| `MB_API_KEY` | `""` | Optional Abuse.ch MalwareBazaar Auth Key. |
| `NVD_API_KEY` | `""` | Optional NIST NVD 2.0 API Key for higher rate limits. |

---

## 🔌 REST API Reference

Interactive documentation with live OpenAPI testing is available at **`/docs`** (Swagger UI) and **`/redoc`**.

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
| `GET` | `/api/news` | Security bulletins and news feeds with search and pagination. |
| `GET` | `/api/artifact/{type}/{id}` | Deep inspection details for CVE, malware hash, port, IP, or ransomware claim. |
| `POST`| `/api/sync` | Manually triggers immediate synchronization of all background feeds. |

---

## 🧪 Automated Testing Suite

ThreatRadar enforces 100% test coverage over critical API endpoints, schema migrations, and rendering contracts using `pytest`:

```bash
# Execute test suite
./venv/bin/pytest -v tests/
```

Test coverage includes:
- Semantic version injection verification (`test_api_version`, `test_index_page_version_injection`)
- All primary API query endpoints (`/api/stats`, `/api/cves`, `/api/malware`, `/api/dshield`, `/api/ransomware`, `/api/attacks/live`)
- Input validation and 404/400 exception boundaries (`test_artifact_cve_not_found`, `test_artifact_invalid_type`)
- Schema migration idempotency across versions 1.0.0 through 1.5.0 (`test_database_schema_migrations`)

---

## 🔒 Security and Hygiene Architecture

- **Private Repository:** Kept strictly private on GitHub (`fr3dux/threat-radar`).
- **Zero Secrets Tracked:** Git history contains no API tokens, private keys, or passwords.
- **Database & Cache Isolation:** Database (`*.db`, `*.db-wal`), virtual environments (`venv/`), bytecode caches (`__pycache__/`), and logs are strictly ignored by `.gitignore`.
- **Non-Root Docker Execution:** Docker container runs under an unprivileged `appuser` (UID 10001).

---

## 🇧🇷 Resumo em Portugues

O **ThreatRadar** e uma plataforma autonoma e leve de inteligencia contra ameacas ciberneticas (CTI) e radar para SOC. Desenvolvido em Python (FastAPI) com banco de dados embutido SQLite assincrono, ele agrega e correlaciona continuamente:
1. **CISA KEV:** Vulnerabilidades exploradas ativamente no mundo real e campanhas de ransomware.
2. **NIST NVD 2.0:** Ultimas CVEs dos ultimos 7 dias e todas as falhas com severidade Critica.
3. **EPSS (FIRST.org):** Probabilidade matematica de exploracao ativa em 30 dias para cada CVE.
4. **SANS DShield:** Sensores globais, IPs atacantes, portas mais visadas e status INFOCON.
5. **MalwareBazaar:** Amostras de malware recentes, familias ativas e hashes SHA256/MD5.
6. **Ransomware.live:** Vitimas recentes de extorsao por ransomware com filtro e destaque especial para alvos no Brasil.
7. **Mapa de Ataques 60 FPS:** Mapa-mundi cartografico real com feixes luminosos balisticos e stream ao vivo de conexoes maliciosas.

---

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.
