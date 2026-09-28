# 🛡️ ThreatRadar

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Threat Intelligence](https://img.shields.io/badge/CTI-Autonomous%20Engine-red.svg)](https://github.com)
[![Docker Ready](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)](docker-compose.yml)

**ThreatRadar** is an autonomous, lightweight, standalone Cyber Threat Intelligence (CTI) aggregator, SOC radar, and search engine. Built on top of FastAPI and asynchronous SQLite (`aiosqlite`), it continuously ingests, correlates, and normalizes high-fidelity vulnerability intelligence, active malware telemetry, global attack traffic, and security advisories into a single pane of glass and high-speed REST API.

---

## 📑 Table of Contents

- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Integrated Threat Intelligence Sources](#-integrated-threat-intelligence-sources)
- [Quickstart with Docker Compose (1 Minute)](#-quickstart-with-docker-compose-1-minute)
- [Native Linux Installation (venv + Systemd)](#-native-linux-installation-venv--systemd)
- [Configuration & Environment Variables](#-configuration--environment-variables)
- [REST API Reference](#-rest-api-reference)
- [Artifact Deep-Dive](#-artifact-deep-dive)
- [Roadmap & Contributing](#-roadmap--contributing)
- [Resumo em Português](#-resumo-em-português)
- [License](#-license)

---

## 🚀 Key Features

- **Autonomous Periodic Ingestion:** Background scheduler (`APScheduler`) continuously synchronizes feeds without blocking the main event loop.
- **Zero-Heavyweight Footprint:** Operates on an embedded asynchronous SQLite database. No external database server (PostgreSQL/MySQL/Redis) required.
- **Single Pane of Glass Web UI:** Fast, reactive, responsive interface featuring instant keyword search, source filtering, and detailed artifact inspection modals.
- **Security-First REST API:** Query CVEs, malware hashes, attack telemetry, and threat bulletins with pagination, severity scoring, and full-text matching.
- **Production & Container Ready:** Non-root Docker container, Docker Compose setup, and production Systemd unit template included.

---

## 🏛️ Architecture

```
                                  ┌───────────────────────────────┐
                                  │   Threat Intelligence Feeds   │
                                  ├───────────────┬───────────────┤
                                  │ CISA KEV      │ NIST NVD      │
                                  │ MalwareBazaar │ SANS DShield  │
                                  │ CTI RSS Feeds │               │
                                  └───────┬───────┴───────┬───────┘
                                          │               │
                                   Periodic Ingestion (APScheduler)
                                          │               │
                                          ▼               ▼
┌────────────────────────────────────────────────────────────────────────┐
│                          ThreatRadar Core                              │
│                                                                        │
│  ┌───────────────────────┐            ┌─────────────────────────────┐  │
│  │   aiosqlite Engine    │ ◄────────► │   FastAPI Backend (Async)   │  │
│  │  (threat_radar.db)    │            └──────────────┬──────────────┘  │
│  └───────────────────────┘                           │                 │
└──────────────────────────────────────────────────────┼─────────────────┘
                                                       │
                           ┌───────────────────────────┴───────────────────────────┐
                           ▼                                                       ▼
                ┌──────────────────────┐                               ┌──────────────────────┐
                │   Web Dashboard      │                               │    REST API (JSON)   │
                │  (Port 9220 / HTML)  │                               │    (/api/* Endpoints)│
                └──────────────────────┘                               └──────────────────────┘
```

---

## 📡 Integrated Threat Intelligence Sources

| Source | Category | Extracted Data | Update Interval |
|---|---|---|---|
| **CISA KEV** | Exploited CVEs | Known Exploited Vulnerabilities catalog, ransomware campaign linkages, remediation deadlines | Hourly / Configurable |
| **NIST NVD** | Vulnerability DB | CVE IDs, CVSS v3.1/v2 metrics, CWE weaknesses, affected configurations | Hourly (API Key optional) |
| **SANS ISC DShield** | Network Telemetry | Global Infocon status, Top 50 attacking IP sources, Top attacked ports | Hourly / Dynamic |
| **Abuse.ch MalwareBazaar** | Malware Analysis | Recent malware samples, SHA-256 / MD5 hashes, signatures, file types, tags | Hourly / Dynamic |
| **CTI Advisories & Feeds** | Security News | BleepingComputer, The Hacker News, Dark Reading, KrebsOnSecurity, SecurityWeek | Hourly / Dynamic |

---

## ⚡ Quickstart with Docker Compose (1 Minute)

The fastest and most reliable way to spin up ThreatRadar is using Docker Compose:

```bash
# 1. Clone the repository
git clone https://github.com/your-org/threat-radar.git
cd threat-radar

# 2. Copy the sample environment file
cp .env.example .env

# 3. Start ThreatRadar in background mode
docker compose up -d

# 4. View logs to verify startup
docker compose logs -f
```

The ThreatRadar dashboard will be available at:
👉 **http://localhost:9220**

---

## 🐧 Native Linux Installation (venv + Systemd)

For standalone bare-metal or Linux virtual machines (Debian/Ubuntu/RHEL):

### 1. Prerequisites & Virtual Environment

```bash
# Update and install Python 3.11+ and venv
sudo apt-get update && sudo apt-get install -y python3 python3-venv git

# Clone and navigate
git clone https://github.com/your-org/threat-radar.git /opt/threat-radar
cd /opt/threat-radar

# Create virtualenv and install dependencies
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
chmod 600 .env
```

### 3. Setup Systemd Service

Create `/etc/systemd/system/threat-radar.service`:

```ini
[Unit]
Description=ThreatRadar Cyber Threat Intelligence Engine
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/threat-radar
EnvironmentFile=/opt/threat-radar/.env
ExecStart=/opt/threat-radar/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 9220
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable threat-radar
sudo systemctl start threat-radar
sudo systemctl status threat-radar
```

---

## ⚙️ Configuration & Environment Variables

Variables can be defined in `.env` or passed through the container runtime:

| Variable | Default | Description |
|---|---|---|
| `HOST` | `0.0.0.0` | Host interface to bind the web server |
| `PORT` | `9220` | Port on which the application listens |
| `SYNC_INTERVAL_SECONDS` | `3600` | Frequency in seconds of the automated feed synchronization cycle |
| `NVD_API_KEY` | *(None)* | Optional NIST NVD API key to raise rate limits (from 5 to 50 req/30s) |
| `MB_API_KEY` | *(None)* | Optional Abuse.ch MalwareBazaar Auth-Key for elevated API quota |
| `DB_PATH` | `./threat_radar.db` | Destination path for the persistent SQLite database file |

---

## 🔌 REST API Reference

ThreatRadar provides high-throughput, structured JSON API endpoints:

### Dashboard & Health
- `GET /api/stats` - Total counts of indexed CVEs, malware samples, attack sources, news articles, and sync status.
- `GET /api/status` - Live synchronization state and per-feed success/failure timestamps.
- `POST /api/sync` - Asynchronously triggers an immediate full synchronization of all intelligence feeds.

### Vulnerability Intelligence (CVEs)
- `GET /api/cves` - Search and filter vulnerability records.
  - Query parameters:
    - `q`: Search keyword across CVE ID, vendor, product, or description.
    - `source`: Filter by source (`cisa_kev`, `nvd`, or `all`).
    - `ransomware`: Filter by known ransomware campaign usage (`Known`, `Unknown`).
    - `min_cvss`: Minimum CVSS score (e.g. `7.5`).
    - `severity`: Minimum severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
    - `limit`: Number of results (1 to 200, default 50).
    - `offset`: Pagination offset (default 0).

### Malware Telemetry
- `GET /api/malware` - Search recent malware samples and hashes.
  - Query parameters:
    - `q`: Search by SHA256, MD5, signature, filename, or reporter.
    - `file_type`: Filter by binary type (e.g. `exe`, `elf`, `dll`, `zip`, `pdf`).
    - `signature`: Filter by malware family name (e.g. `AgentTesla`, `RedLine`).
    - `limit` / `offset`: Pagination controls.

### Global Attack Telemetry (SANS DShield)
- `GET /api/dshield` - Returns current SANS Infocon status level, Top 50 attacking IP addresses, and Top 50 targeted ports.

### Threat Intelligence News
- `GET /api/news` - Curated security bulletins and threat alerts.
  - Query parameters:
    - `q`: Search title or snippet text.
    - `source`: Filter by publisher name.
    - `limit` / `offset`: Pagination controls.

### Deep Artifact Inspection
- `GET /api/artifact/{artifact_type}/{identifier}` - Returns raw payload and normalized metadata for an indicator:
  - Supported types: `cve`, `malware`, `ip`, `port`, `news`.
  - Example: `GET /api/artifact/cve/CVE-2024-21413`
  - Example: `GET /api/artifact/malware/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
  - Example: `GET /api/artifact/ip/198.51.100.1`

---

## 🔍 Artifact Deep-Dive

ThreatRadar stores raw JSON representations directly in SQLite for full auditability:
- For CVEs: full CISA KEV or NVD JSON response.
- For Malware: full Abuse.ch metadata including tags, file sizes, delivery methods, and signatures.
- For DShield: raw JSON from SANS ISC endpoints.

---

## 🗺️ Roadmap & Contributing

- [x] Initial FastAPI asynchronous ingestion architecture.
- [x] CISA KEV, NIST NVD, Abuse.ch MalwareBazaar, SANS DShield, and RSS parsers.
- [x] Responsive Web UI with real-time modal inspector.
- [x] Dockerfile and Docker Compose deployment.
- [ ] STIX 2.1 / TAXII export server endpoint.
- [ ] YARA / Sigma rule generation on top of detected malware artifacts.
- [ ] Webhook notifications (Slack, Discord, Telegram, Webex) on Critical CVEs (CVSS 9.0+ / KEV).

Contributions, bug reports, and pull requests are warmly welcome! Please open an issue first to discuss substantial feature proposals.

---

## 🇧🇷 Resumo em Português

O **ThreatRadar** é um centro autônomo e de alta performance para agregação de Inteligência de Ameaças Cibernéticas (CTI) e monitoramento de SOC.
- **Fontes Nativas:** CISA KEV (vulnerabilidades exploradas ativamente), NIST NVD (CVSS e métricas CVE), Abuse.ch MalwareBazaar (amostras de malware e hashes), SANS ISC DShield (IPs atacantes e portas visadas no tráfego global) e feeds CTI de notícias.
- **Implantação Rápida:** Pronto para rodar com `docker compose up -d` na porta 9220 ou nativamente com Python venv e Systemd.
- **Painel e API:** Interface web responsiva para SOC e analistas de segurança, acompanhada de uma API REST completa para integrações com SIEM, SOAR e EDR.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.
