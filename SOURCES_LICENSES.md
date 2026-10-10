# Dark Threat Radar — source and usage notes

This file is an operational inventory, not legal advice. Feed access does not
automatically grant republication or commercial-use rights. The operator must
review each provider's current terms before enabling a public or commercial
deployment.

| Source | Integration | Authentication | Default schedule | Operational note |
|---|---|---|---|---|
| ThreatFox (abuse.ch) | `https://threatfox-api.abuse.ch/api/v1/` | `THREATFOX_AUTH_KEY` | 15 min | Disabled as `auth_required` until a key is configured. Review abuse.ch Terms of Service. |
| URLhaus (abuse.ch) | v2 authenticated `recent.csv` export | `URLHAUS_AUTH_KEY` | 15 min | The key is placed only in the provider request URL and is never logged or returned by the API. Review abuse.ch Terms of Service. |
| Feodo Tracker (abuse.ch) | `ipblocklist.json` | None | 15 min | Attribution: Feodo Tracker / abuse.ch. Review abuse.ch Terms of Service. |
| SSLBL (abuse.ch) | IP, certificate and JA3 CSV feeds | None | 15 min | JA3 is contextual and lower-confidence; stale values are stored inactive. Review abuse.ch Terms of Service. |
| GitHub Advisory Database | GitHub REST global advisories | Optional `GITHUB_TOKEN` | 1 hour | Use is subject to GitHub API terms and advisory data licensing. |
| OSV.dev | package query API | None | 6 hours | Only Watchlist packages are queried; no arbitrary package sweep is performed. Review OSV data-source licenses. |
| Spamhaus DROP | IPv4, IPv6 and ASN NDJSON feeds | None | 1 hour | Use and redistribution are subject to the Spamhaus data terms. |
| OpenPhish | official Community text feed | None | Disabled | Explicit opt-in through the administration panel after reviewing the provider terms; commercial use is not assumed. |
| AlienVault OTX / LevelBlue | OTX DirectConnect pulses API | `OTX_API_KEY` | 1 hour | Requires an OTX account and API key. Pulse data remains attributable to its contributing authors; review current OTX terms before redistribution. |
| PhishTank | verified-online JSON feed | `PHISHTANK_API_KEY` | 1 hour | Requires a free application key. Observe PhishTank attribution, download-frequency, and redistribution requirements. |
| AbuseIPDB | v2 blacklist API | `ABUSEIPDB_API_KEY` | 24 hours | Requests only high-confidence entries. A persistent quota guard honors reset headers and prevents restarts or manual syncs from exhausting the Standard plan's five daily blacklist requests. |
| blocklist.de | public `all.txt` attacker list | None | 1 hour | Indicators are treated as short-lived and expire after 49 hours. Preserve provider attribution and review current usage terms. |
| Microsoft MSRC | public CVRF/CSAF v3 API | None | 1 hour | Public Microsoft security update metadata; linked documents and trademarks remain under their applicable terms. |
| Red Hat Security Data | public CVE API | None | 1 hour | Public product-security metadata; preserve advisory links and review Red Hat API/data terms. |
| CIRCL MISP OSINT | public TLP:CLEAR MISP feed | None | 6 hours | Ingests only recent public events. Respect event-level markings, attribution, and the CIRCL feed terms. |
| MITRE ATT&CK | official Enterprise ATT&CK STIX data | None | 6 hours | ATT&CK is used under MITRE's applicable terms; preserve ATT&CK and MITRE attribution. |
| RansomFeed | `https://api.ransomfeed.it/` | None | 1 hour | Public victim metadata remains attributed to RansomFeed; operators must review current API and data-use terms before redistribution. |
| RansomLook | `https://www.ransomlook.io/api/recent` | None | 1 hour | RansomLook publishes its collected data under CC BY 4.0; preserve attribution and review current project terms. |
| DataBreaches.net | public RSS feed | None | 1 hour | Stores bounded headline/summary metadata and links to the original report. Article content remains with its publisher. |
| ThreatCluster | public ransomware victims API | `THREATCLUSTER_API_KEY` | 1 hour | Optional per-installation key. Do not redistribute feed data outside the local installation without verifying the provider's current plan and terms. |

Existing 1.7 sources remain unchanged: CISA KEV, NIST NVD, EPSS,
MalwareBazaar, SANS ISC DShield, ransomware.live and the configured news feeds.

Provider response bodies and credentials must never be written to connector
health records. Outbound requests identify the Dark Threat Radar client without
including installation secrets.
