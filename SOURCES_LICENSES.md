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
| OpenPhish | community URL feed | Optional plan key | Disabled | Enable only after confirming the selected OpenPhish plan permits the intended use. |

Existing 1.7 sources remain unchanged: CISA KEV, NIST NVD, EPSS,
MalwareBazaar, SANS ISC DShield, ransomware.live and the configured news feeds.

Provider response bodies and credentials must never be written to connector
health records. User-Agent: `DarkThreatRadar/1.8.1`.
