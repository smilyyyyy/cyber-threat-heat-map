# Cyber Threat Heat Map

A self-hosted threat-intelligence dashboard. It collects malicious IP addresses and malware
information from four public sources, scores every IP for risk and shows the results on a
Grafana dashboard with a world heat map.

## What it shows

| Requirement            | Dashboard panel(s)                                                         |
|------------------------|----------------------------------------------------------------------------|
| IP addresses           | AbuseIPDB blacklist explorer, IPs named in OTX / CIRCL threat reports      |
| Attacks by country     | World heat map, Top 15 attacking countries, daily country trend           |
| Most malicious         | Risk-ranked IP table, risk-level breakdown, ISPs and usage types           |
| Top malware families   | Top 15 families (OTX + CIRCL), threat report activity over time            |
| Exposure (extra)       | Open ports, known CVEs and Shodan tags on malicious IPs                     |
| Pipeline health (extra)| Audit log of every collection run                                          |

## Architecture

```
 AbuseIPDB ─┐
 OTX ───────┤                      ┌──────────────┐  read-only  ┌──────────┐
 CIRCL ─────┼──► collector (Python)│  PostgreSQL  │────────────►│ Grafana  │──► browser
 Shodan ────┘    every 6 hours ───►│  (threatdb)  │  grafana_ro │ :3000    │
                                   └──────────────┘             └──────────┘
```

All three parts run as Docker containers defined in `docker-compose.yml`.

| Source              | Key needed | What it provides                                              |
|---------------------|-----------|---------------------------------------------------------------|
| AbuseIPDB blacklist | Yes (free)| Up to 10,000 IPs with 100% abuse confidence, with country     |
| AbuseIPDB check     | Yes (free)| Per-IP total reports, ISP, usage type, Tor flag               |
| AlienVault OTX      | Yes (free)| Threat pulses, malware families, IPv4 indicators              |
| CIRCL OSINT feed    | No        | Public MISP threat events, malware galaxies, IP indicators    |
| Shodan InternetDB   | No        | Open ports, known CVEs, tags for each IP                      |

## Risk score (0-100)

| Weight | Signal                                                         |
|--------|----------------------------------------------------------------|
| 35%    | AbuseIPDB abuse-confidence score                               |
| 25%    | Number of abuse reports (log scale, 1,000+ reports = full)     |
| 20%    | Threat-intel sightings in OTX and CIRCL (5+ = full)            |
| 20%    | Exposure: open ports (10+ = full, half) and any known CVE (half)|

Levels: **Critical** ≥ 75, **High** ≥ 50, **Medium** ≥ 25, **Low** < 25.
The formula lives in the `v_ip_risk` view in `collector/app/schema.sql`.

## Setup (Windows, macOS or Linux)

Requirements: Docker Desktop, free AbuseIPDB and AlienVault OTX accounts.

1. Copy `.env.example` to `.env` and paste your two API keys.
2. Start everything:
   ```
   docker compose up -d --build
   ```
3. Open http://localhost:3000 and log in (default `admin` / `admin123`).
   The dashboard opens automatically and fills in within a few minutes.

## Everyday commands

| Task                               | Command                                                     |
|------------------------------------|-------------------------------------------------------------|
| Watch the collector working        | `docker compose logs -f collector`                          |
| Collect again right now            | `docker compose restart collector`                          |
| Stop (keeps data)                  | `docker compose down`                                       |
| Reset everything (deletes data)    | `docker compose down -v`                                    |
| Row counts                         | `docker exec threat-db psql -U threat -d threatdb -c "SELECT source, status, rows_fetched, finished_at FROM collection_runs ORDER BY id DESC LIMIT 10"` |

## Free-tier limits handled automatically

* AbuseIPDB blacklist: 5 calls/day, so the collector downloads it at most once every 20 hours.
* AbuseIPDB check: 1,000 calls/day, so it checks up to 200 IPs per run (4 runs/day). If the
  quota runs out, the run is logged as `rate_limited` and continues next time.
* Each source is isolated: if one fails, the others still run, and the failure is shown
  in the *Collection Runs* panel.

## Project structure

```
threat-heatmap/
├── docker-compose.yml          one-command deployment
├── .env.example                API keys and settings (copy to .env)
├── db/                         PostgreSQL image + read-only Grafana user
├── collector/
│   ├── Dockerfile
│   └── app/
│       ├── main.py             scheduler and pipeline order
│       ├── schema.sql          tables, views and risk score
│       ├── db.py               connection, schema, run audit log
│       ├── normalize.py        IP validation, malware name cleaning
│       └── sources/            abuseipdb.py, otx.py, circl.py, shodan_idb.py
└── grafana/
    ├── provisioning/           data source + dashboard auto-loaded
    └── dashboards/             cyber-threat-heatmap.json
```

## Security notes

* Grafana connects with `grafana_ro`, a database account that can only read.
* Ports 3000 and 5432 are bound to `127.0.0.1`, so they are not reachable from the network.
* `.env` (API keys) is excluded by `.gitignore`.
* The tool only reads public threat intelligence; it never scans or contacts the listed IPs
  (InternetDB returns Shodan's existing data).
