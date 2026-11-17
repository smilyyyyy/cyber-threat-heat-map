
-- ---------- Pipeline audit log ----------
CREATE TABLE IF NOT EXISTS collection_runs (
    id           SERIAL PRIMARY KEY,
    source       TEXT NOT NULL,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at  TIMESTAMPTZ,
    status       TEXT NOT NULL DEFAULT 'running',   -- ok | skipped | rate_limited | error
    rows_fetched INT DEFAULT 0,
    duration_s   NUMERIC(8,2),
    message      TEXT
);

-- ---------- AbuseIPDB ----------
CREATE TABLE IF NOT EXISTS abuse_ips (
    ip             TEXT PRIMARY KEY,
    country_code   CHAR(2),
    confidence     INT,
    last_reported  TIMESTAMPTZ,
    first_seen     TIMESTAMPTZ DEFAULT now(),
    last_collected TIMESTAMPTZ DEFAULT now()
);

-- Per-IP detail from the AbuseIPDB "check" endpoint
CREATE TABLE IF NOT EXISTS ip_enrichment (
    ip               TEXT PRIMARY KEY,
    country_code     CHAR(2),
    abuse_confidence INT,
    total_reports    INT,
    distinct_users   INT,
    isp              TEXT,
    usage_type       TEXT,
    domain           TEXT,
    is_tor           BOOLEAN,
    last_reported    TIMESTAMPTZ,
    checked_at       TIMESTAMPTZ DEFAULT now()
);

-- Daily snapshot of blacklist size per country (trend over time)
CREATE TABLE IF NOT EXISTS country_snapshots (
    snapshot_date DATE,
    country_code  CHAR(2),
    ip_count      INT,
    PRIMARY KEY (snapshot_date, country_code)
);

-- ---------- AlienVault OTX ----------
CREATE TABLE IF NOT EXISTS otx_pulses (
    pulse_id           TEXT PRIMARY KEY,
    name               TEXT,
    author             TEXT,
    created            TIMESTAMPTZ,
    modified           TIMESTAMPTZ,
    tlp                TEXT,
    adversary          TEXT,
    indicator_count    INT,
    targeted_countries TEXT[],
    tags               TEXT[],
    collected_at       TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS otx_malware (
    pulse_id TEXT REFERENCES otx_pulses(pulse_id) ON DELETE CASCADE,
    family   TEXT,
    PRIMARY KEY (pulse_id, family)
);

CREATE TABLE IF NOT EXISTS otx_ips (
    ip       TEXT,
    pulse_id TEXT REFERENCES otx_pulses(pulse_id) ON DELETE CASCADE,
    PRIMARY KEY (ip, pulse_id)
);

-- ---------- CIRCL OSINT (MISP feed) ----------
CREATE TABLE IF NOT EXISTS circl_events (
    event_uuid   TEXT PRIMARY KEY,
    info         TEXT,
    event_date   DATE,
    threat_level INT,          -- 1 High, 2 Medium, 3 Low, 4 Undefined
    org          TEXT,
    details_fetched BOOLEAN DEFAULT FALSE,
    collected_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS circl_malware (
    event_uuid TEXT REFERENCES circl_events(event_uuid) ON DELETE CASCADE,
    family     TEXT,
    PRIMARY KEY (event_uuid, family)
);

CREATE TABLE IF NOT EXISTS circl_ips (
    ip         TEXT,
    event_uuid TEXT REFERENCES circl_events(event_uuid) ON DELETE CASCADE,
    PRIMARY KEY (ip, event_uuid)
);

-- ---------- Shodan InternetDB (exposure) ----------
CREATE TABLE IF NOT EXISTS shodan_idb (
    ip         TEXT PRIMARY KEY,
    ports      INT[]  DEFAULT '{}',
    vulns      TEXT[] DEFAULT '{}',
    cpes       TEXT[] DEFAULT '{}',
    hostnames  TEXT[] DEFAULT '{}',
    tags       TEXT[] DEFAULT '{}',
    found      BOOLEAN,
    checked_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_abuse_country ON abuse_ips(country_code);
CREATE INDEX IF NOT EXISTS idx_otx_ips_ip    ON otx_ips(ip);
CREATE INDEX IF NOT EXISTS idx_circl_ips_ip  ON circl_ips(ip);

-- =====================================================================
-- Analytical views used by Grafana
-- =====================================================================
DROP VIEW IF EXISTS v_ip_risk CASCADE;
DROP VIEW IF EXISTS v_ip_master CASCADE;
DROP VIEW IF EXISTS v_malware CASCADE;

-- One row per malicious IP, merged across every source
CREATE VIEW v_ip_master AS
WITH all_ips AS (
    SELECT ip FROM abuse_ips
    UNION SELECT ip FROM otx_ips
    UNION SELECT ip FROM circl_ips
),
otx AS (SELECT ip, count(*) AS n FROM otx_ips   GROUP BY ip),
cir AS (SELECT ip, count(*) AS n FROM circl_ips GROUP BY ip)
SELECT
    i.ip,
    COALESCE(e.country_code, a.country_code)         AS country_code,
    COALESCE(e.abuse_confidence, a.confidence, 0)    AS abuse_confidence,
    COALESCE(e.total_reports, 0)                     AS total_reports,
    e.distinct_users,
    e.isp,
    e.usage_type,
    e.domain,
    COALESCE(e.is_tor, FALSE)                        AS is_tor,
    COALESCE(o.n, 0)                                 AS otx_pulses,
    COALESCE(c.n, 0)                                 AS circl_events,
    COALESCE(o.n, 0) + COALESCE(c.n, 0)              AS intel_sightings,
    COALESCE(cardinality(s.ports), 0)                AS open_ports,
    COALESCE(cardinality(s.vulns), 0)                AS cve_count,
    s.ports,
    s.vulns,
    (a.ip IS NOT NULL)                               AS in_abuseipdb,
    (e.ip IS NOT NULL)                               AS enriched,
    (s.ip IS NOT NULL)                               AS shodan_checked,
    COALESCE(e.last_reported, a.last_reported)       AS last_reported,
    concat_ws(' + ',
        CASE WHEN a.ip IS NOT NULL THEN 'AbuseIPDB' END,
        CASE WHEN o.ip IS NOT NULL THEN 'OTX' END,
        CASE WHEN c.ip IS NOT NULL THEN 'CIRCL' END) AS sources
FROM all_ips i
LEFT JOIN abuse_ips     a ON a.ip = i.ip
LEFT JOIN ip_enrichment e ON e.ip = i.ip
LEFT JOIN shodan_idb    s ON s.ip = i.ip
LEFT JOIN otx           o ON o.ip = i.ip
LEFT JOIN cir           c ON c.ip = i.ip;

-- Composite risk score (0-100). Weights:
--   35% AbuseIPDB confidence
--   25% report volume (log-scaled, 1000+ reports = full marks)
--   20% threat-intel sightings (OTX pulses + CIRCL events, 5+ = full marks)
--   20% exposure (Shodan: half for open ports (10+ = full), half if any CVE)
CREATE VIEW v_ip_risk AS
SELECT m.*,
    ROUND((
          0.35 * m.abuse_confidence
        + 0.25 * LEAST(100, 100 * ln(1 + m.total_reports) / ln(1001))
        + 0.20 * LEAST(m.intel_sightings, 5) * 20
        + 0.20 * (0.5 * LEAST(m.open_ports, 10) * 10
                + 0.5 * CASE WHEN m.cve_count > 0 THEN 100 ELSE 0 END)
    )::numeric, 1) AS risk_score
FROM v_ip_master m;

DROP VIEW IF EXISTS v_ip_risk_level;
CREATE VIEW v_ip_risk_level AS
SELECT r.*,
    CASE WHEN r.risk_score >= 75 THEN 'Critical'
         WHEN r.risk_score >= 50 THEN 'High'
         WHEN r.risk_score >= 25 THEN 'Medium'
         ELSE 'Low' END AS risk_level
FROM v_ip_risk r;

CREATE VIEW v_malware AS
SELECT 'OTX'::text AS source, m.family, p.created AS seen_at
FROM otx_malware m JOIN otx_pulses p USING (pulse_id)
UNION ALL
SELECT 'CIRCL', m.family, e.event_date::timestamptz
FROM circl_malware m JOIN circl_events e USING (event_uuid);
