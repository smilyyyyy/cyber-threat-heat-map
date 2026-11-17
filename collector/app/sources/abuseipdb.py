"""AbuseIPDB: blacklist (bulk malicious IPs) + check (per-IP detail for ranking)."""
import logging
from collections import Counter
from datetime import date

from psycopg2.extras import execute_values

from .. import config, db
from ..http import session
from ..normalize import public_ipv4

log = logging.getLogger("abuseipdb")
API = "https://api.abuseipdb.com/api/v2"


def _headers():
    return {"Key": config.ABUSEIPDB_KEY, "Accept": "application/json"}


def collect_blacklist(conn, run):
    if not config.ABUSEIPDB_KEY:
        run.status, run.message = "skipped", "No ABUSEIPDB_KEY in .env"
        return
    age = db.hours_since_success(conn, "abuseipdb_blacklist")
    if age is not None and age < config.BLACKLIST_MIN_HOURS:
        run.status = "skipped"
        run.message = f"Last download {age:.1f}h ago (free tier allows 5/day)"
        return

    r = session().get(f"{API}/blacklist", headers=_headers(),
                      params={"confidenceMinimum": 100, "limit": 10000},
                      timeout=config.HTTP_TIMEOUT * 2)
    if r.status_code == 429:
        run.status, run.message = "rate_limited", "Daily blacklist quota used"
        return
    r.raise_for_status()

    rows = []
    for d in r.json().get("data", []):
        ip = public_ipv4(d.get("ipAddress"))
        if ip:
            rows.append((ip, d.get("countryCode"), d.get("abuseConfidenceScore"),
                         d.get("lastReportedAt")))

    with conn.cursor() as cur:
        execute_values(cur, """
            INSERT INTO abuse_ips (ip, country_code, confidence, last_reported)
            VALUES %s
            ON CONFLICT (ip) DO UPDATE SET
                country_code   = EXCLUDED.country_code,
                confidence     = EXCLUDED.confidence,
                last_reported  = EXCLUDED.last_reported,
                last_collected = now()""", rows, page_size=1000)

        counts = Counter(r[1] for r in rows if r[1])
        execute_values(cur, """
            INSERT INTO country_snapshots (snapshot_date, country_code, ip_count)
            VALUES %s
            ON CONFLICT (snapshot_date, country_code) DO UPDATE SET ip_count = EXCLUDED.ip_count""",
            [(date.today(), c, n) for c, n in counts.items()])
    conn.commit()
    run.rows = len(rows)


def enrich_ips(conn, run):
    """Look up individual IPs to get total reports, ISP and usage type.
    Intel-feed IPs are checked first, then the most recently reported blacklist IPs."""
    if not config.ABUSEIPDB_KEY:
        run.status, run.message = "skipped", "No ABUSEIPDB_KEY in .env"
        return

    fresh = """NOT EXISTS (SELECT 1 FROM ip_enrichment e WHERE e.ip = c.ip
                              AND e.checked_at > now() - make_interval(days => %s))"""
    half = config.ABUSE_CHECK_LIMIT // 2
    with conn.cursor() as cur:
        # Half the daily budget: IPs named in threat reports (OTX / CIRCL)
        cur.execute(f"""SELECT DISTINCT c.ip FROM (SELECT ip FROM otx_ips UNION SELECT ip FROM circl_ips) c
                        WHERE {fresh} LIMIT %s""", (config.ENRICH_MAX_AGE_DAYS, half))
        candidates = [r[0] for r in cur.fetchall()]
        # The rest: the most recently reported blacklist IPs
        cur.execute(f"""SELECT c.ip FROM abuse_ips c WHERE {fresh} AND NOT (c.ip = ANY(%s))
                        ORDER BY c.last_reported DESC NULLS LAST LIMIT %s""",
                    (config.ENRICH_MAX_AGE_DAYS, candidates,
                     config.ABUSE_CHECK_LIMIT - len(candidates)))
        candidates += [r[0] for r in cur.fetchall()]

    s = session()
    for ip in candidates:
        r = s.get(f"{API}/check", headers=_headers(),
                  params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=config.HTTP_TIMEOUT)
        if r.status_code == 429:
            run.status, run.message = "rate_limited", f"Daily check quota reached after {run.rows} IPs"
            break
        if r.status_code != 200:
            continue
        d = r.json().get("data", {})
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO ip_enrichment (ip, country_code, abuse_confidence, total_reports,
                    distinct_users, isp, usage_type, domain, is_tor, last_reported, checked_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, now())
                ON CONFLICT (ip) DO UPDATE SET
                    country_code = EXCLUDED.country_code, abuse_confidence = EXCLUDED.abuse_confidence,
                    total_reports = EXCLUDED.total_reports, distinct_users = EXCLUDED.distinct_users,
                    isp = EXCLUDED.isp, usage_type = EXCLUDED.usage_type, domain = EXCLUDED.domain,
                    is_tor = EXCLUDED.is_tor, last_reported = EXCLUDED.last_reported, checked_at = now()""",
                (ip, d.get("countryCode"), d.get("abuseConfidenceScore"), d.get("totalReports"),
                 d.get("numDistinctUsers"), d.get("isp"), d.get("usageType"), d.get("domain"),
                 d.get("isTor"), d.get("lastReportedAt")))
        conn.commit()
        run.rows += 1
    if not run.message:
        run.message = f"{len(candidates)} IPs queued"
