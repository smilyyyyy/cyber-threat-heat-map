"""Shodan InternetDB (free, no key): open ports, known CVEs and tags for each malicious IP."""
import logging
from concurrent.futures import ThreadPoolExecutor

from .. import config
from ..http import session

log = logging.getLogger("shodan")
API = "https://internetdb.shodan.io"


def _lookup(s, ip):
    try:
        r = s.get(f"{API}/{ip}", timeout=config.HTTP_TIMEOUT)
    except Exception as e:
        return ip, "error", str(e)
    if r.status_code == 200:
        return ip, "found", r.json()
    if r.status_code == 404:
        return ip, "none", {}
    if r.status_code == 429:
        return ip, "limited", {}
    return ip, "error", f"HTTP {r.status_code}"


def collect(conn, run):
    # Highest-priority IPs first: most reported, then those seen in threat-intel feeds
    with conn.cursor() as cur:
        cur.execute("""
            SELECT m.ip FROM v_ip_master m
            WHERE NOT EXISTS (SELECT 1 FROM shodan_idb s WHERE s.ip = m.ip
                              AND s.checked_at > now() - make_interval(days => %s))
            ORDER BY m.total_reports DESC, m.intel_sightings DESC, m.last_reported DESC NULLS LAST
            LIMIT %s""", (config.ENRICH_MAX_AGE_DAYS, config.SHODAN_LIMIT))
        candidates = [r[0] for r in cur.fetchall()]

    s = session()
    found = limited = 0
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda ip: _lookup(s, ip), candidates))

    with conn.cursor() as cur:
        for ip, status, data in results:
            if status == "limited":
                limited += 1
                continue
            if status == "error":
                continue
            found += status == "found"
            cur.execute("""
                INSERT INTO shodan_idb (ip, ports, vulns, cpes, hostnames, tags, found, checked_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s, now())
                ON CONFLICT (ip) DO UPDATE SET
                    ports = EXCLUDED.ports, vulns = EXCLUDED.vulns, cpes = EXCLUDED.cpes,
                    hostnames = EXCLUDED.hostnames, tags = EXCLUDED.tags,
                    found = EXCLUDED.found, checked_at = now()""",
                (ip, data.get("ports") or [], data.get("vulns") or [], data.get("cpes") or [],
                 data.get("hostnames") or [], data.get("tags") or [], status == "found"))
            run.rows += 1
    conn.commit()
    run.message = f"{len(candidates)} queried, {found} with exposure data"
    if limited:
        run.status = "rate_limited"
        run.message += f", {limited} rate-limited"
