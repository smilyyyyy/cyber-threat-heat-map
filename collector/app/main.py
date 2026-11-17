"""
Cyber Threat Heat Map - collector
Pulls threat intelligence from AbuseIPDB, AlienVault OTX, CIRCL and Shodan InternetDB,
stores it in PostgreSQL and lets Grafana visualise it.

  python -m app.main          run forever (every COLLECT_INTERVAL_HOURS)
  python -m app.main --once   run one collection cycle and exit
"""
import logging
import sys
import time
from datetime import datetime, timezone

from . import config, db
from .sources import abuseipdb, circl, otx, shodan_idb

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
log = logging.getLogger("collector")

# Order matters: gather IPs first, then enrich them, then score them (views)
PIPELINE = [
    ("abuseipdb_blacklist", abuseipdb.collect_blacklist),
    ("otx",                 otx.collect),
    ("circl",               circl.collect),
    ("abuseipdb_check",     abuseipdb.enrich_ips),
    ("shodan_internetdb",   shodan_idb.collect),
]


def cycle():
    conn = db.connect()
    try:
        db.apply_schema(conn)
        for name, func in PIPELINE:
            with db.run_log(conn, name) as run:
                func(conn, run)
        summary(conn)
    finally:
        conn.close()


def summary(conn):
    with conn.cursor() as cur:
        cur.execute("""SELECT
            (SELECT count(*) FROM v_ip_master),
            (SELECT count(DISTINCT country_code) FROM v_ip_master),
            (SELECT count(DISTINCT family) FROM v_malware),
            (SELECT count(*) FROM v_ip_risk_level WHERE risk_level IN ('Critical','High'))""")
        ips, countries, fams, high = cur.fetchone()
    log.info("SUMMARY: %d malicious IPs | %d countries | %d malware families | %d high/critical-risk IPs",
             ips, countries, fams, high)


def main():
    once = "--once" in sys.argv
    interval = config.COLLECT_INTERVAL_HOURS * 3600
    next_run = time.time()
    while True:
        # Wall-clock schedule checked every minute: if the laptop sleeps past the
        # due time, the missed collection runs as soon as it wakes up.
        if time.time() >= next_run:
            log.info("=== Collection cycle started ===")
            try:
                cycle()
            except Exception:
                log.exception("Collection cycle failed; will retry at the next interval")
            if once:
                break
            next_run = time.time() + interval
            log.info("Next collection at %s (in %d hours).",
                     datetime.fromtimestamp(next_run, timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                     config.COLLECT_INTERVAL_HOURS)
        time.sleep(60)


if __name__ == "__main__":
    main()