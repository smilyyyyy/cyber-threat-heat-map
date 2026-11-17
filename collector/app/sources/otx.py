"""AlienVault OTX: threat pulses, the malware families they mention and their IPv4 indicators."""
import logging

from .. import config
from ..http import session
from ..normalize import family, public_ipv4

log = logging.getLogger("otx")
API = "https://otx.alienvault.com/api/v1"


def collect(conn, run):
    if not config.OTX_KEY:
        run.status, run.message = "skipped", "No OTX_KEY in .env"
        return

    s = session()
    s.headers["X-OTX-API-KEY"] = config.OTX_KEY
    pulses = []
    for endpoint in ("pulses/subscribed", "pulses/activity"):
        for page in range(1, config.OTX_PAGES + 1):
            r = s.get(f"{API}/{endpoint}", params={"limit": 50, "page": page},
                      timeout=config.HTTP_TIMEOUT * 2)
            if r.status_code != 200:
                log.warning("%s page %d -> HTTP %d", endpoint, page, r.status_code)
                break
            batch = r.json().get("results", [])
            if not batch:
                break
            pulses.extend(batch)
            log.info("%s page %d: %d pulses", endpoint, page, len(batch))
        if pulses:
            break

    n_mal = n_ip = 0
    with conn.cursor() as cur:
        for p in pulses:
            indicators = p.get("indicators") or []
            cur.execute("""
                INSERT INTO otx_pulses (pulse_id, name, author, created, modified, tlp, adversary,
                                        indicator_count, targeted_countries, tags)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (pulse_id) DO UPDATE SET
                    name = EXCLUDED.name, modified = EXCLUDED.modified,
                    indicator_count = EXCLUDED.indicator_count, tags = EXCLUDED.tags,
                    collected_at = now()""",
                (p["id"], p.get("name"), p.get("author_name"), p.get("created"), p.get("modified"),
                 p.get("TLP") or p.get("tlp"), p.get("adversary") or None,
                 p.get("indicator_count") or len(indicators),
                 p.get("targeted_countries") or [], p.get("tags") or []))

            for fam in p.get("malware_families") or []:
                name = family(fam.get("display_name") if isinstance(fam, dict) else fam)
                if name:
                    cur.execute("INSERT INTO otx_malware VALUES (%s,%s) ON CONFLICT DO NOTHING",
                                (p["id"], name))
                    n_mal += cur.rowcount

            for ind in indicators:
                if ind.get("type") == "IPv4":
                    ip = public_ipv4(ind.get("indicator"))
                    if ip:
                        cur.execute("INSERT INTO otx_ips VALUES (%s,%s) ON CONFLICT DO NOTHING",
                                    (ip, p["id"]))
                        n_ip += cur.rowcount
    conn.commit()
    run.rows = len(pulses)
    run.message = f"{n_mal} new malware tags, {n_ip} new IPs"
