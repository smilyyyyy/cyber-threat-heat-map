"""CIRCL OSINT feed (public MISP feed, no API key needed).
manifest.json lists every event with its tags; each event file holds its indicators."""
import logging
from datetime import date, timedelta

from .. import config
from ..http import session
from ..normalize import families_from_tags, public_ipv4

log = logging.getLogger("circl")
FEED = "https://www.circl.lu/doc/misp/feed-osint"
IP_TYPES = {"ip-dst", "ip-src", "ip-dst|port", "ip-src|port"}


def _parse_date(value):
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def _tag_names(obj):
    return [t.get("name", "") for t in (obj.get("Tag") or []) if isinstance(t, dict)]


def collect(conn, run):
    s = session()
    r = s.get(f"{FEED}/manifest.json", timeout=config.HTTP_TIMEOUT * 2)
    r.raise_for_status()
    manifest = r.json()

    events = []
    for uuid, ev in manifest.items():
        d = _parse_date(ev.get("date"))
        if d:
            events.append((uuid, ev, d))
    events.sort(key=lambda e: e[2], reverse=True)

    cutoff = date.today() - timedelta(days=config.CIRCL_DAYS)
    recent = [e for e in events if e[2] >= cutoff]
    if len(recent) < 50:                       # feed quiet lately: keep the latest 200 instead
        recent = events[:200]

    n_mal = 0
    with conn.cursor() as cur:
        for uuid, ev, d in recent:
            try:
                level = int(ev.get("threat_level_id") or 4)
            except ValueError:
                level = 4
            cur.execute("""
                INSERT INTO circl_events (event_uuid, info, event_date, threat_level, org)
                VALUES (%s,%s,%s,%s,%s)
                ON CONFLICT (event_uuid) DO UPDATE SET info = EXCLUDED.info""",
                (uuid, (ev.get("info") or "")[:500], d, level,
                 (ev.get("Orgc") or {}).get("name")))
            for fam in families_from_tags(_tag_names(ev)):
                cur.execute("INSERT INTO circl_malware VALUES (%s,%s) ON CONFLICT DO NOTHING",
                            (uuid, fam))
                n_mal += cur.rowcount
    conn.commit()

    # Download full details (IPs + galaxy clusters) for the newest events not yet processed
    with conn.cursor() as cur:
        cur.execute("""SELECT event_uuid FROM circl_events WHERE NOT details_fetched
                       ORDER BY event_date DESC LIMIT %s""", (config.CIRCL_EVENT_DETAILS,))
        todo = [x[0] for x in cur.fetchall()]

    n_ip = 0
    for uuid in todo:
        try:
            er = s.get(f"{FEED}/{uuid}.json", timeout=config.HTTP_TIMEOUT)
            er.raise_for_status()
            event = er.json().get("Event", {})
        except Exception as e:                  # one broken event never stops the run
            log.warning("event %s: %s", uuid, e)
            continue

        attrs = list(event.get("Attribute") or [])
        for obj in event.get("Object") or []:
            attrs.extend(obj.get("Attribute") or [])

        fams = families_from_tags(_tag_names(event))
        for g in event.get("Galaxy") or []:
            for cl in g.get("GalaxyCluster") or []:
                if cl.get("tag_name"):
                    fams |= families_from_tags([cl["tag_name"]])

        with conn.cursor() as cur:
            for a in attrs:
                if a.get("type") in IP_TYPES:
                    ip = public_ipv4(str(a.get("value", "")).split("|")[0])
                    if ip:
                        cur.execute("INSERT INTO circl_ips VALUES (%s,%s) ON CONFLICT DO NOTHING",
                                    (ip, uuid))
                        n_ip += cur.rowcount
                fams |= families_from_tags(_tag_names(a))
            for fam in fams:
                cur.execute("INSERT INTO circl_malware VALUES (%s,%s) ON CONFLICT DO NOTHING",
                            (uuid, fam))
                n_mal += cur.rowcount
            cur.execute("UPDATE circl_events SET details_fetched = TRUE WHERE event_uuid = %s", (uuid,))
        conn.commit()

    run.rows = len(recent)
    run.message = f"{len(todo)} events detailed, {n_mal} new malware tags, {n_ip} new IPs"
