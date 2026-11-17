"""All settings come from environment variables (see .env.example)."""
import os


def _int(name, default):
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


def _key(name):
    v = os.getenv(name, "").strip()
    return "" if v.startswith("paste_") else v


ABUSEIPDB_KEY = _key("ABUSEIPDB_KEY")
OTX_KEY = _key("OTX_KEY")

DB = dict(
    host=os.getenv("DB_HOST", "localhost"),
    port=_int("DB_PORT", 5432),
    dbname=os.getenv("DB_NAME", "threatdb"),
    user=os.getenv("DB_USER", "threat"),
    password=os.getenv("DB_PASS", "threat123"),
)

GRAFANA_DB_PASSWORD = os.getenv("GRAFANA_DB_PASSWORD", "grafana_ro_pass")

COLLECT_INTERVAL_HOURS = _int("COLLECT_INTERVAL_HOURS", 6)
BLACKLIST_MIN_HOURS = _int("BLACKLIST_MIN_HOURS", 20)   # free tier: 5 blacklist calls/day
ABUSE_CHECK_LIMIT = _int("ABUSE_CHECK_LIMIT", 200)      # free tier: 1000 checks/day
ENRICH_MAX_AGE_DAYS = _int("ENRICH_MAX_AGE_DAYS", 7)
OTX_PAGES = _int("OTX_PAGES", 10)                       # 50 pulses per page
CIRCL_DAYS = _int("CIRCL_DAYS", 365)
CIRCL_EVENT_DETAILS = _int("CIRCL_EVENT_DETAILS", 100)
SHODAN_LIMIT = _int("SHODAN_LIMIT", 500)
HTTP_TIMEOUT = _int("HTTP_TIMEOUT", 60)
USER_AGENT = "cyber-threat-heatmap/2.0 (academic project)"
