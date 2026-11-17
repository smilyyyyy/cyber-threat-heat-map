"""Database connection, schema setup and the collection-run audit log."""
import logging
import pathlib
import time
from contextlib import contextmanager

import psycopg2
from psycopg2 import sql

from . import config

log = logging.getLogger("db")
SCHEMA = pathlib.Path(__file__).with_name("schema.sql")


def connect(retries=20):
    for attempt in range(1, retries + 1):
        try:
            conn = psycopg2.connect(**config.DB)
            conn.autocommit = False
            return conn
        except psycopg2.OperationalError as e:
            log.info("Database not ready (attempt %d/%d): %s", attempt, retries, str(e).strip())
            time.sleep(3)
    raise SystemExit("Could not connect to PostgreSQL.")


def apply_schema(conn):
    with conn.cursor() as cur:
        cur.execute(SCHEMA.read_text())
        # Make sure the read-only Grafana user exists and can see every table and view
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'grafana_ro'")
        if not cur.fetchone():
            cur.execute(sql.SQL("CREATE ROLE grafana_ro LOGIN PASSWORD {}").format(
                sql.Literal(config.GRAFANA_DB_PASSWORD)))
            log.info("Created read-only role grafana_ro.")
        cur.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO grafana_ro").format(
            sql.Identifier(config.DB["dbname"])))
        cur.execute("GRANT USAGE ON SCHEMA public TO grafana_ro")
        cur.execute("GRANT SELECT ON ALL TABLES IN SCHEMA public TO grafana_ro")
    conn.commit()
    log.info("Schema ready.")


class Run:
    """Tracks one source's collection: rows fetched, status and message."""
    def __init__(self):
        self.rows = 0
        self.status = "ok"
        self.message = ""


@contextmanager
def run_log(conn, source):
    """Records every collection attempt in collection_runs (pipeline health)."""
    with conn.cursor() as cur:
        cur.execute("INSERT INTO collection_runs (source) VALUES (%s) RETURNING id", (source,))
        run_id = cur.fetchone()[0]
    conn.commit()
    start = time.time()
    run = Run()
    try:
        yield run
    except Exception as e:                       # one failing source never stops the others
        conn.rollback()
        run.status, run.message = "error", f"{type(e).__name__}: {e}"[:500]
        log.exception("[%s] failed", source)
    finally:
        with conn.cursor() as cur:
            cur.execute("""UPDATE collection_runs
                           SET finished_at = now(), status = %s, rows_fetched = %s,
                               duration_s = %s, message = %s
                           WHERE id = %s""",
                        (run.status, run.rows, round(time.time() - start, 2),
                         run.message or None, run_id))
        conn.commit()
        log.info("[%s] %s - %d rows (%.1fs) %s", source, run.status, run.rows,
                 time.time() - start, run.message)


def hours_since_success(conn, source):
    with conn.cursor() as cur:
        cur.execute("""SELECT EXTRACT(EPOCH FROM now() - max(finished_at)) / 3600
                       FROM collection_runs WHERE source = %s AND status = 'ok'""", (source,))
        v = cur.fetchone()[0]
    return None if v is None else float(v)
