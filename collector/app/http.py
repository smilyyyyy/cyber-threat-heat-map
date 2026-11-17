"""Shared HTTP session with automatic retries for transient server errors."""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import config


def session():
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=2,
                  status_forcelist=(500, 502, 503, 504),
                  allowed_methods=("GET",))
    s.mount("https://", HTTPAdapter(max_retries=retry, pool_maxsize=10))
    s.headers["User-Agent"] = config.USER_AGENT
    return s
