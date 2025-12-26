# http_client.py
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- Session with retries (kept for options printing if desired) ---
def get_retry_session(retries=3, backoff_factor=0.3, status_forcelist=(429, 500, 502, 503, 504)):
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=frozenset(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'DELETE', 'PATCH'])
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    # sensible default UA
    session.headers.update({"User-Agent": "WebSecScan/1.0 (+https://example.com)"})
    return session

_SESSION = get_retry_session()


def parse_headers(response):
    """
    Parse headers from a requests response object.
    Returns a normal dict (header names as provided by server).
    """
    if response is None:
        return {}
    return dict(response.headers)
