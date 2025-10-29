import re
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse

# --- Session with retries ---
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


def _normalize_url(url: str) -> str:
    """
    Ensure URL has a scheme. If missing, default to http://.
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        return "http://" + url
    return url


def get_request(url, method="GET", headers=None, timeout=10, allow_redirects=True, session=None, verify=True):
    """
    Send an HTTP request to the given URL using a session with retries.
    - method: GET, HEAD, OPTIONS, etc.
    - headers: optional dict to override/add headers
    - timeout: seconds
    - allow_redirects: follow redirects for GET by default
    - session: optional requests.Session (if not provided, use internal session)
    - verify: SSL verification (True/False or path to CA bundle)
    Returns: response object or None if error
    """
    session = session or _SESSION
    url = _normalize_url(url)
    method = method.upper()

    if headers:
        # merge headers into session headers for this request only
        req_headers = session.headers.copy()
        req_headers.update(headers)
    else:
        req_headers = None

    try:
        if method == "GET":
            response = session.get(url, headers=req_headers, timeout=timeout, allow_redirects=allow_redirects, verify=verify)
        elif method == "HEAD":
            response = session.head(url, headers=req_headers, timeout=timeout, allow_redirects=False, verify=verify)
        elif method == "OPTIONS":
            response = session.options(url, headers=req_headers, timeout=timeout, allow_redirects=False, verify=verify)
        elif method in {"POST", "PUT", "DELETE", "PATCH"}:
            # for these methods caller should supply data/json if needed
            response = session.request(method, url, headers=req_headers, timeout=timeout, allow_redirects=allow_redirects, verify=verify)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        return response

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request failed for {url}: {e}")
        return None


def parse_headers(response):
    """
    Parse headers from a requests response object.
    Returns a normal dict (header names as provided by server).
    """
    if response is None:
        return {}
    return dict(response.headers)


def print_headers(headers_dict):
    """
    Print headers line by line (clean, no extra spaces).
    """
    print("\n📋 Response Headers:\n")
    for k, v in headers_dict.items():
        print(f"{k}: {v}")


def print_options_response(url, timeout=10, session=None, verify=True):
    """
    Sends an OPTIONS request and displays the full response like 'curl -i -X OPTIONS'.
    Returns the response or None.
    """
    url = _normalize_url(url)
    print(f"\n{url} — OPTIONS Response:\n" + "=" * 50)
    session = session or _SESSION
    try:
        response = session.options(url, timeout=timeout, allow_redirects=False, verify=verify)
        # Construct readable HTTP/version line if possible
        http_version = "HTTP/?"
        try:
            # response.raw.version is an integer (10 for HTTP/1.0, 11 for HTTP/1.1, 20 for HTTP/2)
            raw_version = getattr(response.raw, "version", None)
            if raw_version is not None:
                if raw_version >= 20:
                    http_version = "HTTP/2"
                elif raw_version == 11:
                    http_version = "HTTP/1.1"
                elif raw_version == 10:
                    http_version = "HTTP/1.0"
        except Exception:
            pass

        print(f"{http_version} {response.status_code} {response.reason}")
        for k, v in response.headers.items():
            print(f"{k}: {v}")
        print()  # newline spacing
        return response
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch OPTIONS response: {e}")
        return None


def get_allowed_methods(url, timeout=10, session=None, verify=True):
    """
    Check which HTTP methods are allowed by the server.
    Uses OPTIONS request and parses Allow header if present.
    Returns list of upper-case method names (e.g. ['GET','POST']).
    """
    session = session or _SESSION
    response = get_request(url, method="OPTIONS", timeout=timeout, session=session, verify=verify)
    if response is None:
        return []

    allow = response.headers.get("Allow") or response.headers.get("allow")
    if allow:
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        return methods
    # fallback: some servers don't send Allow; try to infer from status or common methods
    return []


# -----------------------
# Example use of `re`: parse 'Server' header to extract product and version
# -----------------------
def parse_server_header(response):
    """
    If the response has a 'Server' header, use regex to extract product and version.
    Returns dict: {'raw': '...', 'product': 'Apache', 'version': '2.4.41', 'extra': '(Ubuntu)'}
    Returns None if no Server header.
    """
    if response is None:
        return None
    server = response.headers.get("Server") or response.headers.get("server")
    if not server:
        return None

    # Example server formats:
    #   Apache/2.4.41 (Ubuntu)
    #   nginx/1.18.0
    #   Microsoft-IIS/10.0
    #   cloudflare
    pattern = r'^\s*(?P<product>[^/\s]+)(?:/(?P<version>[\d\.]+))?(?:\s*(?P<extra>\(.*\)))?'
    m = re.search(pattern, server)
    if not m:
        return {"raw": server}

    return {
        "raw": server,
        "product": m.group("product"),
        "version": m.group("version"),
        "extra": m.group("extra")
    }
