import re
import socket
import time
from typing import Dict, List, Tuple, Any, Optional
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import Fore, Style

# Common fingerprinting headers (lowercase for normalized lookups)
COMMON_LEAK_HEADERS = [
    "server",
    "x-powered-by",
    "via",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-powered-by-plesk",
    "x-generator",
    "x-drupal-cache",
    "x-cache",
    "x-backend-server",
    "x-cf-powered-by",
    "x-forwarded-for",
]

def _get_retry_session(retries: int = 2, backoff: float = 0.2) -> requests.Session:
    """
    Return a requests.Session with a Retry policy to reduce false negatives on transient network errors.
    """
    s = requests.Session()
    retry = Retry(total=retries, backoff_factor=backoff,
                  status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=frozenset(['HEAD', 'GET', 'OPTIONS', 'POST']))
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": "WebSecScan/1.0"})
    return s

def _resolve_hostname(hostname: str) -> List[str]:
    """Resolve hostname to a list of unique IP addresses (IPv4/IPv6)."""
    ips: List[str] = []
    try:
        for res in socket.getaddrinfo(hostname, None):
            ip = res[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        # resolution failed: return empty list
        pass
    return ips

def _normalize_url(url: str) -> str:
    """
    Ensure URL has a scheme; if missing default to http://
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        return "http://" + url
    return url

def _safe_head_get(url: str, session: Optional[requests.Session] = None, timeout: int = 10) -> Tuple[Optional[requests.Response], Optional[float]]:
    """
    Try HEAD first (non-destructive). If HEAD returns 405/501 or raises specific errors, fallback to GET.
    Returns (response or None, elapsed_seconds or None)
    """
    session = session or _get_retry_session()
    try:
        start = time.time()
        resp = session.head(url, timeout=timeout, allow_redirects=True)
        elapsed = time.time() - start
        if resp is None:
            return None, None
        if resp.status_code in (405, 501):
            # HEAD not allowed — try GET
            start = time.time()
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            elapsed = time.time() - start
        return resp, elapsed
    except requests.RequestException:
        # fallback: try GET once more (without raising)
        try:
            start = time.time()
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            elapsed = time.time() - start
            return resp, elapsed
        except requests.RequestException:
            return None, None

# Regex to parse Server header into product/version/extra (defensible usage of re)
_SERVER_RE = re.compile(r'^\s*(?P<product>[^/\s]+)(?:/(?P<version>[\d\.]+))?(?:\s*(?P<extra>\(.*\)))?')

def parse_server_header(server_value: str) -> Dict[str, Optional[str]]:
    """
    Parse a Server header value into product/version/extra if possible.
    Returns dict with keys raw, product, version, extra.
    """
    if not server_value:
        return {"raw": None, "product": None, "version": None, "extra": None}
    m = _SERVER_RE.search(server_value)
    if not m:
        return {"raw": server_value, "product": None, "version": None, "extra": None}
    return {"raw": server_value, "product": m.group("product"), "version": m.group("version"), "extra": m.group("extra")}

def get_server_info(target_url: str, timeout: int = 10, session: Optional[requests.Session] = None) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Gather server information and analyze header exposures.

    Returns:
      info: dict (url, hostname, ips, status_code, reason, elapsed, headers)
      findings: list of findings with keys Header, Status, Severity, Recommendation, (optional) Detail
    """
    session = session or _get_retry_session()
    target_url = _normalize_url(target_url)
    parsed = urlparse(target_url)
    hostname = parsed.hostname

    info: Dict[str, Any] = {
        "url": target_url,
        "hostname": hostname,
        "ips": [],
        "status_code": None,
        "reason": None,
        "elapsed": None,
        "headers": {}
    }
    findings: List[Dict[str, Any]] = []

    if not hostname:
        findings.append({
            "Header": "Server Info",
            "Status": "Invalid URL",
            "Severity": "Medium",
            "Recommendation": "Provide a valid URL (including scheme, e.g., https://example.com)."
        })
        return info, findings

    # Resolve IP(s)
    info["ips"] = _resolve_hostname(hostname)

    # Perform HEAD/GET request
    resp, elapsed = _safe_head_get(target_url, session=session, timeout=timeout)
    if resp is None:
        findings.append({
            "Header": "Server Info",
            "Status": "No response",
            "Severity": "Medium",
            "Recommendation": "Target did not respond to HTTP requests or timed out."
        })
        return info, findings

    # Fill info
    info["status_code"] = resp.status_code
    info["reason"] = resp.reason
    info["elapsed"] = elapsed

    # Normalize headers to lowercase keys for consistent analysis
    headers = {k.lower(): v for k, v in resp.headers.items() if v is not None}
    # subset only fingerprint headers (if present)
    headers_subset = {h: headers.get(h) for h in COMMON_LEAK_HEADERS if headers.get(h)}
    info["headers"] = headers_subset

    # ----- Analyze exposures -----

    # 1) Server header presence and version leak
    server_hdr = headers.get("server")
    if server_hdr:
        parsed_server = parse_server_header(server_hdr)
        # If server header contains digits (version) treat as High; else Medium
        has_version = bool(parsed_server.get("version")) or any(ch.isdigit() for ch in (server_hdr or ""))
        findings.append({
            "Header": "Server",
            "Status": f"Present: {server_hdr}",
            "Severity": "High" if has_version else "Medium",
            "Recommendation": ("Remove or minimize the Server header exposure. Do not reveal software or version numbers; "
                               "configure the web server to return generic values or hide the header."),
            "Detail": parsed_server
        })

    # 2) X-Powered-By and framework/version headers
    xpby = headers.get("x-powered-by")
    if xpby:
        findings.append({
            "Header": "X-Powered-By",
            "Status": f"Present: {xpby}",
            "Severity": "High",
            "Recommendation": "Remove X-Powered-By header (or disable in framework) to avoid framework fingerprinting.",
            "Detail": xpby
        })

    for h in ("x-aspnet-version", "x-aspnetmvc-version", "x-powered-by-plesk", "x-generator"):
        val = headers.get(h)
        if val:
            findings.append({
                "Header": h,
                "Status": f"Present: {val}",
                "Severity": "High",
                "Recommendation": f"Remove or disable the {h} header to avoid disclosing internal framework/version details.",
                "Detail": val
            })

    # 3) Via header — indicates intermediate proxies / gateways
    via = headers.get("via")
    if via:
        findings.append({
            "Header": "Via",
            "Status": f"Present: {via}",
            "Severity": "Medium",
            "Recommendation": "Via header present; it may reveal proxy topology or intermediaries. Consider normalizing at the edge.",
            "Detail": via
        })

    # 4) X-Cache / X-Backend-Server / X-CF-Powered-By / X-Forwarded-For — backend/proxy info
    for proxy_hdr in ("x-cache", "x-backend-server", "x-cf-powered-by", "x-forwarded-for"):
        v = headers.get(proxy_hdr)
        if v:
            findings.append({
                "Header": proxy_hdr,
                "Status": f"Present: {v}",
                "Severity": "Low",
                "Recommendation": f"Consider removing or normalizing the {proxy_hdr} header to avoid exposing infrastructure details.",
                "Detail": v
            })

    # 5) Content-Type and Content-Encoding (informational)
    ct = headers.get("content-type")
    if ct:
        findings.append({
            "Header": "Content-Type",
            "Status": f"Present: {ct}",
            "Severity": "Low",
            "Recommendation": "Ensure content types are correctly set; avoid serving sensitive data with permissive types.",
            "Detail": ct
        })
    ce = headers.get("content-encoding")
    if ce:
        findings.append({
            "Header": "Content-Encoding",
            "Status": f"Present: {ce}",
            "Severity": "Low",
            "Recommendation": "Content-Encoding is present (e.g., gzip); ensure compression is configured safely.",
            "Detail": ce
        })

    # 6) If no identifying headers found, mark as good (not exposed)
    if not headers_subset:
        findings.append({
            "Header": "Server Info",
            "Status": "Not exposed",
            "Severity": "Low",
            "Recommendation": "Server-identifying headers not found — good practice. Continue to monitor on changes."
        })

    return info, findings

def print_server_info(info: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
    """
    Nicely print server information and the related findings.
    """
    print(Fore.CYAN + "\n🌐 Server Information & Exposure Check" + Style.RESET_ALL)
    print(Fore.CYAN + "============================================================" + Style.RESET_ALL)

    print(Fore.WHITE + f"Target URL: {info.get('url')}")
    print(Fore.WHITE + f"Hostname: {info.get('hostname')}")
    ips = info.get("ips") or []
    if ips:
        print(Fore.WHITE + f"Resolved IPs: {', '.join(ips)}")
    else:
        print(Fore.WHITE + "Resolved IPs: N/A")

    status = info.get("status_code")
    if status:
        print(Fore.WHITE + f"HTTP Status: {status} {info.get('reason')}")
    else:
        print(Fore.WHITE + "HTTP Status: N/A")

    elapsed = info.get("elapsed")
    if elapsed is not None:
        print(Fore.WHITE + f"Response Time: {elapsed:.3f}s")

    # Show header subset
    headers = info.get("headers", {}) or {}
    if headers:
        print(Fore.WHITE + "\nObserved Server Headers:")
        print(Fore.WHITE + "------------------------")
        for k, v in headers.items():
            print(f"{k}: {v}")
    else:
        print(Fore.WHITE + "\nObserved Server Headers: None of the common fingerprint headers were present.")

    # Print findings grouped by severity
    if findings:
        print(Fore.MAGENTA + "\nFindings:" + Style.RESET_ALL)
        for i, f in enumerate(findings, 1):
            sev_color = {"High": Fore.RED, "Medium": Fore.YELLOW, "Low": Fore.GREEN}.get(f.get("Severity"), Fore.WHITE)
            print(f"\n{i}. {f.get('Header')} — {f.get('Status')}")
            print(f"   Severity: {sev_color}{f.get('Severity')}{Style.RESET_ALL}")
            print(f"   Recommendation: {Fore.CYAN}{f.get('Recommendation')}{Style.RESET_ALL}")
            if "Detail" in f:
                print(f"   Detail: {Fore.WHITE}{f.get('Detail')}{Style.RESET_ALL}")
    else:
        print(Fore.GREEN + "\nNo server exposure findings." + Style.RESET_ALL)

    print(Fore.CYAN + "\n============================================================" + Style.RESET_ALL)
