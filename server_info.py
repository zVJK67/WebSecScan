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
]

# Known server fingerprints (header order patterns)
SERVER_FINGERPRINTS = {
    "nginx": ["server", "date", "content-type", "content-length", "connection"],
    "apache": ["date", "server", "content-length", "content-type"],
    "iis": ["content-type", "server", "date"],
    "lighttpd": ["server", "content-type", "content-length", "date"],
}

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
            start = time.time()
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            elapsed = time.time() - start
        return resp, elapsed
    except requests.RequestException:
        try:
            start = time.time()
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            elapsed = time.time() - start
            return resp, elapsed
        except requests.RequestException:
            return None, None

def _send_malformed_requests(url: str, session: requests.Session, timeout: int = 10) -> List[Dict[str, Any]]:
    """
    Send malformed HTTP requests to trigger error pages that may reveal server information.
    Returns list of error responses with their details.
    """
    error_responses = []
    
    malformed_tests = [
        {
            "name": "Invalid HTTP Method",
            "method": "INVALID",
            "path": "/"
        },
        {
            "name": "Invalid HTTP Version",
            "custom_request": b"GET / HTTP/9.9\r\nHost: test\r\n\r\n"
        },
        {
            "name": "Malformed Headers",
            "headers": {"X-Invalid": "value\r\nInjected: header"}
        },
        {
            "name": "Non-existent page (404)",
            "path": "/this-page-does-not-exist-12345.html"
        }
    ]
    
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    for test in malformed_tests:
        try:
            if "custom_request" in test:
                # Skip custom raw requests for now (requires low-level socket)
                continue
            elif "method" in test:
                resp = session.request(test["method"], base_url + test.get("path", "/"), 
                                      timeout=timeout, allow_redirects=False)
            elif "path" in test:
                resp = session.get(base_url + test["path"], timeout=timeout, allow_redirects=False)
            else:
                resp = session.get(base_url, headers=test.get("headers"), 
                                  timeout=timeout, allow_redirects=False)
            
            if resp.status_code >= 400:
                # Check for server information in error pages
                server_mentions = []
                content = resp.text[:2000]  # First 2000 chars
                
                # Look for common server signatures in error pages
                patterns = [
                    r'(Apache[/\s][\d.]+)',
                    r'(nginx[/\s][\d.]+)',
                    r'(Microsoft-IIS[/\s][\d.]+)',
                    r'(lighttpd[/\s][\d.]+)',
                    r'(Tomcat[/\s][\d.]+)',
                    r'(PHP[/\s][\d.]+)',
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    server_mentions.extend(matches)
                
                if server_mentions or "server" in resp.headers:
                    error_responses.append({
                        "test": test["name"],
                        "status_code": resp.status_code,
                        "server_header": resp.headers.get("server"),
                        "mentions_in_body": list(set(server_mentions)),
                        "content_preview": content[:200]
                    })
        except Exception:
            continue
    
    return error_responses

def _analyze_header_order(headers: requests.structures.CaseInsensitiveDict) -> Dict[str, Any]:
    """
    Analyze the order of HTTP headers to fingerprint the server type.
    Different servers have characteristic header orderings.
    """
    # Get ordered list of header names (lowercase)
    header_order = [k.lower() for k in headers.keys()]
    
    # Compare against known patterns
    matches = {}
    for server_type, signature in SERVER_FINGERPRINTS.items():
        # Check how many headers match in order
        common_headers = [h for h in signature if h in header_order]
        if len(common_headers) >= 3:
            # Check if they appear in the same relative order
            positions = [header_order.index(h) for h in common_headers]
            is_ordered = all(positions[i] < positions[i+1] for i in range(len(positions)-1))
            
            if is_ordered:
                matches[server_type] = {
                    "confidence": len(common_headers) / len(signature),
                    "matching_headers": common_headers
                }
    
    return {
        "header_order": header_order[:10],  # First 10 headers
        "potential_matches": matches
    }

def _analyze_status_line(response: requests.Response) -> Dict[str, str]:
    """
    Analyze HTTP status line formatting for fingerprinting clues.
    """
    # Get raw response if available
    raw = response.raw
    status_line_info = {
        "http_version": f"HTTP/{response.raw.version / 10:.1f}" if hasattr(response.raw, 'version') else "Unknown",
        "status_code": response.status_code,
        "reason_phrase": response.reason
    }
    
    return status_line_info

# Regex to parse Server header into product/version/extra
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
    return {
        "raw": server_value,
        "product": m.group("product"),
        "version": m.group("version"),
        "extra": m.group("extra")
    }

def get_server_info(target_url: str, timeout: int = 10, session: Optional[requests.Session] = None) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Gather server information and analyze header exposures.

    Returns:
      info: dict (url, hostname, ips, status_code, reason, elapsed, headers, header_order, status_line, error_responses)
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
        "headers": {},
        "header_order_analysis": {},
        "status_line": {},
        "error_responses": []
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

    # Fill basic info
    info["status_code"] = resp.status_code
    info["reason"] = resp.reason
    info["elapsed"] = elapsed

    # Analyze status line formatting
    info["status_line"] = _analyze_status_line(resp)

    # Analyze header order for fingerprinting
    info["header_order_analysis"] = _analyze_header_order(resp.headers)

    # Send malformed requests to check error pages
    info["error_responses"] = _send_malformed_requests(target_url, session, timeout)

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

    # 4) X-Cache / X-Backend-Server / X-CF-Powered-By — backend/proxy info
    for proxy_hdr in ("x-cache", "x-backend-server", "x-cf-powered-by"):
        v = headers.get(proxy_hdr)
        if v:
            findings.append({
                "Header": proxy_hdr,
                "Status": f"Present: {v}",
                "Severity": "Low",
                "Recommendation": f"Consider removing or normalizing the {proxy_hdr} header to avoid exposing infrastructure details.",
                "Detail": v
            })

    # 5) Header order analysis
    header_order_result = info.get("header_order_analysis", {})
    potential_matches = header_order_result.get("potential_matches", {})
    if potential_matches:
        for server_type, match_info in potential_matches.items():
            findings.append({
                "Header": "Header Order Pattern",
                "Status": f"Matches {server_type} signature",
                "Severity": "Medium",
                "Recommendation": f"HTTP header ordering suggests {server_type} server. Consider randomizing header order to prevent fingerprinting.",
                "Detail": f"Confidence: {match_info['confidence']:.0%}, Matching headers: {', '.join(match_info['matching_headers'])}"
            })

    # 6) Error page analysis
    error_responses = info.get("error_responses", [])
    for err in error_responses:
        if err.get("server_header") or err.get("mentions_in_body"):
            findings.append({
                "Header": "Error Page Disclosure",
                "Status": f"{err['test']} (HTTP {err['status_code']})",
                "Severity": "High",
                "Recommendation": "Error pages reveal server information. Configure custom error pages that don't expose server details.",
                "Detail": f"Server header: {err.get('server_header')}, Body mentions: {err.get('mentions_in_body')}"
            })

    # 7) If no identifying headers found
    if not headers_subset and not potential_matches and not error_responses:
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

    # Status line info
    status_line = info.get("status_line", {})
    if status_line:
        print(Fore.WHITE + f"\nHTTP Status Line:")
        print(Fore.WHITE + f"  Version: {status_line.get('http_version')}")
        print(Fore.WHITE + f"  Reason Phrase: {status_line.get('reason_phrase')}")

    # Header order analysis
    header_order = info.get("header_order_analysis", {})
    if header_order.get("header_order"):
        print(Fore.WHITE + f"\nHeader Order: {' → '.join(header_order['header_order'][:5])}...")

    # Show header subset
    headers = info.get("headers", {}) or {}
    if headers:
        print(Fore.WHITE + "\nObserved Server Headers:")
        print(Fore.WHITE + "------------------------")
        for k, v in headers.items():
            print(f"{k}: {v}")
    else:
        print(Fore.WHITE + "\nObserved Server Headers: None of the common fingerprint headers were present.")

    # Error responses
    error_responses = info.get("error_responses", [])
    if error_responses:
        print(Fore.YELLOW + f"\nError Page Analysis: {len(error_responses)} test(s) revealed server information" + Style.RESET_ALL)

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