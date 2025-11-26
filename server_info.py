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

# CVSS Score for Server Information Leak category
CATEGORY_CVSS = {
    "score": "3.1",
    "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "severity": "Low"
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
      findings: list of findings with keys Header, Detail, Recommendation
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
            "Detail": "Invalid URL",
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
            "Detail": "No response - Target did not respond to HTTP requests or timed out.",
            "Recommendation": "Verify the target URL is accessible and responding to HTTP requests."
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

    # ----- Analyze exposures (ONLY report when exposed) -----

    # 1) Server header presence
    server_hdr = headers.get("server")
    if server_hdr:
        parsed_server = parse_server_header(server_hdr)
        findings.append({
            "Header": "Server Header Exposed",
            "Detail": f"server: {server_hdr}",
            "Recommendation": "Disable or mask the Server header through server configuration or by using a reverse proxy."
        })

    # 2) X-Powered-By
    xpby = headers.get("x-powered-by")
    if xpby:
        findings.append({
            "Header": "Technology Header Exposed",
            "Detail": f"X-Powered-By: {xpby}",
            "Recommendation": "Remove or obfuscate the X-Powered-By header to prevent unnecessary information disclosure."
        })

    # 3) Framework/Generator headers
    framework_headers = []
    for h in ("x-aspnet-version", "x-aspnetmvc-version", "x-powered-by-plesk", "x-generator"):
        val = headers.get(h)
        if val:
            framework_headers.append(f"{h}: {val}")
    
    if framework_headers:
        findings.append({
            "Header": "Framework/Generator Header Exposed",
            "Detail": ", ".join(framework_headers),
            "Recommendation": "Disable framework-identifying headers within application configuration."
        })

    # 4) Via header — indicates intermediate proxies / gateways
    via = headers.get("via")
    if via:
        findings.append({
            "Header": "Proxy Header Exposed",
            "Detail": f"Via: {via}",
            "Recommendation": "Via header present; it may reveal proxy topology or intermediaries. Consider normalizing at the edge."
        })

    # 5) X-Cache / X-Backend-Server / X-CF-Powered-By — backend/proxy info
    backend_headers = []
    for proxy_hdr in ("x-cache", "x-backend-server", "x-cf-powered-by", "x-drupal-cache"):
        v = headers.get(proxy_hdr)
        if v:
            backend_headers.append(f"{proxy_hdr}: {v}")
    
    if backend_headers:
        findings.append({
            "Header": "Backend/Cache Header Exposed",
            "Detail": ", ".join(backend_headers),
            "Recommendation": "Consider removing or normalizing these headers to avoid exposing infrastructure details."
        })

    # 6) Header order analysis (fingerprinting) - Show matching headers instead of percentage
    header_order_result = info.get("header_order_analysis", {})
    potential_matches = header_order_result.get("potential_matches", {})
    if potential_matches:
        for server_type, match_info in potential_matches.items():
            matching_hdrs = match_info['matching_headers']
            findings.append({
                "Header": "Server Behavior Fingerprinting",
                "Detail": f"The server's unique response patterns match known fingerprints -> {server_type}\n   Matching headers: {', '.join(matching_hdrs)}",
                "Recommendation": "Add a reverse proxy or WAF to normalize responses and reduce fingerprinting accuracy."
            })

    # 7) Error page analysis (Option B: Separate findings for each error test)
    error_responses = info.get("error_responses", [])
    for err in error_responses:
        if err.get("server_header") or err.get("mentions_in_body"):
            detail_parts = [f"HTTP {err['status_code']} response exposed server information"]
            if err.get("server_header"):
                detail_parts.append(f"Server header: {err['server_header']}")
            if err.get("mentions_in_body"):
                detail_parts.append(f"Body mentions: {', '.join(err['mentions_in_body'])}")
            
            findings.append({
                "Header": f"Error Page Reveals Server Details ({err['test']})",
                "Detail": "\n   ".join(detail_parts),
                "Recommendation": "Replace default error pages with custom ones that do not reveal server details."
            })

    return info, findings

def print_server_info(info: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
    """
    Print server information and findings in the new format.
    """
    print(Fore.CYAN + "Server Information Leak" + Style.RESET_ALL)
    print(Fore.MAGENTA + "═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
    
    # Target information with asterisk borders
    print(Fore.YELLOW + "*" * 64 + Style.RESET_ALL)
    print(Fore.WHITE + f"Target URL: {info.get('url')}")
    print(Fore.WHITE + f"Hostname: {info.get('hostname')}")
    ips = info.get("ips") or []
    if ips:
        print(Fore.WHITE + f"Resolved IPs: {', '.join(ips)}")
    else:
        print(Fore.WHITE + "Resolved IPs: N/A")
    print(Fore.YELLOW + "*" * 64 + Style.RESET_ALL)
    
    # Risk Rating section
    print(Fore.WHITE + "\nRisk Rating:")
    print(Fore.WHITE + f"Severity: {CATEGORY_CVSS['severity']}")
    print(Fore.WHITE + f"CVSS: {CATEGORY_CVSS['score']} ({CATEGORY_CVSS['vector']})")
    
    # Findings section
    if findings:
        print(Fore.WHITE + "\nFindings:")
        print(Fore.WHITE + "`" * 80)
        
        for i, f in enumerate(findings, 1):
            print(Fore.WHITE + f"{i}. {f.get('Header')}")
            print(Fore.WHITE + f"   Detail: {f.get('Detail')}")
            print(Fore.WHITE + f"   Recommendation: {f.get('Recommendation')}")
            if i < len(findings):  # Add blank line between findings except after last one
                print()
        
        # Add note about fingerprinting accuracy
        print(Fore.YELLOW + "\nNote: Server fingerprinting based on response patterns is not 100% accurate. " + Style.RESET_ALL)
        print(Fore.YELLOW + "Manual verification is recommended to confirm the actual server software in use." + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "\nFindings: None - No server information exposure detected." + Style.RESET_ALL)
    
    print(Fore.MAGENTA + "═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)