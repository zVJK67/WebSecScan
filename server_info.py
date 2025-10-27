# server_info.py
import requests
import socket
import time
from urllib.parse import urlparse
from colorama import Fore, Style

COMMON_LEAK_HEADERS = [
    "Server",
    "X-Powered-By",
    "Via",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Powered-By-Plesk",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Cache",
    "X-Backend-Server",
    "X-CF-Powered-By",
]

def _resolve_hostname(hostname):
    """Resolve hostname to a list of IP addresses (IPv4/IPv6 if available)."""
    ips = []
    try:
        for res in socket.getaddrinfo(hostname, None):
            ip = res[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips

def _safe_head_get(url, timeout=10):
    """
    Try HEAD first (non-destructive). If HEAD fails or returns 405, fallback to GET.
    Returns (response_obj or None, elapsed_seconds or None)
    """
    try:
        start = time.time()
        resp = requests.head(url, timeout=timeout, allow_redirects=True)
        elapsed = time.time() - start
        # some servers don't allow HEAD and return 405
        if resp.status_code == 405 or resp.status_code == 501:
            start = time.time()
            resp = requests.get(url, timeout=timeout, allow_redirects=True)
            elapsed = time.time() - start
        return resp, elapsed
    except requests.RequestException:
        # last try GET if HEAD failed
        try:
            start = time.time()
            resp = requests.get(url, timeout=timeout, allow_redirects=True)
            elapsed = time.time() - start
            return resp, elapsed
        except requests.RequestException:
            return None, None

def get_server_info(target_url, timeout=10):
    """
    Gather server information and analyze header exposures.

    Returns:
      info: dict with keys (url, hostname, ips, status_code, reason, elapsed, headers_subset)
      findings: list of dict findings with Header, Status, Severity, Recommendation
    """
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    info = {
        "url": target_url,
        "hostname": hostname,
        "ips": [],
        "status_code": None,
        "reason": None,
        "elapsed": None,
        "headers": {},
    }
    findings = []

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
    resp, elapsed = _safe_head_get(target_url, timeout=timeout)
    if resp is None:
        findings.append({
            "Header": "Server Info",
            "Status": "No response",
            "Severity": "Medium",
            "Recommendation": "Target did not respond to HTTP requests or timed out."
        })
        return info, findings

    info["status_code"] = resp.status_code
    info["reason"] = resp.reason
    info["elapsed"] = elapsed
    # pull only interesting headers to avoid noise
    headers = resp.headers
    headers_subset = {h: headers.get(h) for h in COMMON_LEAK_HEADERS if headers.get(h)}
    info["headers"] = headers_subset

    # Analyze exposures
    # 1) Server header presence and version leak
    server_hdr = headers.get("Server")
    if server_hdr:
        # If header contains a slash or version like "nginx/1.18.0" flag version exposure
        has_version = any(ch.isdigit() for ch in server_hdr)
        findings.append({
            "Header": "Server",
            "Status": f"Present: {server_hdr}",
            "Severity": "Medium" if not has_version else "High",
            "Recommendation": ("Remove or minimize the Server header exposure. Do not reveal software or version numbers; "
                               "configure the web server to return generic values or hide the header.")
        })

    # 2) X-Powered-By and related framework/version headers
    xpby = headers.get("X-Powered-By")
    if xpby:
        findings.append({
            "Header": "X-Powered-By",
            "Status": f"Present: {xpby}",
            "Severity": "High",
            "Recommendation": "Remove X-Powered-By header (or disable in framework) to avoid framework fingerprinting."
        })

    for h in ("X-AspNet-Version", "X-AspNetMvc-Version", "X-Powered-By-Plesk", "X-Generator"):
        val = headers.get(h)
        if val:
            findings.append({
                "Header": h,
                "Status": f"Present: {val}",
                "Severity": "High",
                "Recommendation": f"Remove or disable the {h} header to avoid disclosing internal framework/version details."
            })

    # 3) Via header — indicates intermediate proxies / gateways; might leak architecture
    via = headers.get("Via")
    if via:
        findings.append({
            "Header": "Via",
            "Status": f"Present: {via}",
            "Severity": "Medium",
            "Recommendation": ("Via header present; it may reveal proxy topology or intermediaries. "
                               "Consider minimizing or normalizing this header at the edge.")
        })

    # 4) X-Cache / X-Backend-Server / X-CF-Powered-By — proxy/backend info
    for proxy_hdr in ("X-Cache", "X-Backend-Server", "X-CF-Powered-By", "X-Forwarded-For"):
        v = headers.get(proxy_hdr)
        if v:
            findings.append({
                "Header": proxy_hdr,
                "Status": f"Present: {v}",
                "Severity": "Low",
                "Recommendation": f"Consider removing or normalizing the {proxy_hdr} header to avoid exposing infrastructure details."
            })

    # 5) Content-Type and Content-Encoding (informational; show but low severity)
    ct = headers.get("Content-Type")
    if ct:
        findings.append({
            "Header": "Content-Type",
            "Status": f"Present: {ct}",
            "Severity": "Low",
            "Recommendation": "Ensure content types are correctly set; avoid serving sensitive data with permissive types."
        })
    ce = headers.get("Content-Encoding")
    if ce:
        findings.append({
            "Header": "Content-Encoding",
            "Status": f"Present: {ce}",
            "Severity": "Low",
            "Recommendation": "Content-Encoding is present (e.g., gzip); ensure compression does not lead to information leakage."
        })

    # 6) If no identifying headers found, mark as good (no exposure)
    if not headers_subset:
        findings.append({
            "Header": "Server Info",
            "Status": "Not exposed",
            "Severity": "Low",
            "Recommendation": "Server-identifying headers not found — good practice. Continue to monitor on changes."
        })

    return info, findings

def print_server_info(info, findings):
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
    headers = info.get("headers", {})
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
    else:
        print(Fore.GREEN + "\nNo server exposure findings." + Style.RESET_ALL)

    print(Fore.CYAN + "\n============================================================" + Style.RESET_ALL)
