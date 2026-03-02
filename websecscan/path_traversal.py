# path_traversal.py  (grouped output, friendly Details)
"""
Basic Path Traversal Tester (safe, non-destructive)

- Groups multiple triggering payloads per endpoint into one finding.
- Categorizes behavior types for better understanding.
- Better exception handling (timeouts, SSL, connection errors).
- Uses requests.Session with Retry.

NOTE:
This module performs non-destructive, read-only security probes to detect
path traversal vulnerabilities. It does not modify, upload, or delete
server-side resources. Payloads are used solely to identify security
misconfigurations, consistent with industry-standard vulnerability scanners
such as OWASP ZAP and Burp Suite.
"""

from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse, urlencode
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import Fore, Style
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
MAX_INSPECT_BYTES = 2048  # Limit content inspection to reduce data exposure

# Default payloads and probes (safe, non-exploitative)
TRAVERSAL_PAYLOADS = [
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",  
    "../..\\..\\windows\\win.ini",
]

COMMON_FILENAME_PARAMS = ["file", "path", "page", "template", "img", "download", "doc", "fileName"]
COMMON_PATHS = ["/", "/download", "/view", "/static", "/images", "/assets", "/file", "/get", "/show", "/ftp"]

# High-confidence textual indicators (Linux / Windows)
PASSWD_INDICATORS = ["root:", "bin/bash", "sshd:", "/bin/bash"]
WININI_INDICATORS = ["[extensions]", "[fonts]", "for 16-bit app support"]

# Heuristic threshold (bytes) for "response length changed a lot"
LENGTH_DELTA_THRESHOLD = 200


def _normalize_target(base: str) -> str:
    base = base.strip()
    if not base.startswith(("http://", "https://")):
        base = "http://" + base
    return base.rstrip("/")


def _build_session(retries: int = 2, backoff: float = 0.3) -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD", "OPTIONS"])
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": "WebSecScan/PathTraversal/1.1"})
    s.verify = False
    return s


def _probe_url(session: requests.Session, url: str, timeout: int = 10, allow_redirects: bool = True, verbose: bool = False):
    try:
        if verbose:
            print(Fore.WHITE + f"[probe] GET {url}" + Style.RESET_ALL)
        return session.get(url, timeout=timeout, allow_redirects=allow_redirects)
    except requests.RequestException:
        return None


def _endpoint_of(url: str) -> str:
    try:
        p = urlparse(url)
        parts = (p.path or "/").split("/")
        return "/" + (parts[1] if len(parts) > 1 and parts[1] else "")
    except Exception:
        return "/"


def _categorize_behavior(baseline_status: Optional[int], found_status: Optional[int],
                         baseline_len: int, found_len: int) -> str:

    if baseline_status and found_status and baseline_status != found_status:
        return "Endpoint returned a different HTTP status compared to normal request"

    if found_len > baseline_len and (found_len - baseline_len) > LENGTH_DELTA_THRESHOLD:
        return "Response size increased significantly (possible file access attempt)"

    if baseline_len > found_len and (baseline_len - found_len) > LENGTH_DELTA_THRESHOLD:
        return "Server returned a smaller response than expected"

    return "Server behavior changed when traversal patterns were used"


def test_path_traversal(
    base_url: str,
    payloads: Optional[List[str]] = None,
    paths: Optional[List[str]] = None,
    params: Optional[List[str]] = None,
    timeout: int = 10,
    max_tests: int = 200,
    verbose: bool = False,
) -> List[Dict]:

    base = _normalize_target(base_url)
    payloads = payloads or TRAVERSAL_PAYLOADS
    paths = paths or COMMON_PATHS
    params = params or COMMON_FILENAME_PARAMS

    session = _build_session()
    grouped: Dict[str, Dict] = {}
    tests_run = 0

    # Baseline capture
    baseline: Dict[str, Dict[str, Optional[int]]] = {}
    for p in paths:
        if tests_run >= max_tests:
            break
        full = urljoin(base + "/", p.lstrip("/"))
        resp = _probe_url(session, full, timeout=timeout, verbose=verbose)
        baseline[full] = {
            "status": getattr(resp, "status_code", None),
            "length": len(resp.text) if resp and resp.text else 0,
        }
        tests_run += 1

    def _record_behavior_change(endpoint: str, baseline_status: Optional[int], baseline_len: int,
                                found_status: int, found_len: int, payload: str):
        if endpoint not in grouped:
            behavior = _categorize_behavior(baseline_status, found_status, baseline_len, found_len)
            grouped[endpoint] = {
                "Category": "Path Traversal",
                "Severity": "Medium",
                "Endpoint": endpoint,
                "Payloads": [],
                "Behavior": behavior,
                "ExampleStatus": found_status,
            }
        grouped[endpoint]["Payloads"].append(payload)

    # Path-based traversal
    for p in paths:
        if tests_run >= max_tests:
            break
        base_full = urljoin(base + "/", p.lstrip("/"))
        base_info = baseline.get(base_full, {})
        base_len = base_info.get("length", 0)
        base_status = base_info.get("status")
        endpoint = _endpoint_of(base_full)

        for payload in payloads:
            if tests_run >= max_tests:
                break
            probe = base_full.rstrip("/") + "/" + payload.lstrip("/")
            resp = _probe_url(session, probe, timeout=timeout, verbose=verbose)
            tests_run += 1
            if not resp:
                continue

            raw_text = resp.text or ""
            text = raw_text[:MAX_INSPECT_BYTES]
            length = len(raw_text)
            status = resp.status_code
            lower_text = text.lower()

            if any(ind.lower() in lower_text for ind in PASSWD_INDICATORS):
                grouped[endpoint] = {
                    "Category": "Path Traversal",
                    "Severity": "High",
                    "Endpoint": endpoint,
                    "Payloads": [payload],
                    "Behavior": "Direct evidence of sensitive file content (Linux /etc/passwd)",
                    "ExampleStatus": status,
                }
                continue

            if any(ind.lower() in lower_text for ind in WININI_INDICATORS):
                grouped[endpoint] = {
                    "Category": "Path Traversal",
                    "Severity": "High",
                    "Endpoint": endpoint,
                    "Payloads": [payload],
                    "Behavior": "Direct evidence of sensitive file content (Windows win.ini)",
                    "ExampleStatus": status,
                }
                continue

            if base_len and (abs(length - base_len) > LENGTH_DELTA_THRESHOLD or
                             (base_status and status != base_status)):
                _record_behavior_change(endpoint, base_status, base_len, status, length, payload)

    # Query parameter traversal
    for p in paths:
        if tests_run >= max_tests:
            break
        base_full = urljoin(base + "/", p.lstrip("/"))
        base_info = baseline.get(base_full, {})
        base_len = base_info.get("length", 0)
        base_status = base_info.get("status")
        endpoint = _endpoint_of(base_full)

        for param in params:
            if tests_run >= max_tests:
                break
            for payload in payloads:
                if tests_run >= max_tests:
                    break
                probe = base_full + "?" + urlencode({param: payload})
                resp = _probe_url(session, probe, timeout=timeout, verbose=verbose)
                tests_run += 1
                if not resp:
                    continue

                raw_text = resp.text or ""
                text = raw_text[:MAX_INSPECT_BYTES]
                length = len(raw_text)
                status = resp.status_code
                lower_text = text.lower()
                payload_str = f"{param}={payload}"

                if any(ind.lower() in lower_text for ind in PASSWD_INDICATORS):
                    grouped[endpoint] = {
                        "Category": "Path Traversal",
                        "Severity": "High",
                        "Endpoint": endpoint,
                        "Payloads": [payload_str],
                        "Behavior": "Direct evidence of sensitive file content via query parameter",
                        "ExampleStatus": status,
                    }
                    continue

                if any(ind.lower() in lower_text for ind in WININI_INDICATORS):
                    grouped[endpoint] = {
                        "Category": "Path Traversal",
                        "Severity": "High",
                        "Endpoint": endpoint,
                        "Payloads": [payload_str],
                        "Behavior": "Direct evidence of sensitive file content via query parameter",
                        "ExampleStatus": status,
                    }
                    continue

                if base_len and (abs(length - base_len) > LENGTH_DELTA_THRESHOLD or
                                 (base_status and status != base_status)):
                    _record_behavior_change(endpoint, base_status, base_len, status, length, payload_str)

    findings: List[Dict] = []
    for endpoint, data in grouped.items():
        findings.append({
            "Category": "Path Traversal",
            "_item_short": "Path Traversal",
            "Endpoint": endpoint,
            "Payloads": data.get("Payloads", []),
            "Behavior": data.get("Behavior"),
            "Status": data.get("ExampleStatus"),
        })

    return findings


def print_path_traversal_results(findings: List[Dict]) -> None:
    print(Fore.CYAN + "\nPath Traversal" + Style.RESET_ALL)
    print(Fore.MAGENTA + "═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)

    if not findings:
        print(Fore.GREEN + "✓ No path traversal vulnerabilities detected" + Style.RESET_ALL)
        print(Fore.MAGENTA + "══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        return

    has_direct_evidence = any(
        "Direct evidence" in f.get("Behavior", "")
        for f in findings
    )

    print("Risk Rating:")
    if has_direct_evidence:
        print("Severity: High")
        print("CVSS: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)")
    else:
        print("Severity: Medium")
        print("CVSS: 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)")

    print("\nFindings:")
    for idx, f in enumerate(findings, 1):
        print(f"{idx}. Endpoint: {f.get('Endpoint')}")
        print("   Payloads Triggering:")
        for p in f.get("Payloads", []):
            print(f"     - {p}")
        print(f"   Evidence: {f.get('Behavior')}")
        if idx < len(findings):
            print("─" * 64)

    print(Fore.YELLOW + "\nRecommendation" + Style.RESET_ALL)
    print("   - Validate and sanitize user-supplied paths.")
    print("   - Enforce a fixed base directory for file access.")
    print("   - Avoid exposing detailed file system errors.")
    print("   - Monitor logs for repeated traversal attempts.")

    print(Fore.MAGENTA + "\n═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
