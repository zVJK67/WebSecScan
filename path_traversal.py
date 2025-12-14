# path_traversal.py  (grouped output, friendly Details)
"""
Basic Path Traversal Tester (safe, non-destructive)

- Groups multiple triggering payloads per endpoint into one finding.
- Categorizes behavior types for better understanding.
- Better exception handling (timeouts, SSL, connection errors).
- Uses requests.Session with Retry.
"""

from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlencode
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import Fore, Style
import urllib3

# Suppress InsecureRequestWarning because HTTP-level probes intentionally skip cert verification
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default payloads and probes (safe, non-exploitative)
TRAVERSAL_PAYLOADS = [
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",  # url-encoded
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
    # Scanner design: skip TLS verification for HTTP-level tests (TLS checked separately)
    s.verify = False
    return s


def _probe_url(session: requests.Session, url: str, timeout: int = 10, allow_redirects: bool = True, verbose: bool = False):
    try:
        if verbose:
            print(Fore.WHITE + f"[probe] GET {url}" + Style.RESET_ALL)
        return session.get(url, timeout=timeout, allow_redirects=allow_redirects)
    except requests.exceptions.Timeout:
        if verbose:
            print(Fore.YELLOW + f"[timeout] {url}" + Style.RESET_ALL)
        return None
    except requests.exceptions.SSLError:
        if verbose:
            print(Fore.YELLOW + f"[ssl error] {url}" + Style.RESET_ALL)
        return None
    except requests.exceptions.ConnectionError:
        if verbose:
            print(Fore.YELLOW + f"[connection error] {url}" + Style.RESET_ALL)
        return None
    except requests.RequestException as e:
        if verbose:
            print(Fore.YELLOW + f"[request error] {url} -> {e}" + Style.RESET_ALL)
        return None


def _human_size(n: int) -> str:
    """Turn byte counts into ~KB/MB strings for friendly explanations."""
    if n is None:
        return "N/A"
    if n < 1024:
        return f"{n}B"
    if n < 1024**2:
        return f"{n/1024:.1f}KB"
    return f"{n/(1024**2):.1f}MB"


def _endpoint_of(url: str) -> str:
    """Return a short endpoint like '/download' from a full URL."""
    try:
        p = urlparse(url)
        # keep first segment only for grouping clarity (e.g., '/download')
        parts = (p.path or "/").split("/")
        return "/" + (parts[1] if len(parts) > 1 and parts[1] else "")
    except Exception:
        return "/"


def _categorize_behavior(baseline_status: Optional[int], found_status: Optional[int], 
                         baseline_len: int, found_len: int) -> str:
    """Categorize the type of behavioral change detected."""
    
    # Status code changed
    if baseline_status and found_status and baseline_status != found_status:
        return "Endpoint returned a different HTTP status compared to normal request"
    
    # Significant size increase
    if found_len > baseline_len and (found_len - baseline_len) > LENGTH_DELTA_THRESHOLD:
        return "Response size increased significantly (possible file access attempt)"
    
    # Significant size decrease (might indicate different content)
    if baseline_len > found_len and (baseline_len - found_len) > LENGTH_DELTA_THRESHOLD:
        return "Server returned a smaller response than expected"
    
    # Default for any other behavioral change
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
    """
    Run a safe path traversal probe against the target.

    - base_url: target base (http(s)://...)
    - timeout: per-request timeout in seconds
    - max_tests: maximum number of HTTP requests to make
    - verbose: print probe progress

    Returns grouped findings (one finding per endpoint).
    """
    base = _normalize_target(base_url)
    payloads = payloads or TRAVERSAL_PAYLOADS
    paths = paths or COMMON_PATHS
    params = params or COMMON_FILENAME_PARAMS

    session = _build_session()
    grouped: Dict[str, Dict] = {}  # endpoint -> info
    tests_run = 0

    # Baseline capture (one request per path) to compare content lengths
    baseline: Dict[str, Dict[str, Optional[int]]] = {}
    for p in paths:
        if tests_run >= max_tests:
            break
        full = urljoin(base + "/", p.lstrip("/"))
        resp = _probe_url(session, full, timeout=timeout, verbose=verbose)
        baseline[full] = {
            "status": getattr(resp, "status_code", None),
            "length": len(resp.text) if resp and getattr(resp, "text", None) is not None else 0,
        }
        tests_run += 1

    # Helper to record a behavioral change signal for an endpoint
    def _record_behavior_change(endpoint: str, baseline_status: Optional[int], baseline_len: int, 
                                found_status: int, found_len: int, payload: str):
        if endpoint not in grouped:
            behavior = _categorize_behavior(baseline_status, found_status, baseline_len, found_len)
            grouped[endpoint] = {
                "Category": "Path Traversal",
                "Severity": "Medium",
                "Endpoint": endpoint,
                "Payloads": [],  # Keep in order discovered
                "Behavior": behavior,
                "BaselineStatus": baseline_status,
                "BaselineLen": baseline_len,
                "ExampleStatus": found_status,
                "ExampleLen": found_len,
            }
        # Always append payload in discovery order (no deduplication here)
        grouped[endpoint]["Payloads"].append(payload)

    # 1) append payloads to paths (path-based traversal)
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

            status = resp.status_code
            text = resp.text or ""
            length = len(text)

            # High-confidence indicators (case-insensitive check)
            lower_text = text.lower()
            if any(ind.lower() in lower_text for ind in PASSWD_INDICATORS):
                if endpoint not in grouped or grouped[endpoint].get("Severity") != "High":
                    grouped[endpoint] = {
                        "Category": "Path Traversal",
                        "Severity": "High",
                        "Endpoint": endpoint,
                        "Payloads": [payload],
                        "Behavior": "Direct evidence of sensitive file content (Linux /etc/passwd)",
                        "ExampleStatus": status,
                    }
                else:
                    grouped[endpoint]["Payloads"].append(payload)
                continue

            if any(ind.lower() in lower_text for ind in WININI_INDICATORS):
                if endpoint not in grouped or grouped[endpoint].get("Severity") != "High":
                    grouped[endpoint] = {
                        "Category": "Path Traversal",
                        "Severity": "High",
                        "Endpoint": endpoint,
                        "Payloads": [payload],
                        "Behavior": "Direct evidence of sensitive file content (Windows win.ini)",
                        "ExampleStatus": status,
                    }
                else:
                    grouped[endpoint]["Payloads"].append(payload)
                continue

            # Heuristic behavioral change
            if base_len and (abs(length - base_len) > LENGTH_DELTA_THRESHOLD or 
                           (base_status and status != base_status)):
                _record_behavior_change(endpoint, base_status, base_len, status, length, payload)

    # 2) test via query parameters (param=payload)
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
                q = {param: payload}
                probe = base_full + "?" + urlencode(q)
                resp = _probe_url(session, probe, timeout=timeout, verbose=verbose)
                tests_run += 1
                if not resp:
                    continue

                status = resp.status_code
                text = resp.text or ""
                length = len(text)

                # High-confidence indicators (case-insensitive)
                lower_text = text.lower()
                if any(ind.lower() in lower_text for ind in PASSWD_INDICATORS):
                    payload_str = f"{param}={payload}"
                    if endpoint not in grouped or grouped[endpoint].get("Severity") != "High":
                        grouped[endpoint] = {
                            "Category": "Path Traversal",
                            "Severity": "High",
                            "Endpoint": endpoint,
                            "Payloads": [payload_str],
                            "Behavior": "Direct evidence of sensitive file content via query parameter",
                            "ExampleStatus": status,
                        }
                    else:
                        grouped[endpoint]["Payloads"].append(payload_str)
                    continue

                if any(ind.lower() in lower_text for ind in WININI_INDICATORS):
                    payload_str = f"{param}={payload}"
                    if endpoint not in grouped or grouped[endpoint].get("Severity") != "High":
                        grouped[endpoint] = {
                            "Category": "Path Traversal",
                            "Severity": "High",
                            "Endpoint": endpoint,
                            "Payloads": [payload_str],
                            "Behavior": "Direct evidence of sensitive file content via query parameter",
                            "ExampleStatus": status,
                        }
                    else:
                        grouped[endpoint]["Payloads"].append(payload_str)
                    continue

                # Heuristic behavioral change
                if base_len and (abs(length - base_len) > LENGTH_DELTA_THRESHOLD or
                               (base_status and status != base_status)):
                    _record_behavior_change(endpoint, base_status, base_len, status, length, 
                                          f"{param}={payload}")

    # Convert grouped map -> final findings
    findings: List[Dict] = []
    for endpoint, data in grouped.items():
        findings.append({
            "Category": "Path Traversal",
            "_item_short": "Path Traversal",
            "Endpoint": endpoint,
            "Payloads": data.get("Payloads", []),  # Keep in discovery order
            "Behavior": data.get("Behavior", "Server behavior changed"),
            "Status": data.get("ExampleStatus"),
        })

    if verbose:
        print(Fore.GREEN + f"[done] tests run: {tests_run}" + Style.RESET_ALL)

    return findings


def print_path_traversal_results(findings: List[Dict]) -> None:
    """
    Print path traversal results in the requested format.
    """
    
    # Print section header
    print(Fore.CYAN + "\nPath Traversal" + Style.RESET_ALL)
    print(Fore.MAGENTA + "═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
    
    if not findings:
        # No findings case
        print(Fore.GREEN + "✓ No path traversal vulnerabilities detected" + Style.RESET_ALL)
        print("=" * 64)
        return
    
    # Fixed risk rating
    print("Risk Rating:")
    print(f"Severity: High")
    print("CVSS: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)")
    
    print("\nFindings:")
    print(Fore.CYAN + f"``````````````````````````````````````````````````````````````````````````````````" + Style.RESET_ALL)
    
    for idx, f in enumerate(findings, 1):
        endpoint = f.get("Endpoint", "/")
        payloads = f.get("Payloads", [])
        behavior = f.get("Behavior", "Server behavior changed")
        
        print(f"{idx}. Endpoint: {endpoint}")
        print("\n   Payloads Triggering:")
        for payload in payloads:
            print(f"     - {payload}")
        print(f"\n   Evidence: {behavior}")
        
        # Add separator between findings (but not after the last one)
        if idx < len(findings):
            print("─" * 64)
    
    # Recommendations section
    print(f"\n{Fore.YELLOW}Recommendation{Style.RESET_ALL}")
    Fore.YELLOW + "**********************************************************" + Style.RESET_ALL
    print("   - Validate and sanitize user-supplied paths. Normalize and resolve paths before use.")
    print("   - Do not pass user input directly into file system functions.")
    print("   - Restrict file access to a fixed, safe base directory (enforce an allowlist).")
    print("   - Return generic error messages to avoid revealing internal directory structure.")
    print("   - Monitor logs for repeated invalid path requests.")
    
    print(Fore.MAGENTA + "\n═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
