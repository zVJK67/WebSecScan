# path_traversal.py  (grouped output, friendly Details)
"""
Basic Path Traversal Tester (safe, non-destructive)

- Groups multiple triggering payloads per endpoint into one finding.
- Replaces noisy repeated 'Details' with a short human-friendly note:
  e.g., "Response grew from ~11KB to ~75KB when traversal patterns used."
- Better exception handling (timeouts, SSL, connection errors).
- Uses requests.Session with Retry.
"""

from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlencode
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import Fore, Style

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
            "length": len(resp.text) if resp and resp.text is not None else 0,
        }
        tests_run += 1

    # Helper to record a length delta signal for an endpoint
    def _record_length_delta(endpoint: str, baseline_len: int, found_len: int, payload: str):
        node = grouped.setdefault(endpoint, {
            "Category": "Path Traversal",
            "Severity": "Medium",
            "Endpoint": endpoint,
            "Payloads": [],
            "Signals": [],     # keep internal signals but we’ll condense into friendly text
            "BaselineLen": baseline_len,
            "ExampleFoundLen": found_len,
            "ExampleStatus": None,
        })
        node["Payloads"].append(payload)
        node["Signals"].append((baseline_len, found_len))  # internal
        # keep the most extreme found length as the example
        if abs(found_len - baseline_len) > abs(node["ExampleFoundLen"] - baseline_len):
            node["ExampleFoundLen"] = found_len

    # 1) append payloads to paths (path-based traversal)
    for p in paths:
        if tests_run >= max_tests:
            break
        base_full = urljoin(base + "/", p.lstrip("/"))
        base_info = baseline.get(base_full, {})
        base_len = base_info.get("length", 0)
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

            # High-confidence indicators
            if any(ind in text for ind in PASSWD_INDICATORS):
                grouped[endpoint] = {
                    "Category": "Path Traversal",
                    "Severity": "High",
                    "Endpoint": endpoint,
                    "Payloads": [payload],
                    "HighConfidence": "Linux /etc/passwd-like content detected.",
                    "ExampleStatus": status,
                }
                # Once high is found for this endpoint, we don't need to keep adding heuristics
                continue

            if any(ind in text for ind in WININI_INDICATORS):
                grouped[endpoint] = {
                    "Category": "Path Traversal",
                    "Severity": "High",
                    "Endpoint": endpoint,
                    "Payloads": [payload],
                    "HighConfidence": "Windows win.ini-like content detected.",
                    "ExampleStatus": status,
                }
                continue

            # Heuristic length delta
            if base_len and abs(length - base_len) > LENGTH_DELTA_THRESHOLD:
                _record_length_delta(endpoint, base_len, length, payload)
                grouped[endpoint]["ExampleStatus"] = status

    # 2) test via query parameters (param=payload)
    for p in paths:
        if tests_run >= max_tests:
            break
        base_full = urljoin(base + "/", p.lstrip("/"))
        base_info = baseline.get(base_full, {})
        base_len = base_info.get("length", 0)
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

                if any(ind in text for ind in PASSWD_INDICATORS):
                    grouped[endpoint] = {
                        "Category": "Path Traversal",
                        "Severity": "High",
                        "Endpoint": endpoint,
                        "Payloads": [f"{param}={payload}"],
                        "HighConfidence": "Linux /etc/passwd-like content detected (via parameter).",
                        "ExampleStatus": status,
                    }
                    continue

                if base_len and abs(length - base_len) > LENGTH_DELTA_THRESHOLD:
                    _record_length_delta(endpoint, base_len, length, f"{param}={payload}")
                    grouped[endpoint]["ExampleStatus"] = status

    # Convert grouped map -> final friendly findings
    findings: List[Dict] = []
    for endpoint, data in grouped.items():
        if data.get("Severity") == "High":
            # High-confidence finding
            desc = data.get("HighConfidence", "Sensitive file content detected.")
            findings.append({
                "Category": "Path Traversal",
                "Severity": "High",
                "Description": desc,
                "Endpoint": endpoint,
                "Payloads": data.get("Payloads", []),
                "Status": data.get("ExampleStatus"),
                "Details": "Direct evidence from response content.",
            })
            continue

        # Medium heuristic finding (length delta)
        base_len = data.get("BaselineLen", 0)
        found_len = data.get("ExampleFoundLen", 0)
        friendly = f"Response grew from ~{_human_size(base_len)} to ~{_human_size(found_len)} when traversal patterns were used."
        findings.append({
            "Category": "Path Traversal",
            "Severity": "Medium",
            "Endpoint": endpoint,
            "Payloads": sorted(set(data.get("Payloads", []))),
            "Description": "Server response changed a lot when traversal sequences were included.",
            "Behavior": "The response size changed significantly compared to the normal page.",
            "Interpretation": (
                "Medium confidence: the server behaved differently, which can happen when it tries to read files "
                "or renders an internal error page. Manual verification is recommended."
            ),
            "Recommendation": (
                "1) Validate and canonicalize incoming paths (resolve and enforce an allowlist).\n"
                "2) Never use user-controlled input directly for file reads; use fixed base directories and safe APIs.\n"
                "3) Log/monitor failed file-read attempts and return generic errors (avoid leaking file contents)."
            ),
            "Details": friendly,
            "Status": data.get("ExampleStatus"),
        })

    # If nothing found, add a low-severity informational result
    if not findings:
        findings.append({
            "Category": "Path Traversal",
            "Severity": "Low",
            "Description": "No obvious path traversal indicators found for tested payloads/paths. This scan is not exhaustive."
        })

    if verbose:
        print(Fore.CYAN + f"[done] tests run: {tests_run}, grouped findings: {len(findings)}" + Style.RESET_ALL)

    return findings
