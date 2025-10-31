# dir_scan.py
"""
Directory & File Exposure Scanner (safe checks)

Usage:
    from dir_scan import scan_common_paths
    findings = scan_common_paths("https://example.com")
"""

from typing import List, Dict
from urllib.parse import urljoin, urlparse
import requests
from colorama import Fore, Style

# Common paths to probe (safe, read-only): config, backups, admin, logs, well-known
COMMON_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/.git/", "/.env", "/.htaccess",
    "/config.php", "/config.php.bak", "/config.bak", "/backup.zip",
    "/wp-config.php", "/admin/", "/admin/index.php", "/phpinfo.php",
    "/server-status", "/.well-known/security.txt", "/.well-known/change-password",
    "/.git/config", "/.DS_Store", "/.gitignore", "/logs/", "/error_log",
    "/.htpasswd", "/README", "/readme.html", "/readme.txt", "/backup.tar.gz"
]

# Response codes that commonly indicate exposure or interesting behaviour
INTERESTING_STATUS = {200, 401, 403, 500}

def _normalize_url(base: str) -> str:
    parsed = urlparse(base)
    if not parsed.scheme:
        base = "http://" + base
    if not base.endswith("/"):
        # keep consistent join behavior
        base = base
    return base

def scan_common_paths(base_url: str, timeout: int = 6, max_results: int = 50) -> List[Dict]:
    """
    Scan a list of common files/directories (non-destructive).
    Returns a list of findings, each with Category/Severity/Description.
    """
    base = _normalize_url(base_url)
    session = requests.Session()
    session.headers.update({"User-Agent": "WebSecScan/DirScanner/1.0"})
    findings = []

    scanned = 0
    for path in COMMON_PATHS:
        if scanned >= max_results:
            break
        scanned += 1
        full = urljoin(base, path.lstrip("/"))
        try:
            resp = session.get(full, timeout=timeout, allow_redirects=True)
            status = resp.status_code
            # interesting: present, auth required, forbidden, server error
            if status in INTERESTING_STATUS:
                # Build a human-readable description
                desc = f"Path {path} returned HTTP {status}."
                # try to glean small hints from body (first 200 chars)
                body_snippet = (resp.text or "")[:200].strip().replace("\n", " ")
                if body_snippet:
                    desc += f" Body snippet: {body_snippet!r}"

                sev = "Low"
                if status == 200:
                    # public file found — severity depends on filename
                    if any(x in path.lower() for x in [".env", "config", "backup", "phpinfo", ".git", "key", "passwd"]):
                        sev = "High"
                    elif path.endswith("/") or "admin" in path.lower():
                        sev = "Medium"
                    else:
                        sev = "Medium"
                elif status == 401:
                    sev = "Medium"
                elif status == 403:
                    sev = "Low"
                elif status >= 500:
                    sev = "Low"

                findings.append({
                    "Category": "Directory/File Exposure",
                    "Severity": sev,
                    "Description": desc,
                    "Path": full,
                    "Status": status
                })
        except requests.RequestException:
            # ignore transient network errors for scanning
            continue

    # If no interesting results, add a low informational finding
    if not findings:
        findings.append({
            "Category": "Directory/File Exposure",
            "Severity": "Low",
            "Description": "No common sensitive files or directories found in the default path list. This does not guarantee absence; consider expanding path list or authenticated checks."
        })

    return findings
