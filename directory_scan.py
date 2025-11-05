# dir_scan.py
"""
Directory & File Exposure Scanner (safe checks)

Usage:
    from dir_scan import scan_common_paths, print_dir_scan_results
    findings = scan_common_paths("https://example.com")
    print_dir_scan_results(findings)
"""

from typing import List, Dict
from urllib.parse import urljoin, urlparse
import requests
from colorama import Fore, Style

# Common paths to probe (safe, read-only)
COMMON_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/.git/", "/.env", "/.htaccess",
    "/config.php", "/config.php.bak", "/config.bak", "/backup.zip",
    "/wp-config.php", "/admin/", "/admin/index.php", "/phpinfo.php",
    "/server-status", "/.well-known/security.txt", "/.well-known/change-password",
    "/.git/config", "/.DS_Store", "/.gitignore", "/logs/", "/error_log",
    "/.htpasswd", "/README", "/readme.html", "/readme.txt", "/backup.tar.gz"
]

# “Interesting” responses to surface (presence, forbidden, auth required, server error)
INTERESTING_STATUS = {200, 401, 403, 500}

_SEV_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def _normalize_url(base: str) -> str:
    parsed = urlparse(base)
    if not parsed.scheme:
        base = "http://" + base
    return base


def _severity_for(path: str, status: int) -> str:
    """
    Simple heuristic. Publicly reachable sensitive files => High,
    admin or directory hits => Medium, other interesting codes => Low/Medium.
    """
    p = path.lower()
    if status == 200:
        if any(x in p for x in [".env", "config", "backup", "phpinfo", ".git", ".htpasswd", "key", "passwd"]):
            return "High"
        if p.endswith("/") or "admin" in p:
            return "Medium"
        return "Medium"
    if status == 401:
        return "Medium"   # auth gate exists (interesting)
    if status == 403:
        return "Low"      # blocked (good), but still noteworthy
    if status >= 500:
        return "Low"      # server error while probing
    return "Low"


def scan_common_paths(base_url: str, timeout: int = 6, max_results: int = 50) -> List[Dict]:
    """
    Scan a list of common files/directories (non-destructive).
    Returns a list of findings with:
      Category, Severity, Description, RelPath, URL, Status
    """
    base = _normalize_url(base_url)
    session = requests.Session()
    session.headers.update({"User-Agent": "WebSecScan/DirScanner/1.0"})

    findings: List[Dict] = []
    scanned = 0

    for rel in COMMON_PATHS:
        if scanned >= max_results:
            break
        scanned += 1

        full = urljoin(base if base.endswith("/") else base + "/", rel.lstrip("/"))
        try:
            resp = session.get(full, timeout=timeout, allow_redirects=True)
            status = resp.status_code

            if status in INTERESTING_STATUS:
                sev = _severity_for(rel, status)
                findings.append({
                    "Category": "Directory/File Exposure",
                    "Severity": sev,
                    "Description": f"Path {rel} returned HTTP {status}.",
                    "RelPath": rel,
                    "URL": full,
                    "Status": status,
                })
        except requests.RequestException:
            # ignore transient network errors
            continue

    if not findings:
        findings.append({
            "Category": "Directory/File Exposure",
            "Severity": "Low",
            "Description": "No common sensitive files or directories found in the default list. Not a guarantee — consider expanding paths or authenticated checks.",
            "RelPath": None,
            "URL": None,
            "Status": None,
        })

    return findings


def print_dir_scan_results(findings: List[Dict], show_counts: bool = True) -> None:
    """
    Pretty, clear output:
      - Optional severity counts
      - Itemized findings in the requested format
      - Single remediation block at the end
    """
    if not findings:
        print(Fore.GREEN + "\nDirectory & File Exposure\n---------------------------------------" + Style.RESET_ALL)
        print("No findings.")
        return

    # Sort High -> Medium -> Low, then by path
    findings_sorted = sorted(
        findings,
        key=lambda f: (_SEV_ORDER.get(f.get("Severity", "Low"), 3), f.get("RelPath") or "")
    )

    if show_counts:
        counts = {"High": 0, "Medium": 0, "Low": 0}
        for f in findings_sorted:
            sev = f.get("Severity", "Low")
            if sev in counts:
                counts[sev] += 1
        total = sum(counts.values())
        print(Fore.MAGENTA + "\nDirectory & File Exposure — Summary" + Style.RESET_ALL)
        print("---------------------------------------")
        print(f"Total Findings: {total} | "
              f"{Fore.RED}High: {counts['High']}{Style.RESET_ALL} | "
              f"{Fore.YELLOW}Medium: {counts['Medium']}{Style.RESET_ALL} | "
              f"{Fore.GREEN}Low: {counts['Low']}{Style.RESET_ALL}\n")

    print(Fore.WHITE + "Directory & File Exposure" + Style.RESET_ALL)
    print("---------------------------------------")

    for idx, f in enumerate(findings_sorted, 1):
        sev = f.get("Severity", "Low")
        color = {"High": Fore.RED, "Medium": Fore.YELLOW, "Low": Fore.GREEN}.get(sev, Fore.WHITE)
        rel = f.get("RelPath") or "-"
        url = f.get("URL") or "-"
        status = f.get("Status")

        print(f"{idx}. Path: {rel}")
        print(f"   Severity: {color}{sev}{Style.RESET_ALL}")
        print(f"   URL: {url}")
        if status is not None:
            print(f"   HTTP Status: {status}")
        desc = f.get("Description")
        if desc:
            print(f"   Note: {desc}")
        print()

    # Single remediation block
    print(Fore.CYAN + "Recommended Remediations" + Style.RESET_ALL)
    print("---------------------------------------")
    print("• Remove public access to sensitive files (e.g., .env, backups, config, .git, phpinfo).")
    print("• Disable directory listing; serve only explicit whitelisted files.")
    print("• Block VCS directories and metadata (.git/, .gitignore, .DS_Store) at the web server/reverse proxy.")
    print("• Do not keep backups in webroot (e.g., backup.zip, backup.tar.gz, config.php.bak).")
    print("• Restrict admin paths with auth & IP allowlists; avoid exposing admin panels publicly.")
    print("• Review robots.txt: it is not a security control and may leak sensitive paths.")
    print("• Enforce least privilege on web server user; return generic errors (avoid stack traces).")
